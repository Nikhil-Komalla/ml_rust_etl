use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::{DefaultHashBuilder, HashTable};
use rayon::prelude::*;

use crate::csv::{
    fast_hash_bytes, for_each_line_fields, is_valid_utf8, FileSet, OverflowSpan, SliceRef,
    CHUNK_BYTES, FILE_IDX_ARENA, FILE_IDX_OVERFLOW,
};

const LINK_SHARDS: usize = 32;

#[derive(Clone, Copy)]
struct RawEdge {
    a: SliceRef,
    b: SliceRef,
    ha: u64,
    hb: u64,
}

#[derive(Clone, Copy)]
pub struct LinkEntry {
    raw_off: u32,
    raw_len: u16,
    canon_len: u16,
    canon_off: u32,
    raw_hash: u64,
    canon_hash: u64,
}

#[derive(Clone)]
struct ShardNode {
    sref: SliceRef,
    hash: u64,
}

pub struct LinkMap {
    shards: Vec<HashTable<LinkEntry>>,
    raw_arena: Vec<u8>,
    pub canon_arena: Vec<u8>,
    overflow_raw: Vec<Box<[u8]>>,
    overflow_canon: Vec<Box<[u8]>>,
    empty: bool,
}

impl LinkMap {
    pub fn empty() -> Self {
        Self {
            shards: Vec::new(),
            raw_arena: Vec::new(),
            canon_arena: Vec::new(),
            overflow_raw: Vec::new(),
            overflow_canon: Vec::new(),
            empty: true,
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    #[inline(always)]
    fn entry_raw<'a>(&'a self, e: &LinkEntry) -> &'a [u8] {
        if e.raw_len != u16::MAX {
            let off = e.raw_off as usize;
            &self.raw_arena[off..off + e.raw_len as usize]
        } else {
            &self.overflow_raw[e.raw_off as usize]
        }
    }

    #[inline(always)]
    fn entry_canon_ref(&self, e: &LinkEntry) -> SliceRef {
        if e.canon_len != u16::MAX {
            SliceRef {
                file_idx: FILE_IDX_ARENA,
                len: e.canon_len,
                off: e.canon_off,
            }
        } else {
            SliceRef {
                file_idx: FILE_IDX_OVERFLOW,
                len: 0,
                off: e.canon_off,
            }
        }
    }

    #[inline(always)]
    pub fn resolve(&self, raw: &[u8], raw_hash: u64) -> Option<(SliceRef, u64)> {
        if self.empty {
            return None;
        }
        let shard = ((raw_hash >> 28) as usize) & (LINK_SHARDS - 1);
        self.shards[shard]
            .find(raw_hash, |e| self.entry_raw(e) == raw)
            .map(|e| (self.entry_canon_ref(e), e.canon_hash))
    }

    #[inline(always)]
    pub fn canon_overflow_slice(&self, idx: u32) -> &[u8] {
        &self.overflow_canon[idx as usize]
    }
}

pub fn build_link_map(
    paths: &[PathBuf],
    hash_builder: &DefaultHashBuilder,
    ncpu: usize,
) -> io::Result<LinkMap> {
    if paths.is_empty() {
        return Ok(LinkMap::empty());
    }
    let files = FileSet::open(paths)?;
    let chunks = files.chunks(CHUNK_BYTES);
    if chunks.is_empty() {
        return Ok(LinkMap::empty());
    }

    // Stage L1: parse valid link edges in parallel using ncpu workers (no locks).
    let next_chunk = AtomicUsize::new(0);
    let nworkers = ncpu.clamp(1, 64).min(chunks.len());
    let mut worker_edges: Vec<Vec<RawEdge>> = (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_overflow: Vec<Vec<OverflowSpan>> = (0..nworkers).map(|_| Vec::new()).collect();

    std::thread::scope(|scope| {
        for (wid, (edges_out, ov_out)) in worker_edges
            .iter_mut()
            .zip(worker_overflow.iter_mut())
            .enumerate()
        {
            let files_ref = &files;
            let chunks_ref = &chunks;
            let next_ref = &next_chunk;
            scope.spawn(move || {
                loop {
                    let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk) = chunks_ref.get(cidx) else {
                        break;
                    };
                    let slice = &files_ref.file_bytes(chunk.file_idx)[chunk.start..chunk.end];
                    for_each_line_fields::<2>(slice, |[a, b]| {
                        if a.is_empty() || b.is_empty() || a == b {
                            return;
                        }
                        if !is_valid_utf8(a) || !is_valid_utf8(b) {
                            return;
                        }
                        let ra = files_ref.make_ref(chunk.file_idx, a, ov_out, wid);
                        let rb = files_ref.make_ref(chunk.file_idx, b, ov_out, wid);
                        let ha = fast_hash_bytes(a, hash_builder);
                        let hb = fast_hash_bytes(b, hash_builder);
                        edges_out.push(RawEdge {
                            a: ra,
                            b: rb,
                            ha,
                            hb,
                        });
                    });
                }
            });
        }
    });

    let total_edges: usize = worker_edges.iter().map(Vec::len).sum();
    if total_edges == 0 {
        return Ok(LinkMap::empty());
    }

    // Stage L2: shard-parallel interning of distinct endpoints into local dense node IDs.
    let shard_results: Vec<(Vec<ShardNode>, HashTable<u32>)> = (0..LINK_SHARDS)
        .into_par_iter()
        .map(|s| {
            let mut nodes: Vec<ShardNode> = Vec::new();
            let mut table: HashTable<u32> = HashTable::new();
            let mask = (LINK_SHARDS - 1) as u64;
            let files_ref = &files;
            let ov_ref = &worker_overflow;
            for edges in &worker_edges {
                for e in edges {
                    if (((e.ha >> 28) as usize) & mask as usize) == s {
                        let bytes = files_ref.resolve(e.a, &[], ov_ref);
                        if table
                            .find(e.ha, |&idx| {
                                files_ref.resolve(nodes[idx as usize].sref, &[], ov_ref) == bytes
                            })
                            .is_none()
                        {
                            let idx = nodes.len() as u32;
                            nodes.push(ShardNode {
                                sref: e.a,
                                hash: e.ha,
                            });
                            table.insert_unique(e.ha, idx, |&i| nodes[i as usize].hash);
                        }
                    }
                    if (((e.hb >> 28) as usize) & mask as usize) == s {
                        let bytes = files_ref.resolve(e.b, &[], ov_ref);
                        if table
                            .find(e.hb, |&idx| {
                                files_ref.resolve(nodes[idx as usize].sref, &[], ov_ref) == bytes
                            })
                            .is_none()
                        {
                            let idx = nodes.len() as u32;
                            nodes.push(ShardNode {
                                sref: e.b,
                                hash: e.hb,
                            });
                            table.insert_unique(e.hb, idx, |&i| nodes[i as usize].hash);
                        }
                    }
                }
            }
            (nodes, table)
        })
        .collect();

    let mut offsets = [0u32; LINK_SHARDS];
    let mut num_nodes = 0usize;
    let mut shard_nodes_list = Vec::with_capacity(LINK_SHARDS);
    let mut shard_tables = Vec::with_capacity(LINK_SHARDS);
    for (s, (nodes, table)) in shard_results.into_iter().enumerate() {
        offsets[s] = num_nodes as u32;
        num_nodes += nodes.len();
        shard_nodes_list.push(nodes);
        shard_tables.push(table);
    }

    let mut all_nodes: Vec<ShardNode> = Vec::with_capacity(num_nodes);
    for mut v in shard_nodes_list {
        all_nodes.append(&mut v);
    }

    // Stage L3: map all edges to dense u32 pairs in parallel.
    let resolved_batches: Vec<Vec<(u32, u32)>> = worker_edges
        .par_iter()
        .map(|edges| {
            let mut out = Vec::with_capacity(edges.len());
            let mask = LINK_SHARDS - 1;
            for e in edges {
                let sa = ((e.ha >> 28) as usize) & mask;
                let ba = files.resolve(e.a, &[], &worker_overflow);
                let la = *shard_tables[sa]
                    .find(e.ha, |&idx| {
                        files.resolve(all_nodes[(offsets[sa] + idx) as usize].sref, &[], &worker_overflow)
                            == ba
                    })
                    .unwrap();

                let sb = ((e.hb >> 28) as usize) & mask;
                let bb = files.resolve(e.b, &[], &worker_overflow);
                let lb = *shard_tables[sb]
                    .find(e.hb, |&idx| {
                        files.resolve(all_nodes[(offsets[sb] + idx) as usize].sref, &[], &worker_overflow)
                            == bb
                    })
                    .unwrap();

                out.push((offsets[sa] + la, offsets[sb] + lb));
            }
            out
        })
        .collect();

    drop(worker_edges);
    drop(shard_tables);

    // Stage L4: iterative DSU union-to-byte-wise-smallest root (zero recursion).
    let mut parent: Vec<u32> = (0..num_nodes as u32).collect();
    #[inline(always)]
    fn find(parent: &mut [u32], mut x: u32) -> u32 {
        while parent[x as usize] != x {
            let p = parent[x as usize];
            parent[x as usize] = parent[p as usize];
            x = parent[x as usize];
        }
        x
    }

    for batch in resolved_batches {
        for (u, v) in batch {
            let ru = find(&mut parent, u);
            let rv = find(&mut parent, v);
            if ru != rv {
                let bu = files.resolve(all_nodes[ru as usize].sref, &[], &worker_overflow);
                let bv = files.resolve(all_nodes[rv as usize].sref, &[], &worker_overflow);
                if bu < bv {
                    parent[rv as usize] = ru;
                } else {
                    parent[ru as usize] = rv;
                }
            }
        }
    }

    // Flatten iteratively: parent[i] points directly to final root of component.
    for i in 0..num_nodes {
        let mut r = parent[i];
        while parent[r as usize] != r {
            r = parent[r as usize];
        }
        let mut cur = i as u32;
        while parent[cur as usize] != r {
            let nxt = parent[cur as usize];
            parent[cur as usize] = r;
            cur = nxt;
        }
    }

    // Stage L5: Pack ONLY non-root nodes into compact LinkMap shards and drop link mmaps.
    let mut raw_arena: Vec<u8> = Vec::new();
    let mut canon_arena: Vec<u8> = Vec::new();
    let mut overflow_raw: Vec<Box<[u8]>> = Vec::new();
    let mut overflow_canon: Vec<Box<[u8]>> = Vec::new();
    let mut canon_placed: Vec<(u32, u16)> = vec![(0, 0); num_nodes]; // off, len (u16::MAX => overflow)
    let mut has_canon_placed = vec![false; num_nodes];
    let mut shards: Vec<HashTable<LinkEntry>> = (0..LINK_SHARDS).map(|_| HashTable::new()).collect();

    for i in 0..num_nodes {
        let r = parent[i] as usize;
        if r == i {
            continue;
        }
        if !has_canon_placed[r] {
            let cb = files.resolve(all_nodes[r].sref, &[], &worker_overflow);
            if cb.len() < u16::MAX as usize && canon_arena.len() + cb.len() <= u32::MAX as usize {
                let off = canon_arena.len() as u32;
                canon_arena.extend_from_slice(cb);
                canon_placed[r] = (off, cb.len() as u16);
            } else {
                let idx = overflow_canon.len() as u32;
                overflow_canon.push(cb.to_vec().into_boxed_slice());
                canon_placed[r] = (idx, u16::MAX);
            }
            has_canon_placed[r] = true;
        }
        let (canon_off, canon_len) = canon_placed[r];

        let rb = files.resolve(all_nodes[i].sref, &[], &worker_overflow);
        let (raw_off, raw_len) =
            if rb.len() < u16::MAX as usize && raw_arena.len() + rb.len() <= u32::MAX as usize {
                let off = raw_arena.len() as u32;
                raw_arena.extend_from_slice(rb);
                (off, rb.len() as u16)
            } else {
                let idx = overflow_raw.len() as u32;
                overflow_raw.push(rb.to_vec().into_boxed_slice());
                (idx, u16::MAX)
            };

        let raw_hash = all_nodes[i].hash;
        let canon_hash = all_nodes[r].hash;
        let shard = ((raw_hash >> 28) as usize) & (LINK_SHARDS - 1);
        shards[shard].insert_unique(
            raw_hash,
            LinkEntry {
                raw_off,
                raw_len,
                canon_len,
                canon_off,
                raw_hash,
                canon_hash,
            },
            |e| e.raw_hash,
        );
    }

    Ok(LinkMap {
        shards,
        raw_arena,
        canon_arena,
        overflow_raw,
        overflow_canon,
        empty: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_dsu_chain_hub_unused_smallest() {
        let dir = std::env::temp_dir().join("ss_test_links_unit");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut content = String::from("user_id_a,user_id_b\n");
        for i in 0..500 {
            content.push_str(&format!("id_{i:03},id_{:03}\n", i + 1));
        }
        content.push_str("id_250,!root\n");
        content.push_str("u1,u1\n");
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let hb = DefaultHashBuilder::default();
        let lm = build_link_map(&[p], &hb, 4).unwrap();
        let h500 = fast_hash_bytes(b"id_500", &hb);
        let (sref, ch) = lm.resolve(b"id_500", h500).unwrap();
        let resolved = &lm.canon_arena[sref.off as usize..sref.off as usize + sref.len as usize];
        assert_eq!(resolved, b"!root");
        assert_eq!(ch, fast_hash_bytes(b"!root", &hb));

        let hroot = fast_hash_bytes(b"!root", &hb);
        assert!(lm.resolve(b"!root", hroot).is_none());
        let hu1 = fast_hash_bytes(b"u1", &hb);
        assert!(lm.resolve(b"u1", hu1).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
