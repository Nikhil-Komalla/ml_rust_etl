use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashMap;
use rayon::prelude::*;

use crate::csv::{
    cmp_raw_keys, mix64, resolve_raw_key, CompactKey64, CsvSource, LongArena, CHUNK_BYTES,
};

const LINK_SHARDS: usize = 32;

#[derive(Clone, Copy)]
#[repr(C)]
struct BuildSlot {
    key: u64,
    val: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinkSlot {
    key: u64,
    canon: CompactKey64,
}

struct FlatLinkShard {
    slots: Vec<LinkSlot>,
    mask: usize,
}

pub struct LinkMap {
    bloom: Vec<u64>,
    bloom_mask: usize,
    shards: Vec<FlatLinkShard>,
    long_map: HashMap<Box<[u8]>, CompactKey64>,
    has_long: bool,
    canon_arena: Vec<u8>,
    canon_spans: Vec<(u32, u32)>,
    empty: bool,
}

impl LinkMap {
    pub fn empty() -> Self {
        Self {
            bloom: Vec::new(),
            bloom_mask: 0,
            shards: Vec::new(),
            long_map: HashMap::new(),
            has_long: false,
            canon_arena: Vec::new(),
            canon_spans: Vec::new(),
            empty: true,
        }
    }

    #[inline(always)]
    pub fn resolve_inline(&self, k: CompactKey64) -> CompactKey64 {
        debug_assert!(!k.is_ref() && k != CompactKey64::EMPTY);
        if self.empty {
            return k;
        }
        let h = mix64(k.0);
        let w = self.bloom[((h >> 32) as usize) & self.bloom_mask];
        let need = (1u64 << ((h >> 16) & 63)) | (1u64 << ((h >> 22) & 63));
        if (w & need) != need {
            return k;
        }
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        let shard = &self.shards[s];
        let mut slot = (h as usize) & shard.mask;
        loop {
            let cur = shard.slots[slot];
            if cur.key == k.0 {
                return cur.canon;
            }
            if cur.key == 0 {
                return k;
            }
            slot = (slot + 1) & shard.mask;
        }
    }

    #[inline(always)]
    pub fn resolve_long(&self, bytes: &[u8]) -> Option<CompactKey64> {
        if !self.has_long {
            return None;
        }
        self.long_map.get(bytes).copied()
    }

    #[inline(always)]
    pub fn canon_bytes(&self, comp_id: u32) -> &[u8] {
        let (off, len) = self.canon_spans[comp_id as usize];
        &self.canon_arena[off as usize..off as usize + len as usize]
    }
}

pub fn build_link_map(paths: &[PathBuf], ncpu: usize) -> io::Result<LinkMap> {
    if paths.is_empty() {
        return Ok(LinkMap::empty());
    }
    let src = CsvSource::open(paths)?;
    let chunks = src.chunks(CHUNK_BYTES);
    if chunks.is_empty() {
        return Ok(LinkMap::empty());
    }

    // Stage L1: parallel CsvSource parse into per-worker edge lists and sharded inline endpoints.
    let next_chunk = AtomicUsize::new(0);
    let nworkers = ncpu.clamp(1, 63).min(chunks.len());
    let mut worker_edges: Vec<Vec<(CompactKey64, CompactKey64)>> =
        (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_inline_buckets: Vec<Vec<Vec<CompactKey64>>> = (0..nworkers)
        .map(|_| (0..LINK_SHARDS).map(|_| Vec::new()).collect())
        .collect();
    let mut worker_long_endpoints: Vec<Vec<CompactKey64>> =
        (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_arenas: Vec<LongArena> = (0..nworkers).map(|_| LongArena::default()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..nworkers).map(|_| None).collect();

    std::thread::scope(|scope| {
        for (wid, ((((edges_out, buckets_out), long_out), arena_out), err_out)) in worker_edges
            .iter_mut()
            .zip(worker_inline_buckets.iter_mut())
            .zip(worker_long_endpoints.iter_mut())
            .zip(worker_arenas.iter_mut())
            .zip(worker_errs.iter_mut())
            .enumerate()
        {
            let src_ref = &src;
            let chunks_ref = &chunks;
            let next_ref = &next_chunk;
            scope.spawn(move || {
                let mut buf = Vec::new();
                loop {
                    let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(&task) = chunks_ref.get(cidx) else {
                        break;
                    };
                    if let Err(e) = src_ref.for_each_chunk_line::<2>(task, &mut buf, |[a, b]| {
                        if a.is_empty() || b.is_empty() || a == b {
                            return;
                        }
                        let ka = CompactKey64::encode_raw(a, wid, arena_out);
                        let kb = CompactKey64::encode_raw(b, wid, arena_out);
                        edges_out.push((ka, kb));
                        if !ka.is_ref() {
                            let s = ((mix64(ka.0) >> 52) as usize) & (LINK_SHARDS - 1);
                            buckets_out[s].push(ka);
                        } else {
                            long_out.push(ka);
                        }
                        if !kb.is_ref() {
                            let s = ((mix64(kb.0) >> 52) as usize) & (LINK_SHARDS - 1);
                            buckets_out[s].push(kb);
                        } else {
                            long_out.push(kb);
                        }
                    }) {
                        *err_out = Some(e);
                        break;
                    }
                }
            });
        }
    });

    for e in worker_errs.into_iter().flatten() {
        return Err(e);
    }

    let total_edges: usize = worker_edges.iter().map(Vec::len).sum();
    if total_edges == 0 {
        return Ok(LinkMap::empty());
    }

    // Transpose [worker][shard] -> [shard][worker] without copying elements.
    let mut shard_inputs: Vec<Vec<Vec<CompactKey64>>> = (0..LINK_SHARDS)
        .map(|_| Vec::with_capacity(nworkers))
        .collect();
    for mut w_buckets in worker_inline_buckets {
        for (s, v) in w_buckets.drain(..).enumerate() {
            if !v.is_empty() {
                shard_inputs[s].push(v);
            }
        }
    }

    // Stage L2: shard-parallel interning with tight dynamic capacity (avoids huge 2*total buffers).
    let shard_results: Vec<(Vec<BuildSlot>, usize, Vec<CompactKey64>)> = shard_inputs
        .into_par_iter()
        .map(|batches| {
            let total: usize = batches.iter().map(Vec::len).sum();
            let mut cap = (total / 2).max(8).next_power_of_two();
            let mut mask = cap - 1;
            let mut slots = vec![BuildSlot { key: 0, val: 0 }; cap];
            let mut nodes = Vec::with_capacity((total / 3).max(16));
            for batch in batches {
                for k in batch {
                    if (nodes.len() + 1) * 10 >= cap * 6 {
                        let new_cap = cap * 2;
                        let new_mask = new_cap - 1;
                        let mut new_slots = vec![BuildSlot { key: 0, val: 0 }; new_cap];
                        for s in &slots {
                            if s.key != 0 {
                                let mut p = (mix64(s.key) as usize) & new_mask;
                                while new_slots[p].key != 0 {
                                    p = (p + 1) & new_mask;
                                }
                                new_slots[p] = *s;
                            }
                        }
                        slots = new_slots;
                        cap = new_cap;
                        mask = new_mask;
                    }
                    let h = mix64(k.0);
                    let mut slot = (h as usize) & mask;
                    loop {
                        let cur = slots[slot];
                        if cur.key == k.0 {
                            break;
                        }
                        if cur.key == 0 {
                            let idx = nodes.len() as u32;
                            nodes.push(k);
                            slots[slot] = BuildSlot {
                                key: k.0,
                                val: idx,
                            };
                            break;
                        }
                        slot = (slot + 1) & mask;
                    }
                }
            }
            (slots, mask, nodes)
        })
        .collect();

    let mut offsets = [0usize; LINK_SHARDS + 1];
    let mut num_inline = 0usize;
    let mut build_shards = Vec::with_capacity(LINK_SHARDS);
    let mut shard_nodes_list = Vec::with_capacity(LINK_SHARDS);
    for (s, (slots, mask, nodes)) in shard_results.into_iter().enumerate() {
        offsets[s] = num_inline;
        num_inline += nodes.len();
        build_shards.push((slots, mask));
        shard_nodes_list.push(nodes);
    }
    offsets[LINK_SHARDS] = num_inline;

    let mut long_build_map: HashMap<Box<[u8]>, u32> = HashMap::new();
    let mut long_nodes: Vec<CompactKey64> = Vec::new();
    for batch in &worker_long_endpoints {
        for &k in batch {
            let bytes = LongArena::resolve_in(&worker_arenas, k);
            if !long_build_map.contains_key(bytes) {
                let global_id = (num_inline + long_nodes.len()) as u32;
                long_build_map.insert(bytes.to_vec().into_boxed_slice(), global_id);
                long_nodes.push(k);
            }
        }
    }
    drop(worker_long_endpoints);

    let num_nodes = num_inline + long_nodes.len();
    let mut all_nodes: Vec<CompactKey64> = Vec::with_capacity(num_nodes);
    for mut v in shard_nodes_list {
        all_nodes.append(&mut v);
    }
    all_nodes.append(&mut long_nodes);

    // Stage L3: map all edges to dense u32 pairs in parallel.
    let resolved_batches: Vec<Vec<(u32, u32)>> = worker_edges
        .par_iter()
        .map(|edges| {
            let mut out = Vec::with_capacity(edges.len());
            let resolve_node = |k: CompactKey64| -> u32 {
                if !k.is_ref() {
                    let h = mix64(k.0);
                    let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
                    let (ref slots, mask) = build_shards[s];
                    let mut slot = (h as usize) & mask;
                    loop {
                        let cur = slots[slot];
                        if cur.key == k.0 {
                            return (offsets[s] as u32) + cur.val;
                        }
                        slot = (slot + 1) & mask;
                    }
                } else {
                    let bytes = LongArena::resolve_in(&worker_arenas, k);
                    *long_build_map.get(bytes).unwrap()
                }
            };
            for &(ka, kb) in edges {
                out.push((resolve_node(ka), resolve_node(kb)));
            }
            out
        })
        .collect();

    drop(worker_edges);
    drop(build_shards);
    drop(long_build_map);

    // Stage L4: iterative DSU union-to-byte-wise-smallest root.
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
                let ord = cmp_raw_keys(
                    all_nodes[ru as usize],
                    all_nodes[rv as usize],
                    &worker_arenas,
                    &worker_arenas,
                );
                if ord == std::cmp::Ordering::Less {
                    parent[rv as usize] = ru;
                } else {
                    parent[ru as usize] = rv;
                }
            }
        }
    }

    // Flatten iteratively.
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

    // Build non-root-only canonical mapping (plus both root+non-roots for Tag 11 long roots).
    let mut root_canon = vec![CompactKey64::EMPTY; num_nodes];
    let mut canon_arena: Vec<u8> = Vec::new();
    let mut canon_spans: Vec<(u32, u32)> = Vec::new();
    let mut scratch = [0u8; 10];
    for i in 0..num_nodes {
        let r = parent[i] as usize;
        if root_canon[r] == CompactKey64::EMPTY {
            let r_key = all_nodes[r];
            if !r_key.is_ref() {
                root_canon[r] = r_key;
            } else {
                let cid = canon_spans.len() as u32;
                let bytes = resolve_raw_key(r_key, &worker_arenas, &mut scratch);
                let off = canon_arena.len() as u32;
                canon_arena.extend_from_slice(bytes);
                canon_spans.push((off, bytes.len() as u32));
                root_canon[r] = CompactKey64::from_comp(cid);
            }
        }
    }

    // node_canon[i] == CompactKey64::EMPTY means skip storing node i (inline root resolves to itself on miss).
    let mut node_canon = vec![CompactKey64::EMPTY; num_nodes];
    let mut long_map: HashMap<Box<[u8]>, CompactKey64> = HashMap::new();
    for i in 0..num_nodes {
        let r = parent[i] as usize;
        let canon = root_canon[r];
        let k = all_nodes[i];
        if !k.is_ref() {
            if i != r || all_nodes[r].is_ref() {
                node_canon[i] = canon;
            }
        } else {
            let bytes = LongArena::resolve_in(&worker_arenas, k);
            long_map.insert(bytes.to_vec().into_boxed_slice(), canon);
        }
    }
    let has_long = !long_map.is_empty();

    drop(parent);
    drop(root_canon);
    drop(worker_arenas);

    // Stage L5: parallel compact rebuild of the 32 final shards sized tightly to emitted non-root count!
    let final_shard_results: Vec<(FlatLinkShard, usize)> = (0..LINK_SHARDS)
        .into_par_iter()
        .map(|s| {
            let lo = offsets[s];
            let hi = offsets[s + 1];
            let mut m = 0usize;
            for i in lo..hi {
                if node_canon[i] != CompactKey64::EMPTY {
                    m += 1;
                }
            }
            let cap = (m * 10 / 6).max(2).next_power_of_two();
            let mask = cap - 1;
            let mut slots = vec![
                LinkSlot {
                    key: 0,
                    canon: CompactKey64::EMPTY,
                };
                cap
            ];
            for i in lo..hi {
                let canon = node_canon[i];
                if canon != CompactKey64::EMPTY {
                    let key = all_nodes[i].0;
                    let mut pos = (mix64(key) as usize) & mask;
                    while slots[pos].key != 0 {
                        pos = (pos + 1) & mask;
                    }
                    slots[pos] = LinkSlot { key, canon };
                }
            }
            (FlatLinkShard { slots, mask }, m)
        })
        .collect();

    let mut shards = Vec::with_capacity(LINK_SHARDS);
    let mut total_inline_entries = 0usize;
    for (sh, m) in final_shard_results {
        total_inline_entries += m;
        shards.push(sh);
    }

    let bloom_words = (total_inline_entries * 3 / 8).max(64).next_power_of_two();
    let bloom_mask = bloom_words - 1;
    let mut bloom = vec![0u64; bloom_words];
    for i in 0..num_inline {
        if node_canon[i] != CompactKey64::EMPTY {
            let h = mix64(all_nodes[i].0);
            let w = ((h >> 32) as usize) & bloom_mask;
            bloom[w] |= (1u64 << ((h >> 16) & 63)) | (1u64 << ((h >> 22) & 63));
        }
    }

    Ok(LinkMap {
        bloom,
        bloom_mask,
        shards,
        long_map,
        has_long,
        canon_arena,
        canon_spans,
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
        // Mix Tag 10/01 and Tag 11 long/special IDs with a Tag 11 root
        content.push_str("chain_00000,chain_00001\n");
        content.push_str("chain_00001,!chain_min\n");
        content.push_str("u99,chain_00000\n");
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let lm = build_link_map(&[p], 4).unwrap();
        // Inline root component: !root is inline Tag 01, so id_500 and !root both resolve to inline !root
        let k500 = CompactKey64::encode_raw_inline(b"id_500").unwrap();
        let kroot = CompactKey64::encode_raw_inline(b"!root").unwrap();
        assert_eq!(lm.resolve_inline(k500), kroot);
        assert_eq!(lm.resolve_inline(kroot), kroot);

        // Self-link u1,u1 changes nothing
        let ku1 = CompactKey64::encode_raw_inline(b"u1").unwrap();
        assert_eq!(lm.resolve_inline(ku1), ku1);

        // Long root component: !chain_min is Tag 11, so all 3 resolve to the same Tag 00 comp_id
        let kchain = lm.resolve_long(b"chain_00000").unwrap();
        assert!(kchain.is_comp());
        assert_eq!(lm.canon_bytes(kchain.comp_id()), b"!chain_min");
        let kchain_min = lm.resolve_long(b"!chain_min").unwrap();
        assert_eq!(kchain_min, kchain);
        let ku99 = CompactKey64::encode_raw_inline(b"u99").unwrap();
        assert_eq!(lm.resolve_inline(ku99), kchain);

        let _ = fs::remove_dir_all(&dir);
    }
}
