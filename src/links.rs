use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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
    cap: usize,
}

#[inline(always)]
fn fast_range32(h: u64, cap: usize) -> usize {
    (((h as u32 as u64).wrapping_mul(cap as u64)) >> 32) as usize
}

#[inline(always)]
fn bloom_bits(h: u64) -> u64 {
    (1u64 << ((h >> 12) & 63)) | (1u64 << ((h >> 18) & 63)) | (1u64 << ((h >> 24) & 63))
}

#[inline(always)]
fn atomic_find(parent: &[AtomicU32], mut x: u32) -> u32 {
    loop {
        let p = parent[x as usize].load(Ordering::Relaxed);
        if p == x {
            return x;
        }
        let gp = parent[p as usize].load(Ordering::Relaxed);
        if gp != p {
            let _ = parent[x as usize].compare_exchange_weak(
                p,
                gp,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        x = gp;
    }
}

pub struct LinkMap {
    bloom: Vec<u64>,
    bloom_shift: u32,
    bloom_sub_mask: usize,
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
            bloom_shift: 0,
            bloom_sub_mask: 0,
            shards: Vec::new(),
            long_map: HashMap::new(),
            has_long: false,
            canon_arena: Vec::new(),
            canon_spans: Vec::new(),
            empty: true,
        }
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    #[inline(always)]
    fn bloom_idx(&self, h: u64) -> usize {
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        (s << self.bloom_shift) | (((h >> 32) as usize) & self.bloom_sub_mask)
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn prefetch_bloom(&self, h: u64) {
        if self.empty {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let idx = self.bloom_idx(h);
            std::arch::x86_64::_mm_prefetch(
                self.bloom.as_ptr().add(idx) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn bloom_may_contain(&self, h: u64) -> bool {
        if self.empty {
            return false;
        }
        let idx = self.bloom_idx(h);
        let w = unsafe { *self.bloom.get_unchecked(idx) };
        let need = bloom_bits(h);
        (w & need) == need
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn prefetch_slot(&self, h: u64) {
        if self.empty {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
            let shard = self.shards.get_unchecked(s);
            let slot = fast_range32(h, shard.cap);
            std::arch::x86_64::_mm_prefetch(
                shard.slots.as_ptr().add(slot) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn probe_inline_with_hash(&self, k: CompactKey64, h: u64) -> CompactKey64 {
        debug_assert!(!self.empty && k.is_inline());
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        let shard = unsafe { self.shards.get_unchecked(s) };
        let cap = shard.cap;
        let mut slot = fast_range32(h, cap);
        loop {
            let cur = unsafe { *shard.slots.get_unchecked(slot) };
            if cur.key == k.0 {
                return cur.canon;
            }
            if cur.key == 0 {
                return k;
            }
            slot += 1;
            if slot == cap {
                slot = 0;
            }
        }
    }

    #[inline(always)]
    pub fn resolve_inline_with_hash(&self, k: CompactKey64, h: u64) -> CompactKey64 {
        if !self.bloom_may_contain(h) {
            return k;
        }
        self.probe_inline_with_hash(k, h)
    }

    #[inline(always)]
    pub fn resolve_inline(&self, k: CompactKey64) -> CompactKey64 {
        debug_assert!(!k.is_ref() && k != CompactKey64::EMPTY);
        if self.empty {
            return k;
        }
        self.resolve_inline_with_hash(k, mix64(k.0))
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

    #[allow(dead_code)]
    pub fn drop_lookup_tables(&mut self) {
        self.bloom = Vec::new();
        self.shards = Vec::new();
        self.long_map = HashMap::new();
        self.has_long = false;
        self.empty = true;
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

    // Stage L4: parallel lock-free DSU union-to-byte-wise-smallest root.
    let parent: Vec<AtomicU32> = (0..num_nodes as u32)
        .into_par_iter()
        .map(AtomicU32::new)
        .collect();

    let all_nodes_ref = &all_nodes;
    let arenas_ref = &worker_arenas;
    resolved_batches.into_par_iter().for_each(|batch| {
        for (u0, v0) in batch {
            loop {
                let u = atomic_find(&parent, u0);
                let v = atomic_find(&parent, v0);
                if u == v {
                    break;
                }
                let ord = cmp_raw_keys(
                    all_nodes_ref[u as usize],
                    all_nodes_ref[v as usize],
                    arenas_ref,
                    arenas_ref,
                );
                let (lo, hi) = if ord == std::cmp::Ordering::Less {
                    (u, v)
                } else {
                    (v, u)
                };
                if parent[hi as usize]
                    .compare_exchange_weak(hi, lo, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }
        }
    });

    // Flatten into static u32 vector in parallel.
    let flat_parent: Vec<u32> = (0..num_nodes)
        .into_par_iter()
        .map(|i| {
            let mut r = parent[i].load(Ordering::Relaxed);
            loop {
                let p = parent[r as usize].load(Ordering::Relaxed);
                if p == r {
                    return r;
                }
                r = p;
            }
        })
        .collect();
    drop(parent);

    let has_long_nodes = num_inline < num_nodes;
    let has_long_root = has_long_nodes
        && flat_parent
            .par_iter()
            .any(|&r| all_nodes[r as usize].is_ref());

    let mut canon_arena: Vec<u8> = Vec::new();
    let mut canon_spans: Vec<(u32, u32)> = Vec::new();
    let mut long_map: HashMap<Box<[u8]>, CompactKey64> = HashMap::new();
    let mut node_canon: Vec<CompactKey64> = Vec::new();

    if !has_long_root {
        if has_long_nodes {
            for i in num_inline..num_nodes {
                let r = flat_parent[i] as usize;
                let canon = all_nodes[r];
                let bytes = LongArena::resolve_in(&worker_arenas, all_nodes[i]);
                long_map.insert(bytes.to_vec().into_boxed_slice(), canon);
            }
        }
    } else {
        let mut root_canon = vec![CompactKey64::EMPTY; num_nodes];
        let mut scratch = [0u8; 10];
        for i in 0..num_nodes {
            let r = flat_parent[i] as usize;
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

        node_canon = vec![CompactKey64::EMPTY; num_nodes];
        for i in 0..num_nodes {
            let r = flat_parent[i] as usize;
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
    }
    let has_long = !long_map.is_empty();
    drop(worker_arenas);

    // Stage L5: parallel compact fast_range shards + parallel L2-resident 1 MB 3-bit Bloom.
    let total_words = (num_inline / 8)
        .max(64)
        .next_power_of_two()
        .min(131_072);
    let words_per_shard = (total_words / LINK_SHARDS).max(2);
    let bloom_shift = words_per_shard.trailing_zeros();
    let bloom_sub_mask = words_per_shard - 1;
    let mut bloom = vec![0u64; LINK_SHARDS * words_per_shard];

    let all_nodes_slice = &all_nodes;
    let flat_parent_slice = &flat_parent;
    let node_canon_slice = &node_canon;
    let shards: Vec<FlatLinkShard> = bloom
        .par_chunks_mut(words_per_shard)
        .enumerate()
        .map(|(s, bloom_slice)| {
            let lo = offsets[s];
            let hi = offsets[s + 1];
            let canon_of = |i: usize| -> CompactKey64 {
                if node_canon_slice.is_empty() {
                    let r = flat_parent_slice[i] as usize;
                    if i != r {
                        all_nodes_slice[r]
                    } else {
                        CompactKey64::EMPTY
                    }
                } else {
                    node_canon_slice[i]
                }
            };
            let mut m = 0usize;
            for i in lo..hi {
                if canon_of(i) != CompactKey64::EMPTY {
                    m += 1;
                }
            }
            let cap = ((m * 10 + 6) / 7).max(m + 1).max(2);
            let mut slots = vec![
                LinkSlot {
                    key: 0,
                    canon: CompactKey64::EMPTY,
                };
                cap
            ];
            for i in lo..hi {
                let canon = canon_of(i);
                if canon != CompactKey64::EMPTY {
                    let key = all_nodes_slice[i].0;
                    let h = mix64(key);
                    let widx = ((h >> 32) as usize) & bloom_sub_mask;
                    bloom_slice[widx] |= bloom_bits(h);
                    let mut pos = fast_range32(h, cap);
                    while slots[pos].key != 0 {
                        pos += 1;
                        if pos == cap {
                            pos = 0;
                        }
                    }
                    slots[pos] = LinkSlot { key, canon };
                }
            }
            FlatLinkShard { slots, cap }
        })
        .collect();

    Ok(LinkMap {
        bloom,
        bloom_shift,
        bloom_sub_mask,
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

    #[test]
    fn test_dsu_fast_path_bloom_and_drop() {
        let dir = std::env::temp_dir().join("ss_test_links_fast");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut content = String::from("user_id_a,user_id_b\n");
        for i in 0..300 {
            content.push_str(&format!("id_{i:03},id_{:03}\n", i + 1));
        }
        content.push_str("id_150,!minroot\n");
        content.push_str("long_alias_12345,id_200\n");
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let mut lm = build_link_map(&[p], 4).unwrap();
        assert!(!lm.is_empty());
        let k_min = CompactKey64::encode_raw_inline(b"!minroot").unwrap();
        let k_300 = CompactKey64::encode_raw_inline(b"id_300").unwrap();
        let h_300 = mix64(k_300.0);
        lm.prefetch_bloom(h_300);
        assert!(lm.bloom_may_contain(h_300));
        lm.prefetch_slot(h_300);
        assert_eq!(lm.probe_inline_with_hash(k_300, h_300), k_min);
        assert_eq!(lm.resolve_inline(k_min), k_min);
        assert_eq!(lm.resolve_long(b"long_alias_12345"), Some(k_min));

        let k_miss = CompactKey64::encode_raw_inline(b"unseen999").unwrap();
        assert_eq!(lm.resolve_inline(k_miss), k_miss);

        lm.drop_lookup_tables();
        assert!(lm.is_empty());
        assert_eq!(lm.resolve_inline(k_300), k_300);

        let _ = fs::remove_dir_all(&dir);
    }
}
