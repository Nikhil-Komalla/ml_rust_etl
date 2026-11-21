use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use hashbrown::HashMap;
use rayon::prelude::*;

use crate::csv::{
    cmp_raw_keys, mix64, resolve_raw_key, CompactKey64, CsvSource, LongArena, CHUNK_BYTES,
};

const LINK_SHARDS: usize = 32;
const BUILD_TAG_MASK: u32 = 0xFFF0_0000;
const BUILD_IDX_MASK: u32 = 0x000F_FFFF;

#[inline(always)]
fn link_tag12(h: u64) -> u32 {
    ((h >> 20) as u32) & BUILD_TAG_MASK
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinkSlot {
    key: u64,
    canon: CompactKey64,
}

#[inline(always)]
fn fast_range32(h: u64, cap: usize) -> usize {
    (((h as u32 as u64).wrapping_mul(cap as u64)) >> 32) as usize
}

#[inline(always)]
fn bloom_bits(h: u64) -> u64 {
    (1u64 << ((h >> 6) & 63))
        | (1u64 << ((h >> 12) & 63))
        | (1u64 << ((h >> 18) & 63))
        | (1u64 << ((h >> 24) & 63))
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
    slots: Vec<LinkSlot>,
    seg_cap: usize,
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
            slots: Vec::new(),
            seg_cap: 0,
            long_map: HashMap::new(),
            has_long: false,
            canon_arena: Vec::new(),
            canon_spans: Vec::new(),
            empty: true,
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    #[inline(always)]
    fn bloom_idx(&self, h: u64) -> usize {
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        (s << self.bloom_shift) | (((h >> 32) as usize) & self.bloom_sub_mask)
    }

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

    #[inline(always)]
    pub fn prefetch_slot(&self, h: u64) {
        if self.empty {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
            let seg_cap = self.seg_cap;
            let pos = fast_range32(h, seg_cap);
            std::arch::x86_64::_mm_prefetch(
                self.slots.as_ptr().add(s * seg_cap + pos) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn probe_inline_with_hash(&self, k: CompactKey64, h: u64) -> CompactKey64 {
        debug_assert!(!self.empty && k.is_inline());
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        let seg_cap = self.seg_cap;
        let base = s * seg_cap;
        let mut slot = fast_range32(h, seg_cap);
        loop {
            let cur = unsafe { *self.slots.get_unchecked(base + slot) };
            if cur.key == k.0 {
                return cur.canon;
            }
            if cur.key == 0 {
                return k;
            }
            slot += 1;
            if slot == seg_cap {
                slot = 0;
            }
        }
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn resolve_inline_with_hash(&self, k: CompactKey64, h: u64) -> CompactKey64 {
        if !self.bloom_may_contain(h) {
            return k;
        }
        self.probe_inline_with_hash(k, h)
    }

    #[cfg(test)]
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

    pub fn drop_lookup_tables(&mut self) {
        self.bloom = Vec::new();
        self.slots = Vec::new();
        self.seg_cap = 0;
        self.long_map = HashMap::new();
        self.has_long = false;
        self.empty = true;
    }
}

#[derive(Clone, Copy)]
struct NodeProbe {
    key: u64,
    tag12: u32,
    shard: u16,
    slot: u32,
}

impl NodeProbe {
    const EMPTY: Self = Self {
        key: 0,
        tag12: 0,
        shard: u16::MAX,
        slot: 0,
    };
}

#[inline(always)]
fn prep_node_probe(k: CompactKey64, build_shards: &[(Vec<u32>, usize)]) -> NodeProbe {
    if !k.is_ref() {
        let h = mix64(k.0);
        let tag12 = link_tag12(h);
        let s = ((h >> 52) as usize) & (LINK_SHARDS - 1);
        let (ref slots, mask) = unsafe { build_shards.get_unchecked(s) };
        let slot = (h as usize) & *mask;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::x86_64::_mm_prefetch(
                slots.as_ptr().add(slot) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
        NodeProbe {
            key: k.0,
            tag12,
            shard: s as u16,
            slot: slot as u32,
        }
    } else {
        NodeProbe {
            key: k.0,
            tag12: 0,
            shard: u16::MAX,
            slot: 0,
        }
    }
}

#[inline(always)]
fn resolve_node_probe(
    p: NodeProbe,
    build_shards: &[(Vec<u32>, usize)],
    offsets: &[usize; LINK_SHARDS + 1],
    all_nodes: &[CompactKey64],
    worker_arenas: &[LongArena],
    long_build_map: &HashMap<Box<[u8]>, u32>,
) -> u32 {
    if p.shard != u16::MAX {
        let s = p.shard as usize;
        let (ref slots, mask) = unsafe { build_shards.get_unchecked(s) };
        let base = unsafe { *offsets.get_unchecked(s) };
        let mut slot = p.slot as usize;
        loop {
            let cur = unsafe { *slots.get_unchecked(slot) };
            if (cur & BUILD_TAG_MASK) == p.tag12 {
                let local_idx = ((cur & BUILD_IDX_MASK) as usize).wrapping_sub(1);
                let gid = base + local_idx;
                if unsafe { all_nodes.get_unchecked(gid).0 } == p.key {
                    return gid as u32;
                }
            }
            slot = (slot + 1) & mask;
        }
    } else {
        let bytes = LongArena::resolve_in(worker_arenas, CompactKey64(p.key));
        *long_build_map.get(bytes).unwrap()
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

    rayon::scope(|scope| {
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
            scope.spawn(move |_| {
                let mut buf = Vec::new();
                loop {
                    let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(&task) = chunks_ref.get(cidx) else {
                        break;
                    };
                    if let Err(e) =
                        src_ref.for_each_chunk_l1_batch::<2>(task, &mut buf, |padded, lines| {
                            for lb in lines {
                                let (a_s, a_e) = lb.span(0);
                                let (b_s, b_e) = lb.span(1);
                                if a_e <= a_s || b_e <= b_s {
                                    continue;
                                }
                                let a = unsafe { padded.get_unchecked(a_s..a_e) };
                                let b = unsafe { padded.get_unchecked(b_s..b_e) };
                                if a == b {
                                    continue;
                                }
                                let ka =
                                    CompactKey64::encode_raw_inline_padded(padded, a_s, a_e - a_s)
                                        .unwrap_or_else(|| arena_out.push_ref(wid, a));
                                let kb =
                                    CompactKey64::encode_raw_inline_padded(padded, b_s, b_e - b_s)
                                        .unwrap_or_else(|| arena_out.push_ref(wid, b));
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
                            }
                        })
                    {
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

    // Stage L2: shard-parallel interning with 4B tagged slots (tag12 | (local_idx + 1)).
    let shard_results: Vec<(Vec<u32>, usize, Vec<CompactKey64>)> = shard_inputs
        .into_par_iter()
        .map(|batches| {
            let total: usize = batches.iter().map(Vec::len).sum();
            let mut cap = ((total * 10 / 9).max(16)).next_power_of_two();
            let mut mask = cap - 1;
            let mut slots = vec![0u32; cap];
            let mut nodes: Vec<CompactKey64> = Vec::with_capacity((total / 2).max(16));
            for batch in batches {
                for k in batch {
                    if (nodes.len() + 1) * 10 >= cap * 6 {
                        let new_cap = cap * 2;
                        let new_mask = new_cap - 1;
                        let mut new_slots = vec![0u32; new_cap];
                        for &cur in &slots {
                            if cur != 0 {
                                let idx = ((cur & BUILD_IDX_MASK) - 1) as usize;
                                let mut p = (mix64(nodes[idx].0) as usize) & new_mask;
                                while new_slots[p] != 0 {
                                    p = (p + 1) & new_mask;
                                }
                                new_slots[p] = cur;
                            }
                        }
                        slots = new_slots;
                        cap = new_cap;
                        mask = new_mask;
                    }
                    let h = mix64(k.0);
                    let tag12 = link_tag12(h);
                    let mut slot = (h as usize) & mask;
                    loop {
                        let cur = slots[slot];
                        if cur == 0 {
                            assert!(nodes.len() < BUILD_IDX_MASK as usize, "link shard overflow");
                            let idx1 = (nodes.len() + 1) as u32;
                            nodes.push(k);
                            slots[slot] = tag12 | idx1;
                            break;
                        }
                        if (cur & BUILD_TAG_MASK) == tag12 {
                            let idx = ((cur & BUILD_IDX_MASK) - 1) as usize;
                            if nodes[idx].0 == k.0 {
                                break;
                            }
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

    // Stage L3+L4 fused: prefetched ring-buffer lookup + parallel lock-free DSU union.
    let parent: Vec<AtomicU32> = (0..num_nodes as u32)
        .into_par_iter()
        .map(AtomicU32::new)
        .collect();

    let all_nodes_ref = &all_nodes;
    let arenas_ref = &worker_arenas;
    worker_edges.into_par_iter().for_each(|edges| {
        const RING: usize = 16;
        let len = edges.len();
        let mut ring = [(NodeProbe::EMPTY, NodeProbe::EMPTY); RING];
        let pre = len.min(RING);
        for i in 0..pre {
            let (ka, kb) = edges[i];
            ring[i] = (
                prep_node_probe(ka, &build_shards),
                prep_node_probe(kb, &build_shards),
            );
        }
        for idx in 0..len {
            let (pa, pb) = ring[idx & (RING - 1)];
            if idx + RING < len {
                let (ka, kb) = unsafe { *edges.get_unchecked(idx + RING) };
                ring[idx & (RING - 1)] = (
                    prep_node_probe(ka, &build_shards),
                    prep_node_probe(kb, &build_shards),
                );
            }
            let u0 = resolve_node_probe(
                pa,
                &build_shards,
                &offsets,
                all_nodes_ref,
                arenas_ref,
                &long_build_map,
            );
            let v0 = resolve_node_probe(
                pb,
                &build_shards,
                &offsets,
                all_nodes_ref,
                arenas_ref,
                &long_build_map,
            );
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

    drop(build_shards);
    drop(long_build_map);

    // Flatten parent in place in parallel to true root r (parent[r] == r), skipping r == i / r == p0.
    (0..num_nodes).into_par_iter().for_each(|i| {
        let p0 = parent[i].load(Ordering::Relaxed);
        if p0 as usize == i {
            return;
        }
        let mut r = p0;
        loop {
            let p = parent[r as usize].load(Ordering::Relaxed);
            if p == r {
                break;
            }
            r = p;
        }
        if r != p0 {
            parent[i].store(r, Ordering::Relaxed);
        }
    });

    let has_long_nodes = num_inline < num_nodes;
    let has_long_root = has_long_nodes
        && (0..num_nodes)
            .into_par_iter()
            .any(|i| all_nodes[parent[i].load(Ordering::Relaxed) as usize].is_ref());

    let mut canon_arena: Vec<u8> = Vec::new();
    let mut canon_spans: Vec<(u32, u32)> = Vec::new();
    let mut long_map: HashMap<Box<[u8]>, CompactKey64> = HashMap::new();
    let mut node_canon: Vec<CompactKey64> = Vec::new();

    if !has_long_root {
        if has_long_nodes {
            for i in num_inline..num_nodes {
                let r = parent[i].load(Ordering::Relaxed) as usize;
                let canon = all_nodes[r];
                let bytes = LongArena::resolve_in(&worker_arenas, all_nodes[i]);
                long_map.insert(bytes.to_vec().into_boxed_slice(), canon);
            }
        }
    } else {
        let mut root_canon = vec![CompactKey64::EMPTY; num_nodes];
        let mut scratch = [0u8; 10];
        for i in 0..num_nodes {
            let r = parent[i].load(Ordering::Relaxed) as usize;
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
            let r = parent[i].load(Ordering::Relaxed) as usize;
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

    // Stage L5: parallel 1-pass non-root collection + 80% fast_range shards + L2-resident Bloom.
    let total_words = (num_inline / 8)
        .max(64)
        .next_power_of_two()
        .min(131_072);
    let words_per_shard = (total_words / LINK_SHARDS).max(2);
    let bloom_shift = words_per_shard.trailing_zeros();
    let bloom_sub_mask = words_per_shard - 1;
    let mut bloom = vec![0u64; LINK_SHARDS * words_per_shard];

    let all_nodes_slice = &all_nodes;
    let parent_slice = &parent;
    let node_canon_slice = &node_canon;
    let offsets_ref = &offsets;
    let max_m = (0..LINK_SHARDS)
        .into_par_iter()
        .map(|s| {
            let lo = offsets_ref[s];
            let hi = offsets_ref[s + 1];
            let mut cnt = 0usize;
            if node_canon_slice.is_empty() {
                for i in lo..hi {
                    if parent_slice[i].load(Ordering::Relaxed) as usize != i {
                        cnt += 1;
                    }
                }
            } else {
                for i in lo..hi {
                    if node_canon_slice[i] != CompactKey64::EMPTY {
                        cnt += 1;
                    }
                }
            }
            cnt
        })
        .max()
        .unwrap_or(0);

    let seg_cap = ((max_m * 5 + 3) / 4).max(max_m + 1).max(2);
    let mut slots = vec![
        LinkSlot {
            key: 0,
            canon: CompactKey64::EMPTY,
        };
        LINK_SHARDS * seg_cap
    ];

    slots
        .par_chunks_mut(seg_cap)
        .zip(bloom.par_chunks_mut(words_per_shard))
        .enumerate()
        .for_each(|(s, (seg_slots, bloom_slice))| {
            let lo = offsets_ref[s];
            let hi = offsets_ref[s + 1];
            if node_canon_slice.is_empty() {
                for i in lo..hi {
                    let r = parent_slice[i].load(Ordering::Relaxed) as usize;
                    if i == r {
                        continue;
                    }
                    let canon = all_nodes_slice[r];
                    let key = all_nodes_slice[i].0;
                    let h = mix64(key);
                    let widx = ((h >> 32) as usize) & bloom_sub_mask;
                    bloom_slice[widx] |= bloom_bits(h);
                    let mut pos = fast_range32(h, seg_cap);
                    while seg_slots[pos].key != 0 {
                        pos += 1;
                        if pos == seg_cap {
                            pos = 0;
                        }
                    }
                    seg_slots[pos] = LinkSlot { key, canon };
                }
            } else {
                for i in lo..hi {
                    let canon = node_canon_slice[i];
                    if canon == CompactKey64::EMPTY {
                        continue;
                    }
                    let key = all_nodes_slice[i].0;
                    let h = mix64(key);
                    let widx = ((h >> 32) as usize) & bloom_sub_mask;
                    bloom_slice[widx] |= bloom_bits(h);
                    let mut pos = fast_range32(h, seg_cap);
                    while seg_slots[pos].key != 0 {
                        pos += 1;
                        if pos == seg_cap {
                            pos = 0;
                        }
                    }
                    seg_slots[pos] = LinkSlot { key, canon };
                }
            }
        });
    drop(parent);

    Ok(LinkMap {
        bloom,
        bloom_shift,
        bloom_sub_mask,
        slots,
        seg_cap,
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
