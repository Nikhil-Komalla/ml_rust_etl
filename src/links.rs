use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use hashbrown::HashMap;
use rayon::prelude::*;

use crate::csv::{
    biject42, cmp_raw_keys, encode_b37_pair_padded, field_span, mix64, resolve_raw_key,
    CompactKey64, CsvSource, LongArena, CHUNK_BYTES,
};
use crate::slab::{HugeBuf, Zeroable};

const LINK_SHARDS: usize = 32;
const BUILD_TAG_MASK: u32 = 0xFFF0_0000;
const BUILD_IDX_MASK: u32 = 0x000F_FFFF;
const REM37_MASK: u64 = (1u64 << 37) - 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct LinkSlotB37 {
    key_p1: u64, // (h42 & REM37_MASK) + 1; 0 = empty
    canon: CompactKey64,
}

const _: () = assert!(std::mem::size_of::<LinkSlotB37>() == 16);
unsafe impl Zeroable for LinkSlotB37 {}

#[inline(always)]
fn link_tag12(h: u64) -> u32 {
    ((h >> 20) as u32) & BUILD_TAG_MASK
}

#[inline(always)]
fn fast_range32(h: u64, cap: usize) -> usize {
    (((h as u32 as u64).wrapping_mul(cap as u64)) >> 32) as usize
}

#[inline(always)]
fn bloom_bits(h42: u64) -> u64 {
    (1u64 << (h42 & 63))
        | (1u64 << ((h42 >> 6) & 63))
        | (1u64 << ((h42 >> 12) & 63))
        | (1u64 << ((h42 >> 18) & 63))
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
    bloom: HugeBuf<u64>,
    bloom_shift: u32,
    bloom_sub_mask: usize,
    slots_b37: HugeBuf<LinkSlotB37>,
    seg_cap: usize,
    other_map: HashMap<CompactKey64, CompactKey64>,
    has_other: bool,
    long_map: HashMap<Box<[u8]>, CompactKey64>,
    has_long: bool,
    canon_arena: Vec<u8>,
    canon_spans: Vec<(u32, u32)>,
    empty: bool,
}

impl LinkMap {
    pub fn empty() -> Self {
        Self {
            bloom: HugeBuf::default(),
            bloom_shift: 0,
            bloom_sub_mask: 0,
            slots_b37: HugeBuf::default(),
            seg_cap: 0,
            other_map: HashMap::new(),
            has_other: false,
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
    fn bloom_idx(&self, h42: u64) -> usize {
        let s = (h42 >> 37) as usize;
        (s << self.bloom_shift) | (((h42 >> 23) as usize) & self.bloom_sub_mask)
    }

    #[inline(always)]
    pub fn prefetch_bloom_b37(&self, h42: u64) {
        if self.bloom.is_empty() {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let bidx = self.bloom_idx(h42);
            std::arch::x86_64::_mm_prefetch(
                self.bloom.as_ptr().add(bidx) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn bloom_may_contain_b37(&self, h42: u64) -> bool {
        if self.bloom.is_empty() {
            return false;
        }
        let bidx = self.bloom_idx(h42);
        let w = unsafe { *self.bloom.get_unchecked(bidx) };
        let need = bloom_bits(h42);
        (w & need) == need
    }

    #[inline(always)]
    pub fn prefetch_slot_b37(&self, h42: u64) {
        if self.empty || self.seg_cap == 0 {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let s = (h42 >> 37) as usize;
            let rem37 = h42 & REM37_MASK;
            let pos = fast_range32(rem37, self.seg_cap);
            std::arch::x86_64::_mm_prefetch(
                self.slots_b37.as_ptr().add(s * self.seg_cap + pos) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn probe_b37(&self, h42: u64) -> Option<CompactKey64> {
        if self.empty || self.seg_cap == 0 {
            return None;
        }
        let s = (h42 >> 37) as usize;
        let rem37 = h42 & REM37_MASK;
        let key_p1 = rem37 + 1;
        let seg_cap = self.seg_cap;
        let base = s * seg_cap;
        let mut slot = fast_range32(rem37, seg_cap);
        loop {
            let cur = unsafe { *self.slots_b37.get_unchecked(base + slot) };
            if cur.key_p1 == 0 {
                return None;
            }
            if cur.key_p1 == key_p1 {
                return Some(cur.canon);
            }
            slot += 1;
            if slot == seg_cap {
                slot = 0;
            }
        }
    }

    #[inline(always)]
    pub fn resolve_other_inline(&self, k: CompactKey64) -> Option<CompactKey64> {
        if !self.has_other {
            return None;
        }
        self.other_map.get(&k).copied()
    }

    #[inline(always)]
    pub fn resolve_long(&self, bytes: &[u8]) -> Option<CompactKey64> {
        if !self.has_long {
            return None;
        }
        self.long_map.get(bytes).copied()
    }

    #[inline(always)]
    pub fn resolve_long_canon_bytes(&self, span_idx: u32) -> &[u8] {
        let (off, len) = unsafe { *self.canon_spans.get_unchecked(span_idx as usize) };
        unsafe {
            self.canon_arena
                .get_unchecked(off as usize..off as usize + len as usize)
        }
    }

    pub fn drop_lookup_tables(&mut self) {
        self.bloom = HugeBuf::default();
        self.slots_b37 = HugeBuf::default();
        self.seg_cap = 0;
        self.other_map = HashMap::new();
        self.has_other = false;
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
                        src_ref.for_each_chunk_direct_batched::<2>(task, &mut buf, |padded, lines| {
                            let base = padded.as_ptr();
                            for dl in lines {
                                let ls = dl.ls as usize;
                                let c0 = dl.commas_end[0] as usize;
                                let le = dl.commas_end[1] as usize;
                                let (a_s, a_e) = unsafe { field_span(base, ls, c0) };
                                let (b_s, b_e) = unsafe { field_span(base, c0 + 1, le) };
                                let a_len = a_e - a_s;
                                let b_len = b_e - b_s;
                                if a_len == 0 || b_len == 0 {
                                    continue;
                                }
                                if let Some((va, vb)) = encode_b37_pair_padded(
                                    padded, a_s, a_len, b'u', b_s, b_len, b'u',
                                ) {
                                    if va == vb {
                                        continue;
                                    }
                                    let ka = CompactKey64::from_ub37(va);
                                    let kb = CompactKey64::from_ub37(vb);
                                    edges_out.push((ka, kb));
                                    let sa = ((mix64(ka.0) >> 52) as usize) & (LINK_SHARDS - 1);
                                    buckets_out[sa].push(ka);
                                    let sb = ((mix64(kb.0) >> 52) as usize) & (LINK_SHARDS - 1);
                                    buckets_out[sb].push(kb);
                                    continue;
                                }
                                let a = unsafe { padded.get_unchecked(a_s..a_e) };
                                let b = unsafe { padded.get_unchecked(b_s..b_e) };
                                if a == b {
                                    continue;
                                }
                                let ka = CompactKey64::encode_user_inline_padded(padded, a_s, a_len)
                                    .unwrap_or_else(|| arena_out.push_ref(wid, a));
                                let kb = CompactKey64::encode_user_inline_padded(padded, b_s, b_len)
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

    // Flatten parent in place in parallel to true root r (parent[r] == r).
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

    // Build direct canonical CompactKey64 per root (parallel when all endpoints are inline).
    let mut canon_arena: Vec<u8> = Vec::new();
    let mut canon_spans: Vec<(u32, u32)> = Vec::new();
    let root_canon: Vec<CompactKey64> = if num_inline == num_nodes {
        (0..num_nodes)
            .into_par_iter()
            .map(|i| {
                if parent[i].load(Ordering::Relaxed) as usize != i {
                    return CompactKey64::EMPTY;
                }
                let r_key = all_nodes[i];
                if r_key.is_ub37() {
                    CompactKey64::from_uh42(biject42(r_key.ub37_val()))
                } else {
                    r_key
                }
            })
            .collect()
    } else {
        let mut rc = vec![CompactKey64::EMPTY; num_nodes];
        let mut scratch = [0u8; 10];
        for i in 0..num_nodes {
            if parent[i].load(Ordering::Relaxed) as usize == i {
                let r_key = all_nodes[i];
                if r_key.is_ub37() {
                    rc[i] = CompactKey64::from_uh42(biject42(r_key.ub37_val()));
                } else if !r_key.is_ref() {
                    rc[i] = r_key;
                } else {
                    let bytes = resolve_raw_key(r_key, &worker_arenas, &mut scratch);
                    let sidx = canon_spans.len() as u32;
                    let off = canon_arena.len() as u32;
                    canon_arena.extend_from_slice(bytes);
                    canon_spans.push((off, bytes.len() as u32));
                    rc[i] = CompactKey64::from_comp(sidx);
                }
            }
        }
        rc
    };
    assert!(
        canon_spans.len() < (u32::MAX as usize),
        "too many long link components"
    );

    let mut long_map: HashMap<Box<[u8]>, CompactKey64> = HashMap::new();
    for i in num_inline..num_nodes {
        let r = parent[i].load(Ordering::Relaxed) as usize;
        let canon = root_canon[r];
        let bytes = LongArena::resolve_in(&worker_arenas, all_nodes[i]);
        long_map.insert(bytes.to_vec().into_boxed_slice(), canon);
    }
    let has_long = !long_map.is_empty();
    drop(worker_arenas);

    // Stage L5: partition ONLY non-root inline nodes into 32 b37 shards and rare other_map.
    let par_workers = ncpu.clamp(1, 63);
    let chunk_sz = ((num_inline + par_workers - 1) / par_workers).max(1);
    let parent_slice = &parent;
    let all_nodes_slice = &all_nodes;
    let root_canon_slice = &root_canon;

    let part_outs: Vec<(Vec<Vec<LinkSlotB37>>, Vec<(CompactKey64, CompactKey64)>)> = (0..par_workers)
        .into_par_iter()
        .map(|w| {
            let lo = (w * chunk_sz).min(num_inline);
            let hi = ((w + 1) * chunk_sz).min(num_inline);
            let mut b37_segs: Vec<Vec<LinkSlotB37>> =
                (0..LINK_SHARDS).map(|_| Vec::new()).collect();
            let mut others: Vec<(CompactKey64, CompactKey64)> = Vec::new();
            for i in lo..hi {
                let r = parent_slice[i].load(Ordering::Relaxed) as usize;
                if r == i {
                    continue;
                }
                let k = all_nodes_slice[i];
                let canon = root_canon_slice[r];
                if k.is_ub37() {
                    let h42 = biject42(k.ub37_val());
                    let s = (h42 >> 37) as usize;
                    let rem37 = h42 & REM37_MASK;
                    b37_segs[s].push(LinkSlotB37 {
                        key_p1: rem37 + 1,
                        canon,
                    });
                } else {
                    others.push((k, canon));
                }
            }
            (b37_segs, others)
        })
        .collect();
    drop(parent);
    drop(root_canon);
    drop(all_nodes);

    let mut shard_b37_inputs: Vec<Vec<Vec<LinkSlotB37>>> = (0..LINK_SHARDS)
        .map(|_| Vec::with_capacity(par_workers))
        .collect();
    let mut other_map: HashMap<CompactKey64, CompactKey64> = HashMap::new();
    let mut b37_total = 0usize;
    for (w_segs, w_others) in part_outs {
        for (s, v) in w_segs.into_iter().enumerate() {
            if !v.is_empty() {
                b37_total += v.len();
                shard_b37_inputs[s].push(v);
            }
        }
        for (k, canon) in w_others {
            other_map.insert(k, canon);
        }
    }
    let has_other = !other_map.is_empty();

    if b37_total == 0 {
        return Ok(LinkMap {
            bloom: HugeBuf::default(),
            bloom_shift: 0,
            bloom_sub_mask: 0,
            slots_b37: HugeBuf::default(),
            seg_cap: 0,
            other_map,
            has_other,
            long_map,
            has_long,
            canon_arena,
            canon_spans,
            empty: false,
        });
    }

    let max_m = shard_b37_inputs
        .iter()
        .map(|batches| batches.iter().map(Vec::len).sum::<usize>())
        .max()
        .unwrap_or(0);
    // 70% load factor for compact L3 footprint with short linear probe chains.
    let seg_cap = ((max_m * 10 + 6) / 7).max(max_m + 1).max(2);
    let mut slots_b37 = HugeBuf::<LinkSlotB37>::new_zeroed(LINK_SHARDS * seg_cap);

    let total_words = (b37_total / 4)
        .max(64)
        .next_power_of_two()
        .min(524_288);
    let words_per_shard = (total_words / LINK_SHARDS).max(2);
    let bloom_shift = words_per_shard.trailing_zeros();
    let bloom_sub_mask = words_per_shard - 1;
    let mut bloom = HugeBuf::<u64>::new_zeroed(LINK_SHARDS * words_per_shard);
    slots_b37
        .par_chunks_mut(seg_cap)
        .zip(bloom.par_chunks_mut(words_per_shard))
        .zip(shard_b37_inputs.into_par_iter())
        .for_each(|((seg_slots, bloom_slice), batches)| {
            for batch in batches {
                for entry in batch {
                    let rem37 = entry.key_p1 - 1;
                    let widx = ((rem37 >> 23) as usize) & bloom_sub_mask;
                    bloom_slice[widx] |= bloom_bits(rem37);
                    let mut pos = fast_range32(rem37, seg_cap);
                    while seg_slots[pos].key_p1 != 0 {
                        pos += 1;
                        if pos == seg_cap {
                            pos = 0;
                        }
                    }
                    seg_slots[pos] = entry;
                }
            }
        });

    Ok(LinkMap {
        bloom,
        bloom_shift,
        bloom_sub_mask,
        slots_b37,
        seg_cap,
        other_map,
        has_other,
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
    use crate::csv::{decode_b37, encode_b37_padded, inv_biject42};
    use std::fs;

    fn resolve_canon_for_test<'a>(
        lm: &'a LinkMap,
        k: CompactKey64,
        scratch: &'a mut [u8; 10],
    ) -> &'a [u8] {
        if k.is_uh42() {
            let len = decode_b37(inv_biject42(k.uh42_val()), b'u', scratch);
            &scratch[..len]
        } else if k.is_comp() {
            lm.resolve_long_canon_bytes(k.comp_id())
        } else {
            let len = k.decode_inline(scratch);
            &scratch[..len]
        }
    }

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
        let mut scratch = [0u8; 10];

        let k500 = CompactKey64::encode_raw_inline(b"id_500").unwrap();
        let kroot = CompactKey64::encode_raw_inline(b"!root").unwrap();
        let c500 = lm.resolve_other_inline(k500).unwrap();
        assert_eq!(c500, kroot);
        // Roots themselves are omitted from other_map
        assert_eq!(lm.resolve_other_inline(kroot), None);
        assert_eq!(resolve_canon_for_test(&lm, c500, &mut scratch), b"!root");

        // Self-link u1,u1 changes nothing
        let mut pbuf = *b"u1\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let h_u1 = biject42(encode_b37_padded(&pbuf, 0, 2, b'u').unwrap());
        assert_eq!(lm.probe_b37(h_u1), None);
        pbuf[1] = b'9';
        pbuf[2] = b'9';

        // Long root component: !chain_min resolved from chain_00000, !chain_min, and u99
        let c_chain = lm.resolve_long(b"chain_00000").unwrap();
        let c_min = lm.resolve_long(b"!chain_min").unwrap();
        assert_eq!(c_chain, c_min);
        assert!(c_chain.is_comp());
        assert_eq!(
            resolve_canon_for_test(&lm, c_chain, &mut scratch),
            b"!chain_min"
        );
        let h_u99 = biject42(encode_b37_padded(&pbuf, 0, 3, b'u').unwrap());
        assert!(lm.bloom_may_contain_b37(h_u99));
        assert_eq!(lm.probe_b37(h_u99), Some(c_chain));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_dsu_fast_path_b37_and_drop() {
        let dir = std::env::temp_dir().join("ss_test_links_fast_v6");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut content = String::from("user_id_a,user_id_b\n");
        for i in 0..300 {
            content.push_str(&format!("u{i:04},u{:04}\n", i + 1));
        }
        content.push_str("u0150,u0000\n");
        content.push_str("zzz_long_alias_12345,u0200\n");
        content.push_str("zzz_long_root_12345,u8888\n");
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let mut lm = build_link_map(&[p], 4).unwrap();
        assert!(!lm.is_empty());
        let h_0000 = biject42(encode_b37_padded(b"u0000\0\0\0\0\0\0\0\0\0\0\0", 0, 5, b'u').unwrap());
        let h_300 = biject42(encode_b37_padded(b"u0300\0\0\0\0\0\0\0\0\0\0\0", 0, 5, b'u').unwrap());
        lm.prefetch_bloom_b37(h_300);
        assert!(lm.bloom_may_contain_b37(h_300));
        lm.prefetch_slot_b37(h_300);
        let c300 = lm.probe_b37(h_300).unwrap();
        let mut scratch = [0u8; 10];
        assert_eq!(resolve_canon_for_test(&lm, c300, &mut scratch), b"u0000");
        assert_eq!(c300, CompactKey64::from_uh42(h_0000));
        // Root u0000 is omitted from slots_b37
        assert_eq!(lm.probe_b37(h_0000), None);
        assert_eq!(lm.resolve_long(b"zzz_long_alias_12345"), Some(c300));
        // Long root mapped in long_map too
        let c_long_root = lm.resolve_long(b"zzz_long_root_12345").unwrap();
        assert_eq!(
            resolve_canon_for_test(&lm, c_long_root, &mut scratch),
            b"u8888"
        );

        let h_miss = biject42(encode_b37_padded(b"unseen99\0\0\0\0\0\0\0\0", 0, 8, b'u').unwrap());
        assert_eq!(lm.probe_b37(h_miss), None);

        lm.drop_lookup_tables();
        assert!(lm.is_empty());
        assert!(!lm.bloom_may_contain_b37(h_300));
        assert_eq!(lm.probe_b37(h_300), None);
        assert_eq!(resolve_canon_for_test(&lm, c300, &mut scratch), b"u0000");

        let _ = fs::remove_dir_all(&dir);
    }
}
