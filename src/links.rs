use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

use hashbrown::HashMap;

use crate::csv::{
    biject42, cmp_raw_keys, decode_hex32, encode_b37_padded, encode_b37_pair_padded,
    encode_hex32_padded, field_span, hash_hex128, mix64, resolve_raw_key, CompactKey64,
    CsvSource, Hex128, LongArena,
};
use crate::slab::{HugeBuf, Zeroable};

const LINK_CHUNK_BYTES: usize = 512 * 1024;
const LINK_SHARDS: usize = 32;
const LINK_B37_SHARDS: usize = 64;
const BUILD_TAG_MASK: u32 = 0xFFF0_0000;
const BUILD_IDX_MASK: u32 = 0x000F_FFFF;
const REM36_MASK: u64 = (1u64 << 36) - 1;
const GROUP_LANES: usize = 6;

#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct LinkGroup64 {
    keys: [u32; GROUP_LANES],    // 24B: (rem36 & 0x7FFF_FFFF) as u32 + 1 (0 = empty)
    vals_lo: [u32; GROUP_LANES], // 24B: canon low 32 bits (uh42 low32 or comp_id)
    vals_hi: [u16; GROUP_LANES], // 12B: bits 11..15 = top5 (rem36 >> 31), bit 10 = is_comp, bits 0..9 = uh42 bits 32..41
    ovf: u32,                    //  4B: non-zero when probing must continue to next group
}

const _: () = assert!(std::mem::size_of::<LinkGroup64>() == 64);
const _: () = assert!(std::mem::align_of::<LinkGroup64>() == 64);
unsafe impl Zeroable for LinkGroup64 {}

#[inline(always)]
fn encode_b37_canon(canon: CompactKey64) -> (u32, u16) {
    if canon.is_comp() {
        (canon.comp_id(), 1u16 << 10)
    } else {
        debug_assert!(canon.is_uh42());
        let h42 = canon.uh42_val();
        (h42 as u32, (h42 >> 32) as u16)
    }
}

#[inline(always)]
fn decode_b37_canon(v_lo: u32, vh: u16) -> CompactKey64 {
    if (vh & (1 << 10)) != 0 {
        CompactKey64::from_comp(v_lo)
    } else {
        CompactKey64::from_uh42((((vh & 0x3FF) as u64) << 32) | (v_lo as u64))
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct LinkSlotHex {
    hi: u64,
    lo: u64,
    canon: CompactKey64, // EMPTY (0) = empty slot
}

const _: () = assert!(std::mem::size_of::<LinkSlotHex>() == 24);
unsafe impl Zeroable for LinkSlotHex {}

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
fn bloom_hex_bits(h64: u64) -> u64 {
    (1u64 << (h64 & 63))
        | (1u64 << ((h64 >> 6) & 63))
        | (1u64 << ((h64 >> 12) & 63))
        | (1u64 << ((h64 >> 18) & 63))
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
    groups_b37: HugeBuf<LinkGroup64>,
    seg_groups: usize,
    bloom_hex: HugeBuf<u64>,
    bloom_hex_shift: u32,
    bloom_hex_sub_mask: usize,
    slots_hex: HugeBuf<LinkSlotHex>,
    hex_seg_cap: usize,
    other_map: HashMap<CompactKey64, CompactKey64>,
    has_other: bool,
    long_map: HashMap<Box<[u8]>, CompactKey64>,
    has_long: bool,
    canon_hex: Vec<Hex128>,
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
            groups_b37: HugeBuf::default(),
            seg_groups: 0,
            bloom_hex: HugeBuf::default(),
            bloom_hex_shift: 0,
            bloom_hex_sub_mask: 0,
            slots_hex: HugeBuf::default(),
            hex_seg_cap: 0,
            other_map: HashMap::new(),
            has_other: false,
            long_map: HashMap::new(),
            has_long: false,
            canon_hex: Vec::new(),
            canon_arena: Vec::new(),
            canon_spans: Vec::new(),
            empty: true,
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.empty
    }

    pub fn debug_stats(&self) -> (usize, usize, usize, usize) {
        (
            self.bloom.len() * std::mem::size_of::<u64>(),
            self.groups_b37.len() * std::mem::size_of::<LinkGroup64>(),
            self.bloom_hex.len() * std::mem::size_of::<u64>(),
            self.slots_hex.len() * std::mem::size_of::<LinkSlotHex>(),
        )
    }

    #[inline(always)]
    fn bloom_idx(&self, h42: u64) -> usize {
        let s = (h42 >> 36) as usize;
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
    pub fn prefetch_slot_b37_idx(&self, h42: u64) -> u32 {
        if self.empty || self.seg_groups == 0 {
            return 0;
        }
        let s = (h42 >> 36) as usize;
        let rem36 = h42 & REM36_MASK;
        let g = fast_range32(rem36, self.seg_groups);
        let idx = s * self.seg_groups + g;
        #[cfg(target_arch = "x86_64")]
        unsafe {
            std::arch::x86_64::_mm_prefetch(
                self.groups_b37.as_ptr().add(idx) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
        idx as u32
    }

    #[inline(always)]
    pub fn probe_b37_at(&self, h42: u64, grp_idx: u32) -> Option<CompactKey64> {
        if self.empty || self.seg_groups == 0 {
            return None;
        }
        let k31_p1 = ((h42 & 0x7FFF_FFFF) as u32) + 1;
        let top5 = ((h42 >> 31) & 0x1F) as u16;
        let mut cur = grp_idx as usize;
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        unsafe {
            use std::arch::x86_64::*;
            debug_assert_eq!((self.groups_b37.as_ptr() as usize) & 63, 0);
            let target = _mm256_set1_epi32(k31_p1 as i32);
            loop {
                let grp = &*self.groups_b37.as_ptr().add(cur);
                let v = _mm256_load_si256(grp.keys.as_ptr() as *const __m256i);
                let eq = _mm256_cmpeq_epi32(v, target);
                let mut m = (_mm256_movemask_ps(_mm256_castsi256_ps(eq)) as u32) & 0x3F;
                while m != 0 {
                    let lane = m.trailing_zeros() as usize;
                    let vh = *grp.vals_hi.get_unchecked(lane);
                    if (vh >> 11) == top5 {
                        return Some(decode_b37_canon(*grp.vals_lo.get_unchecked(lane), vh));
                    }
                    m &= m - 1;
                }
                if grp.ovf == 0 {
                    return None;
                }
                let seg_groups = self.seg_groups;
                let base = ((h42 >> 36) as usize) * seg_groups;
                let end = base + seg_groups;
                cur += 1;
                if cur == end {
                    cur = base;
                }
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
        loop {
            let grp = unsafe { &*self.groups_b37.as_ptr().add(cur) };
            for lane in 0..GROUP_LANES {
                let k = grp.keys[lane];
                if k == 0 {
                    return None;
                }
                if k == k31_p1 && (grp.vals_hi[lane] >> 11) == top5 {
                    return Some(decode_b37_canon(grp.vals_lo[lane], grp.vals_hi[lane]));
                }
            }
            if grp.ovf == 0 {
                return None;
            }
            let seg_groups = self.seg_groups;
            let base = ((h42 >> 36) as usize) * seg_groups;
            let end = base + seg_groups;
            cur += 1;
            if cur == end {
                cur = base;
            }
        }
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn prefetch_slot_b37(&self, h42: u64) {
        let _ = self.prefetch_slot_b37_idx(h42);
    }

    #[cfg_attr(not(test), allow(dead_code))]
    #[inline(always)]
    pub fn probe_b37(&self, h42: u64) -> Option<CompactKey64> {
        if self.empty || self.seg_groups == 0 {
            return None;
        }
        let s = (h42 >> 36) as usize;
        let rem36 = h42 & REM36_MASK;
        let g = fast_range32(rem36, self.seg_groups);
        self.probe_b37_at(h42, (s * self.seg_groups + g) as u32)
    }

    #[inline(always)]
    fn bloom_hex_idx(&self, h64: u64) -> usize {
        let s = (h64 >> 59) as usize;
        (s << self.bloom_hex_shift) | (((h64 >> 32) as usize) & self.bloom_hex_sub_mask)
    }

    #[inline(always)]
    pub fn prefetch_bloom_hex(&self, h64: u64) {
        if self.bloom_hex.is_empty() {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let bidx = self.bloom_hex_idx(h64);
            std::arch::x86_64::_mm_prefetch(
                self.bloom_hex.as_ptr().add(bidx) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn bloom_may_contain_hex(&self, h64: u64) -> bool {
        if self.bloom_hex.is_empty() {
            return false;
        }
        let bidx = self.bloom_hex_idx(h64);
        let w = unsafe { *self.bloom_hex.get_unchecked(bidx) };
        let need = bloom_hex_bits(h64);
        (w & need) == need
    }

    #[inline(always)]
    pub fn prefetch_slot_hex(&self, h64: u64) {
        if self.empty || self.hex_seg_cap == 0 {
            return;
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            let s = (h64 >> 59) as usize;
            let pos = fast_range32(h64, self.hex_seg_cap);
            std::arch::x86_64::_mm_prefetch(
                self.slots_hex.as_ptr().add(s * self.hex_seg_cap + pos) as *const i8,
                std::arch::x86_64::_MM_HINT_T0,
            );
        }
    }

    #[inline(always)]
    pub fn probe_hex(&self, h64: u64, hex: Hex128) -> Option<CompactKey64> {
        if self.empty || self.hex_seg_cap == 0 {
            return None;
        }
        let s = (h64 >> 59) as usize;
        let seg_cap = self.hex_seg_cap;
        let base = s * seg_cap;
        let mut slot = fast_range32(h64, seg_cap);
        loop {
            let cur = unsafe { *self.slots_hex.get_unchecked(base + slot) };
            if cur.canon.0 == 0 {
                return None;
            }
            if cur.hi == hex.hi && cur.lo == hex.lo {
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
    pub fn resolve_comp_bytes<'a>(&'a self, comp_id: u32, scratch: &'a mut [u8; 40]) -> &'a [u8] {
        let cid = comp_id as usize;
        if cid < self.canon_hex.len() {
            let hx = unsafe { *self.canon_hex.get_unchecked(cid) };
            let len = decode_hex32(hx, b'u', scratch);
            &scratch[..len]
        } else {
            let span_idx = cid - self.canon_hex.len();
            let (off, len) = unsafe { *self.canon_spans.get_unchecked(span_idx) };
            unsafe {
                self.canon_arena
                    .get_unchecked(off as usize..off as usize + len as usize)
            }
        }
    }

    pub fn drop_lookup_tables(&mut self) {
        self.bloom = HugeBuf::default();
        self.groups_b37 = HugeBuf::default();
        self.seg_groups = 0;
        self.bloom_hex = HugeBuf::default();
        self.slots_hex = HugeBuf::default();
        self.hex_seg_cap = 0;
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
    kind: u8, // 0 = inline/ub37, 1 = hex32, 2 = long ref
    slot: u32,
}

impl NodeProbe {
    const EMPTY: Self = Self {
        key: 0,
        tag12: 0,
        shard: 0,
        kind: 2,
        slot: 0,
    };
}

#[inline(always)]
fn encode_link_endpoint(
    padded: &[u8],
    start: usize,
    len: usize,
    wid: usize,
    arena_out: &mut LongArena,
    hex_out: &mut Vec<Hex128>,
) -> (CompactKey64, Option<Hex128>) {
    if let Some(vb37) = encode_b37_padded(padded, start, len, b'u') {
        return (CompactKey64::from_ub37(vb37), None);
    }
    if let Some(hx) = encode_hex32_padded(padded, start, len, b'u') {
        let h64 = hash_hex128(hx);
        let idx = hex_out.len();
        hex_out.push(hx);
        return (
            CompactKey64::from_hex(wid, idx, false, (h64 & 0xF_FFFF) as u32),
            Some(hx),
        );
    }
    if let Some(uk) = CompactKey64::encode_raw_inline_padded(padded, start, len) {
        return (uk, None);
    }
    let slice = unsafe { padded.get_unchecked(start..start + len) };
    (arena_out.push_ref(wid, slice), None)
}

#[inline(always)]
fn prep_node_probe(
    k: CompactKey64,
    build_shards: &[(Vec<u32>, usize)],
    worker_hex: &[Vec<Hex128>],
) -> NodeProbe {
    if !k.is_ref() {
        let (h, kind) = if k.is_hex() {
            (hash_hex128(k.resolve_hex(worker_hex)), 1u8)
        } else {
            (mix64(k.0), 0u8)
        };
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
            kind,
            slot: slot as u32,
        }
    } else {
        NodeProbe {
            key: k.0,
            tag12: 0,
            shard: 0,
            kind: 2,
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
    worker_hex: &[Vec<Hex128>],
    long_build_map: &HashMap<Box<[u8]>, u32>,
) -> u32 {
    if p.kind == 0 {
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
    } else if p.kind == 1 {
        let hx = CompactKey64(p.key).resolve_hex(worker_hex);
        let s = p.shard as usize;
        let (ref slots, mask) = unsafe { build_shards.get_unchecked(s) };
        let base = unsafe { *offsets.get_unchecked(s) };
        let mut slot = p.slot as usize;
        loop {
            let cur = unsafe { *slots.get_unchecked(slot) };
            if (cur & BUILD_TAG_MASK) == p.tag12 {
                let local_idx = ((cur & BUILD_IDX_MASK) as usize).wrapping_sub(1);
                let gid = base + local_idx;
                let nk = unsafe { *all_nodes.get_unchecked(gid) };
                if nk.is_hex() && nk.resolve_hex(worker_hex) == hx {
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
    let chunks = src.chunks(LINK_CHUNK_BYTES);
    if chunks.is_empty() {
        return Ok(LinkMap::empty());
    }

    let n_threads = ncpu.clamp(1, 63);

    // Stage L1: parallel CsvSource parse into per-worker edge lists and sharded inline/hex32 endpoints.
    let next_chunk = AtomicUsize::new(0);
    let nworkers = n_threads.min(chunks.len());
    let est_edges = (src.total_bytes() / (18 * nworkers.max(1))).max(256);
    let mut worker_edges: Vec<Vec<(CompactKey64, CompactKey64)>> =
        (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_inline_buckets: Vec<Vec<Vec<CompactKey64>>> = (0..nworkers)
        .map(|_| (0..LINK_SHARDS).map(|_| Vec::new()).collect())
        .collect();
    let mut worker_long_endpoints: Vec<Vec<CompactKey64>> =
        (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_arenas: Vec<LongArena> = (0..nworkers).map(|_| LongArena::default()).collect();
    let mut worker_hex: Vec<Vec<Hex128>> = (0..nworkers).map(|_| Vec::new()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..nworkers).map(|_| None).collect();

    let run_l1_worker = |wid: usize,
                         edges_out: &mut Vec<(CompactKey64, CompactKey64)>,
                         buckets_out: &mut Vec<Vec<CompactKey64>>,
                         long_out: &mut Vec<CompactKey64>,
                         arena_out: &mut LongArena,
                         hex_out: &mut Vec<Hex128>,
                         err_out: &mut Option<io::Error>| {
        let mut buf = Vec::new();
        edges_out.reserve(est_edges);
        loop {
            let cidx = next_chunk.fetch_add(1, Ordering::Relaxed);
            let Some(&task) = chunks.get(cidx) else {
                break;
            };
            if let Err(e) =
                src.for_each_chunk_direct_batched::<2>(task, &mut buf, |padded, cm_buf, lines| {
                    let base = padded.as_ptr();
                    let cm_ptr = cm_buf.as_ptr();
                    for dl in lines {
                        let ls = dl.ls as usize;
                        let c0 = unsafe { *cm_ptr.add(dl.cm_off as usize) } as usize;
                        let le = dl.le as usize;
                    let (a_s, a_e) = unsafe { field_span(base, ls, c0) };
                    let (b_s, b_e) = unsafe { field_span(base, c0 + 1, le) };
                    let a_len = a_e - a_s;
                    let b_len = b_e - b_s;
                    if a_len == 0 || b_len == 0 {
                        continue;
                    }
                    if let Some((va, vb)) =
                        encode_b37_pair_padded(padded, a_s, a_len, b'u', b_s, b_len, b'u')
                    {
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
                    let (ka, hxa) =
                        encode_link_endpoint(padded, a_s, a_len, wid, arena_out, hex_out);
                    let (kb, hxb) =
                        encode_link_endpoint(padded, b_s, b_len, wid, arena_out, hex_out);
                    edges_out.push((ka, kb));
                    if let Some(hx) = hxa {
                        let s = ((hash_hex128(hx) >> 52) as usize) & (LINK_SHARDS - 1);
                        buckets_out[s].push(ka);
                    } else if !ka.is_ref() {
                        let s = ((mix64(ka.0) >> 52) as usize) & (LINK_SHARDS - 1);
                        buckets_out[s].push(ka);
                    } else {
                        long_out.push(ka);
                    }
                    if let Some(hx) = hxb {
                        let s = ((hash_hex128(hx) >> 52) as usize) & (LINK_SHARDS - 1);
                        buckets_out[s].push(kb);
                    } else if !kb.is_ref() {
                        let s = ((mix64(kb.0) >> 52) as usize) & (LINK_SHARDS - 1);
                        buckets_out[s].push(kb);
                    } else {
                        long_out.push(kb);
                    }
                }
            }) {
                *err_out = Some(e);
                break;
            }
        }
    };

    if nworkers <= 1 {
        run_l1_worker(
            0,
            &mut worker_edges[0],
            &mut worker_inline_buckets[0],
            &mut worker_long_endpoints[0],
            &mut worker_arenas[0],
            &mut worker_hex[0],
            &mut worker_errs[0],
        );
    } else {
        std::thread::scope(|scope| {
            for (
                wid,
                (((((edges_out, buckets_out), long_out), arena_out), hex_out), err_out),
            ) in worker_edges
                .iter_mut()
                .zip(worker_inline_buckets.iter_mut())
                .zip(worker_long_endpoints.iter_mut())
                .zip(worker_arenas.iter_mut())
                .zip(worker_hex.iter_mut())
                .zip(worker_errs.iter_mut())
                .enumerate()
            {
                let runner = &run_l1_worker;
                scope.spawn(move || {
                    runner(
                        wid,
                        edges_out,
                        buckets_out,
                        long_out,
                        arena_out,
                        hex_out,
                        err_out,
                    );
                });
            }
        });
    }

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
    let intern_shard = |batches: Vec<Vec<CompactKey64>>, w_hex: &[Vec<Hex128>]| {
        let total: usize = batches.iter().map(Vec::len).sum();
        let mut cap = ((total * 3 / 2).max(16)).next_power_of_two();
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
                            let nk = nodes[idx];
                            let h = if nk.is_hex() {
                                hash_hex128(nk.resolve_hex(w_hex))
                            } else {
                                mix64(nk.0)
                            };
                            let mut p = (h as usize) & new_mask;
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
                let is_h = k.is_hex();
                let k_hex = if is_h {
                    k.resolve_hex(w_hex)
                } else {
                    Hex128::default()
                };
                let h = if is_h { hash_hex128(k_hex) } else { mix64(k.0) };
                let tag12 = link_tag12(h);
                let mut slot = (h as usize) & mask;
                loop {
                    let cur = unsafe { *slots.get_unchecked(slot) };
                    if cur == 0 {
                        assert!(nodes.len() < BUILD_IDX_MASK as usize, "link shard overflow");
                        let idx1 = (nodes.len() + 1) as u32;
                        nodes.push(k);
                        unsafe {
                            *slots.get_unchecked_mut(slot) = tag12 | idx1;
                        }
                        break;
                    }
                    if (cur & BUILD_TAG_MASK) == tag12 {
                        let idx = ((cur & BUILD_IDX_MASK) - 1) as usize;
                        let existing = unsafe { *nodes.get_unchecked(idx) };
                        let same = if existing.0 == k.0 {
                            true
                        } else if is_h && existing.is_hex() {
                            existing.resolve_hex(w_hex) == k_hex
                        } else {
                            false
                        };
                        if same {
                            break;
                        }
                    }
                    slot = (slot + 1) & mask;
                }
            }
        }
        (slots, mask, nodes)
    };

    let mut offsets = [0usize; LINK_SHARDS + 1];
    let mut num_inline = 0usize;
    let mut build_shards = Vec::with_capacity(LINK_SHARDS);
    let mut shard_nodes_list = Vec::with_capacity(LINK_SHARDS);

    if n_threads == 1 {
        for batches in shard_inputs {
            let (slots, mask, nodes) = intern_shard(batches, &worker_hex);
            offsets[build_shards.len()] = num_inline;
            num_inline += nodes.len();
            build_shards.push((slots, mask));
            shard_nodes_list.push(nodes);
        }
    } else {
        let in_slots: Vec<Mutex<Option<Vec<Vec<CompactKey64>>>>> = shard_inputs
            .into_iter()
            .map(|v| Mutex::new(Some(v)))
            .collect();
        let out_slots: Vec<Mutex<Option<(Vec<u32>, usize, Vec<CompactKey64>)>>> = (0..LINK_SHARDS)
            .map(|_| Mutex::new(None))
            .collect();
        let next_s = AtomicUsize::new(0);
        let l2_workers = n_threads.min(LINK_SHARDS);
        let worker_hex_ref = &worker_hex;
        std::thread::scope(|scope| {
            for _ in 0..l2_workers {
                let in_ref = &in_slots;
                let out_ref = &out_slots;
                let next_ref = &next_s;
                scope.spawn(move || loop {
                    let s = next_ref.fetch_add(1, Ordering::Relaxed);
                    if s >= LINK_SHARDS {
                        break;
                    }
                    let batches = in_ref[s].lock().unwrap().take().unwrap();
                    let res = intern_shard(batches, worker_hex_ref);
                    *out_ref[s].lock().unwrap() = Some(res);
                });
            }
        });
        for (s, m) in out_slots.into_iter().enumerate() {
            let (slots, mask, nodes) = m.into_inner().unwrap().unwrap();
            offsets[s] = num_inline;
            num_inline += nodes.len();
            build_shards.push((slots, mask));
            shard_nodes_list.push(nodes);
        }
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

    let mut parent: Vec<AtomicU32> = Vec::with_capacity(num_nodes);
    if n_threads == 1 || num_nodes < 262_144 {
        for i in 0..num_nodes {
            parent.push(AtomicU32::new(i as u32));
        }
    } else {
        let spare = parent.spare_capacity_mut();
        let chunk_sz = ((num_nodes + n_threads - 1) / n_threads).max(1);
        std::thread::scope(|scope| {
            for (w, ch) in spare.chunks_mut(chunk_sz).enumerate() {
                let base = w * chunk_sz;
                scope.spawn(move || {
                    for (j, slot) in ch.iter_mut().enumerate() {
                        slot.write(AtomicU32::new((base + j) as u32));
                    }
                });
            }
        });
        unsafe {
            parent.set_len(num_nodes);
        }
    }

    // Stage L3+L4 fused: prefetched ring-buffer lookup + parallel lock-free DSU union.
    let run_dsu_edges = |edges: Vec<(CompactKey64, CompactKey64)>,
                         parent_ref: &[AtomicU32],
                         all_nodes_ref: &[CompactKey64],
                         build_shards_ref: &[(Vec<u32>, usize)],
                         offsets_ref: &[usize; LINK_SHARDS + 1],
                         arenas_ref: &[LongArena],
                         hex_ref: &[Vec<Hex128>],
                         long_map_ref: &HashMap<Box<[u8]>, u32>| {
        const RING: usize = 16;
        let len = edges.len();
        let mut ring = [(NodeProbe::EMPTY, NodeProbe::EMPTY); RING];
        let pre = len.min(RING);
        for i in 0..pre {
            let (ka, kb) = edges[i];
            ring[i] = (
                prep_node_probe(ka, build_shards_ref, hex_ref),
                prep_node_probe(kb, build_shards_ref, hex_ref),
            );
        }
        for idx in 0..len {
            let (pa, pb) = ring[idx & (RING - 1)];
            if idx + RING < len {
                let (ka, kb) = unsafe { *edges.get_unchecked(idx + RING) };
                ring[idx & (RING - 1)] = (
                    prep_node_probe(ka, build_shards_ref, hex_ref),
                    prep_node_probe(kb, build_shards_ref, hex_ref),
                );
            }
            let u0 = resolve_node_probe(
                pa,
                build_shards_ref,
                offsets_ref,
                all_nodes_ref,
                arenas_ref,
                hex_ref,
                long_map_ref,
            );
            let v0 = resolve_node_probe(
                pb,
                build_shards_ref,
                offsets_ref,
                all_nodes_ref,
                arenas_ref,
                hex_ref,
                long_map_ref,
            );
            loop {
                let u = atomic_find(parent_ref, u0);
                let v = atomic_find(parent_ref, v0);
                if u == v {
                    break;
                }
                let ord = cmp_raw_keys(
                    all_nodes_ref[u as usize],
                    all_nodes_ref[v as usize],
                    arenas_ref,
                    hex_ref,
                    arenas_ref,
                    hex_ref,
                );
                let (lo, hi) = if ord == std::cmp::Ordering::Less {
                    (u, v)
                } else {
                    (v, u)
                };
                if parent_ref[hi as usize]
                    .compare_exchange_weak(hi, lo, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break;
                }
            }
        }
    };

    if nworkers <= 1 {
        for edges in worker_edges {
            run_dsu_edges(
                edges,
                &parent,
                &all_nodes,
                &build_shards,
                &offsets,
                &worker_arenas,
                &worker_hex,
                &long_build_map,
            );
        }
    } else {
        std::thread::scope(|scope| {
            let parent_ref = &parent;
            let all_nodes_ref = &all_nodes;
            let build_shards_ref = &build_shards;
            let offsets_ref = &offsets;
            let arenas_ref = &worker_arenas;
            let hex_ref = &worker_hex;
            let long_map_ref = &long_build_map;
            let runner = &run_dsu_edges;
            for edges in worker_edges {
                scope.spawn(move || {
                    runner(
                        edges,
                        parent_ref,
                        all_nodes_ref,
                        build_shards_ref,
                        offsets_ref,
                        arenas_ref,
                        hex_ref,
                        long_map_ref,
                    );
                });
            }
        });
    }

    drop(build_shards);
    drop(long_build_map);

    // Flatten parent in place + build canonical CompactKey64 per inline root in one parallel pass.
    let mut root_canon = vec![CompactKey64::EMPTY; num_nodes];
    let mut canon_hex: Vec<Hex128> = Vec::new();
    let mut canon_arena: Vec<u8> = Vec::new();
    let mut canon_spans: Vec<(u32, u32)> = Vec::new();

    if n_threads == 1 || num_nodes < 16_384 {
        for i in 0..num_nodes {
            let p0 = parent[i].load(Ordering::Relaxed);
            if p0 as usize == i {
                if i < num_inline {
                    let r_key = all_nodes[i];
                    root_canon[i] = if r_key.is_ub37() {
                        CompactKey64::from_uh42(biject42(r_key.ub37_val()))
                    } else if r_key.is_hex() {
                        let cid = canon_hex.len() as u32;
                        canon_hex.push(r_key.resolve_hex(&worker_hex));
                        CompactKey64::from_comp(cid)
                    } else {
                        r_key
                    };
                }
                continue;
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
        }
    } else {
        let chunk_sz = ((num_nodes + n_threads - 1) / n_threads).max(1);
        let mut local_hexs: Vec<Vec<(usize, Hex128)>> = (0..n_threads).map(|_| Vec::new()).collect();
        std::thread::scope(|scope| {
            let parent_ref = &parent;
            let all_nodes_ref = &all_nodes;
            let hex_ref = &worker_hex;
            for (w, (rc_chunk, hex_out)) in root_canon
                .chunks_mut(chunk_sz)
                .zip(local_hexs.iter_mut())
                .enumerate()
            {
                let base = w * chunk_sz;
                scope.spawn(move || {
                    for (j, rc_slot) in rc_chunk.iter_mut().enumerate() {
                        let i = base + j;
                        let p0 = parent_ref[i].load(Ordering::Relaxed);
                        if p0 as usize == i {
                            if i < num_inline {
                                let r_key = unsafe { *all_nodes_ref.get_unchecked(i) };
                                if r_key.is_ub37() {
                                    *rc_slot = CompactKey64::from_uh42(biject42(r_key.ub37_val()));
                                } else if r_key.is_hex() {
                                    hex_out.push((i, r_key.resolve_hex(hex_ref)));
                                } else {
                                    *rc_slot = r_key;
                                }
                            }
                            continue;
                        }
                        let mut r = p0;
                        loop {
                            let p = parent_ref[r as usize].load(Ordering::Relaxed);
                            if p == r {
                                break;
                            }
                            r = p;
                        }
                        if r != p0 {
                            parent_ref[i].store(r, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        let hex_total: usize = local_hexs.iter().map(Vec::len).sum();
        canon_hex.reserve(hex_total);
        for v in local_hexs {
            for (i, hx) in v {
                let cid = canon_hex.len() as u32;
                canon_hex.push(hx);
                root_canon[i] = CompactKey64::from_comp(cid);
            }
        }
    }

    let mut scratch = [0u8; 40];
    for i in num_inline..num_nodes {
        if parent[i].load(Ordering::Relaxed) as usize == i {
            let r_key = all_nodes[i];
            let bytes = resolve_raw_key(r_key, &worker_arenas, &worker_hex, &mut scratch);
            let span_idx = canon_spans.len();
            let off = canon_arena.len() as u32;
            canon_arena.extend_from_slice(bytes);
            canon_spans.push((off, bytes.len() as u32));
            let cid = canon_hex.len() + span_idx;
            assert!(cid < (u32::MAX as usize), "too many canonical link components");
            root_canon[i] = CompactKey64::from_comp(cid as u32);
        }
    }

    let mut long_map: HashMap<Box<[u8]>, CompactKey64> = HashMap::new();
    for i in num_inline..num_nodes {
        let r = parent[i].load(Ordering::Relaxed) as usize;
        let canon = root_canon[r];
        let bytes = LongArena::resolve_in(&worker_arenas, all_nodes[i]);
        long_map.insert(bytes.to_vec().into_boxed_slice(), canon);
    }
    let has_long = !long_map.is_empty();
    drop(worker_arenas);

    // Stage L5: partition non-root b37 (64 shards)/other inline nodes AND all linked HexRef nodes (32 shards).
    let par_workers = if num_inline < 16_384 { 1 } else { n_threads };
    let chunk_sz = ((num_inline + par_workers - 1) / par_workers).max(1);
    let partition_range = |lo: usize,
                           hi: usize|
     -> (
        Vec<Vec<(u64, CompactKey64)>>,
        Vec<Vec<LinkSlotHex>>,
        Vec<(CompactKey64, CompactKey64)>,
    ) {
        let mut b37_segs: Vec<Vec<(u64, CompactKey64)>> =
            (0..LINK_B37_SHARDS).map(|_| Vec::new()).collect();
        let mut hex_segs: Vec<Vec<LinkSlotHex>> =
            (0..LINK_SHARDS).map(|_| Vec::new()).collect();
        let mut others: Vec<(CompactKey64, CompactKey64)> = Vec::new();
        for i in lo..hi {
            let r = parent[i].load(Ordering::Relaxed) as usize;
            let k = unsafe { *all_nodes.get_unchecked(i) };
            let canon = unsafe { *root_canon.get_unchecked(r) };
            if k.is_hex() {
                let hx = k.resolve_hex(&worker_hex);
                let h64 = hash_hex128(hx);
                let s = (h64 >> 59) as usize;
                hex_segs[s].push(LinkSlotHex {
                    hi: hx.hi,
                    lo: hx.lo,
                    canon,
                });
                continue;
            }
            if r == i {
                continue;
            }
            if k.is_ub37() {
                let h42 = biject42(k.ub37_val());
                let s = (h42 >> 36) as usize;
                let rem36 = h42 & REM36_MASK;
                b37_segs[s].push((rem36, canon));
            } else {
                others.push((k, canon));
            }
        }
        (b37_segs, hex_segs, others)
    };

    let part_outs = if par_workers <= 1 {
        vec![partition_range(0, num_inline)]
    } else {
        let mut outs: Vec<
            Option<(
                Vec<Vec<(u64, CompactKey64)>>,
                Vec<Vec<LinkSlotHex>>,
                Vec<(CompactKey64, CompactKey64)>,
            )>,
        > = (0..par_workers).map(|_| None).collect();
        std::thread::scope(|scope| {
            let pr = &partition_range;
            for (w, out) in outs.iter_mut().enumerate() {
                let lo = (w * chunk_sz).min(num_inline);
                let hi = ((w + 1) * chunk_sz).min(num_inline);
                scope.spawn(move || {
                    *out = Some(pr(lo, hi));
                });
            }
        });
        outs.into_iter().map(Option::unwrap).collect()
    };

    drop(parent);
    drop(root_canon);
    drop(all_nodes);
    drop(worker_hex);

    let mut shard_b37_inputs: Vec<Vec<Vec<(u64, CompactKey64)>>> = (0..LINK_B37_SHARDS)
        .map(|_| Vec::with_capacity(par_workers))
        .collect();
    let mut shard_hex_inputs: Vec<Vec<Vec<LinkSlotHex>>> = (0..LINK_SHARDS)
        .map(|_| Vec::with_capacity(par_workers))
        .collect();
    let mut other_map: HashMap<CompactKey64, CompactKey64> = HashMap::new();
    let mut inline_root_remap: HashMap<u64, CompactKey64> = HashMap::new();
    let mut b37_total = 0usize;
    let mut hex_total = 0usize;
    for (mut w_b37, w_hex, w_others) in part_outs {
        for (s, v) in w_b37.iter_mut().enumerate() {
            if !v.is_empty() {
                for &mut (_, ref mut canon) in v.iter_mut() {
                    if !canon.is_uh42() && !canon.is_comp() {
                        *canon = *inline_root_remap.entry(canon.0).or_insert_with(|| {
                            let mut ibuf = [0u8; 10];
                            let len = canon.decode_inline(&mut ibuf);
                            let span_idx = canon_spans.len();
                            let off = canon_arena.len() as u32;
                            canon_arena.extend_from_slice(&ibuf[..len]);
                            canon_spans.push((off, len as u32));
                            let cid = canon_hex.len() + span_idx;
                            assert!(cid < (u32::MAX as usize), "too many canonical link components");
                            CompactKey64::from_comp(cid as u32)
                        });
                    }
                }
                b37_total += v.len();
                shard_b37_inputs[s].push(std::mem::take(v));
            }
        }
        for (s, v) in w_hex.into_iter().enumerate() {
            if !v.is_empty() {
                hex_total += v.len();
                shard_hex_inputs[s].push(v);
            }
        }
        for (k, canon) in w_others {
            other_map.insert(k, canon);
        }
    }
    if !inline_root_remap.is_empty() {
        for v in other_map.values_mut() {
            if let Some(&c) = inline_root_remap.get(&v.0) {
                *v = c;
            }
        }
        for (&orig_k, &comp_c) in &inline_root_remap {
            other_map.insert(CompactKey64(orig_k), comp_c);
        }
        for v in long_map.values_mut() {
            if let Some(&c) = inline_root_remap.get(&v.0) {
                *v = c;
            }
        }
        for batches in &mut shard_hex_inputs {
            for batch in batches {
                for e in batch {
                    if let Some(&c) = inline_root_remap.get(&e.canon.0) {
                        e.canon = c;
                    }
                }
            }
        }
    }
    let has_other = !other_map.is_empty();

    let (bloom, bloom_shift, bloom_sub_mask, groups_b37, seg_groups) = if b37_total == 0 {
        (HugeBuf::default(), 0, 0, HugeBuf::default(), 0)
    } else {
        let max_m = shard_b37_inputs
            .iter()
            .map(|batches| batches.iter().map(Vec::len).sum::<usize>())
            .max()
            .unwrap_or(0);
        // 74% target load across 6-lane 64B cache-line groups, guaranteeing >= 2 free lanes for termination.
        let seg_groups = ((max_m * 100 + 443) / 444).max(max_m / GROUP_LANES + 2);
        let mut groups_b37 = HugeBuf::<LinkGroup64>::new_zeroed(LINK_B37_SHARDS * seg_groups);

        let total_words = (b37_total / 7)
            .max(128)
            .next_power_of_two()
            .min(262_144);
        let words_per_shard = (total_words / LINK_B37_SHARDS).max(2);
        let bloom_shift = words_per_shard.trailing_zeros();
        let bloom_sub_mask = words_per_shard - 1;
        let mut bloom = HugeBuf::<u64>::new_zeroed(LINK_B37_SHARDS * words_per_shard);

        let fill_b37_shard = |seg_grps: &mut [LinkGroup64],
                              bloom_slice: &mut [u64],
                              batches: Vec<Vec<(u64, CompactKey64)>>| {
            for batch in batches {
                for (rem36, canon) in batch {
                    let widx = ((rem36 >> 23) as usize) & bloom_sub_mask;
                    bloom_slice[widx] |= bloom_bits(rem36);
                    let k31_p1 = ((rem36 & 0x7FFF_FFFF) as u32) + 1;
                    let top5 = (rem36 >> 31) as u16;
                    let (v_lo, v_hi_canon) = encode_b37_canon(canon);
                    let vh = (top5 << 11) | v_hi_canon;
                    let mut g = fast_range32(rem36, seg_groups);
                    'insert: loop {
                        let grp = &mut seg_grps[g];
                        for lane in 0..GROUP_LANES {
                            if grp.keys[lane] == 0 {
                                grp.keys[lane] = k31_p1;
                                grp.vals_lo[lane] = v_lo;
                                grp.vals_hi[lane] = vh;
                                break 'insert;
                            }
                        }
                        grp.ovf = 1;
                        g += 1;
                        if g == seg_groups {
                            g = 0;
                        }
                    }
                }
            }
        };

        if n_threads == 1 {
            for ((seg_grps, bloom_slice), batches) in groups_b37
                .chunks_exact_mut(seg_groups)
                .zip(bloom.chunks_exact_mut(words_per_shard))
                .zip(shard_b37_inputs.into_iter())
            {
                fill_b37_shard(seg_grps, bloom_slice, batches);
            }
        } else {
            let tasks: Vec<
                Mutex<Option<(&mut [LinkGroup64], &mut [u64], Vec<Vec<(u64, CompactKey64)>>)>>,
            > = groups_b37
                .chunks_exact_mut(seg_groups)
                .zip(bloom.chunks_exact_mut(words_per_shard))
                .zip(shard_b37_inputs.into_iter())
                .map(|((a, b), c)| Mutex::new(Some((a, b, c))))
                .collect();
            let next_s = AtomicUsize::new(0);
            let fw = n_threads.min(LINK_B37_SHARDS);
            std::thread::scope(|scope| {
                let tasks_ref = &tasks;
                let next_ref = &next_s;
                for _ in 0..fw {
                    scope.spawn(move || loop {
                        let s = next_ref.fetch_add(1, Ordering::Relaxed);
                        if s >= LINK_B37_SHARDS {
                            break;
                        }
                        let (seg_grps, bloom_slice, batches) =
                            tasks_ref[s].lock().unwrap().take().unwrap();
                        fill_b37_shard(seg_grps, bloom_slice, batches);
                    });
                }
            });
        }

        (bloom, bloom_shift, bloom_sub_mask, groups_b37, seg_groups)
    };

    let (bloom_hex, bloom_hex_shift, bloom_hex_sub_mask, slots_hex, hex_seg_cap) = if hex_total == 0
    {
        (HugeBuf::default(), 0, 0, HugeBuf::default(), 0)
    } else {
        let max_m = shard_hex_inputs
            .iter()
            .map(|batches| batches.iter().map(Vec::len).sum::<usize>())
            .max()
            .unwrap_or(0);
        let hex_seg_cap = ((max_m * 10 + 6) / 7).max(max_m + 1).max(2);
        let mut slots_hex = HugeBuf::<LinkSlotHex>::new_zeroed(LINK_SHARDS * hex_seg_cap);

        let total_hex_words = (hex_total / 5)
            .max(64)
            .next_power_of_two()
            .min(131_072);
        let words_per_shard = (total_hex_words / LINK_SHARDS).max(2);
        let bloom_hex_shift = words_per_shard.trailing_zeros();
        let bloom_hex_sub_mask = words_per_shard - 1;
        let mut bloom_hex = HugeBuf::<u64>::new_zeroed(LINK_SHARDS * words_per_shard);

        let fill_hex_shard =
            |seg_slots: &mut [LinkSlotHex], bloom_slice: &mut [u64], batches: Vec<Vec<LinkSlotHex>>| {
                for batch in batches {
                    for entry in batch {
                        let h64 = hash_hex128(Hex128 {
                            hi: entry.hi,
                            lo: entry.lo,
                        });
                        let widx = ((h64 >> 32) as usize) & bloom_hex_sub_mask;
                        bloom_slice[widx] |= bloom_hex_bits(h64);
                        let mut pos = fast_range32(h64, hex_seg_cap);
                        while seg_slots[pos].canon.0 != 0 {
                            pos += 1;
                            if pos == hex_seg_cap {
                                pos = 0;
                            }
                        }
                        seg_slots[pos] = entry;
                    }
                }
            };

        if n_threads == 1 {
            for ((seg_slots, bloom_slice), batches) in slots_hex
                .chunks_exact_mut(hex_seg_cap)
                .zip(bloom_hex.chunks_exact_mut(words_per_shard))
                .zip(shard_hex_inputs.into_iter())
            {
                fill_hex_shard(seg_slots, bloom_slice, batches);
            }
        } else {
            let tasks: Vec<Mutex<Option<(&mut [LinkSlotHex], &mut [u64], Vec<Vec<LinkSlotHex>>)>>> =
                slots_hex
                    .chunks_exact_mut(hex_seg_cap)
                    .zip(bloom_hex.chunks_exact_mut(words_per_shard))
                    .zip(shard_hex_inputs.into_iter())
                    .map(|((a, b), c)| Mutex::new(Some((a, b, c))))
                    .collect();
            let next_s = AtomicUsize::new(0);
            let fw = n_threads.min(LINK_SHARDS);
            std::thread::scope(|scope| {
                let tasks_ref = &tasks;
                let next_ref = &next_s;
                for _ in 0..fw {
                    scope.spawn(move || loop {
                        let s = next_ref.fetch_add(1, Ordering::Relaxed);
                        if s >= LINK_SHARDS {
                            break;
                        }
                        let (seg_slots, bloom_slice, batches) =
                            tasks_ref[s].lock().unwrap().take().unwrap();
                        fill_hex_shard(seg_slots, bloom_slice, batches);
                    });
                }
            });
        }

        (
            bloom_hex,
            bloom_hex_shift,
            bloom_hex_sub_mask,
            slots_hex,
            hex_seg_cap,
        )
    };

    let any_active = !groups_b37.is_empty() || !slots_hex.is_empty() || has_other || has_long;
    Ok(LinkMap {
        bloom,
        bloom_shift,
        bloom_sub_mask,
        groups_b37,
        seg_groups,
        bloom_hex,
        bloom_hex_shift,
        bloom_hex_sub_mask,
        slots_hex,
        hex_seg_cap,
        other_map,
        has_other,
        long_map,
        has_long,
        canon_hex,
        canon_arena,
        canon_spans,
        empty: !any_active,
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
        scratch: &'a mut [u8; 40],
    ) -> &'a [u8] {
        if k.is_uh42() {
            let s10: &mut [u8; 10] = (&mut scratch[..10]).try_into().unwrap();
            let len = decode_b37(inv_biject42(k.uh42_val()), b'u', s10);
            &scratch[..len]
        } else if k.is_comp() {
            lm.resolve_comp_bytes(k.comp_id(), scratch)
        } else {
            let s10: &mut [u8; 10] = (&mut scratch[..10]).try_into().unwrap();
            let len = k.decode_inline(s10);
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
        content.push_str("chain_00000,chain_00001\n");
        content.push_str("chain_00001,!chain_min\n");
        content.push_str("u99,chain_00000\n");
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let lm = build_link_map(&[p], 4).unwrap();
        let mut scratch = [0u8; 40];

        let k500 = CompactKey64::encode_raw_inline(b"id_500").unwrap();
        let kroot = CompactKey64::encode_raw_inline(b"!root").unwrap();
        let c500 = lm.resolve_other_inline(k500).unwrap();
        assert_eq!(c500, kroot);
        assert_eq!(lm.resolve_other_inline(kroot), None);
        assert_eq!(resolve_canon_for_test(&lm, c500, &mut scratch), b"!root");

        let mut pbuf = *b"u1\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        let h_u1 = biject42(encode_b37_padded(&pbuf, 0, 2, b'u').unwrap());
        assert_eq!(lm.probe_b37(h_u1), None);
        pbuf[1] = b'9';
        pbuf[2] = b'9';

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
        let mut scratch = [0u8; 40];
        assert_eq!(resolve_canon_for_test(&lm, c300, &mut scratch), b"u0000");
        assert_eq!(c300, CompactKey64::from_uh42(h_0000));
        assert_eq!(lm.probe_b37(h_0000), None);
        assert_eq!(lm.resolve_long(b"zzz_long_alias_12345"), Some(c300));
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

    #[test]
    fn test_dsu_hex32_roots_and_mixed_b37_components() {
        let dir = std::env::temp_dir().join("ss_test_links_hex32_v5");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Comp 1: u0000... (hex32 smallest root) linked to b37 "u9z" and hex32 "uffff..."
        // Comp 2: u1a (b37 smallest root) linked to hex32 "u5555..."
        // Comp 3: u0000...00 (all-zeros hex32) linked to b37 "u01" -> "u0000...00" < "u01" since '0'<'1' at idx 2? Wait: '0'=='0' at idx1, '0'<'1' at idx2 -> u0000... is smaller!
        let h_root_str = "u00000000000000000000000000000001";
        let h_alias_str = "uffffffffffffffffffffffffffffffff";
        let h_mid_str = "u55555555555555555555555555555555";
        let h_zero_str = "u00000000000000000000000000000000";
        let content = format!(
            "user_id_a,user_id_b\n\
             {h_alias_str},u9z\n\
             u9z,{h_root_str}\n\
             {h_mid_str},u1a\n\
             u01,{h_zero_str}\n\
             {h_mid_str},{h_mid_str}\n"
        );
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        for &threads in &[1usize, 4usize] {
            let mut lm = build_link_map(&[p.clone()], threads).unwrap();
            let mut scratch = [0u8; 40];

            let hx_root = encode_hex32_padded(h_root_str.as_bytes(), 0, 33, b'u').unwrap();
            let hx_alias = encode_hex32_padded(h_alias_str.as_bytes(), 0, 33, b'u').unwrap();
            let hx_mid = encode_hex32_padded(h_mid_str.as_bytes(), 0, 33, b'u').unwrap();
            let hx_zero = encode_hex32_padded(h_zero_str.as_bytes(), 0, 33, b'u').unwrap();
            let hx_miss = encode_hex32_padded(
                b"uabcdef0123456789abcdef0123456789",
                0,
                33,
                b'u',
            )
            .unwrap();

            for hx in [hx_root, hx_alias, hx_mid, hx_zero] {
                let h64 = hash_hex128(hx);
                lm.prefetch_bloom_hex(h64);
                assert!(lm.bloom_may_contain_hex(h64));
                lm.prefetch_slot_hex(h64);
            }

            let c_root = lm.probe_hex(hash_hex128(hx_root), hx_root).unwrap();
            let c_alias = lm.probe_hex(hash_hex128(hx_alias), hx_alias).unwrap();
            let h_u9z = biject42(encode_b37_padded(b"u9z\0\0\0\0\0\0\0\0\0\0\0\0\0", 0, 3, b'u').unwrap());
            let c_u9z = lm.probe_b37(h_u9z).unwrap();
            assert_eq!(c_root, c_alias);
            assert_eq!(c_root, c_u9z);
            assert_eq!(
                resolve_canon_for_test(&lm, c_root, &mut scratch),
                h_root_str.as_bytes()
            );

            // b37 smallest root ("u1a" < "u5555...")
            let c_mid = lm.probe_hex(hash_hex128(hx_mid), hx_mid).unwrap();
            assert_eq!(resolve_canon_for_test(&lm, c_mid, &mut scratch), b"u1a");

            // All-zeros hex32 root
            let c_zero = lm.probe_hex(hash_hex128(hx_zero), hx_zero).unwrap();
            let h_u01 = biject42(encode_b37_padded(b"u01\0\0\0\0\0\0\0\0\0\0\0\0\0", 0, 3, b'u').unwrap());
            assert_eq!(lm.probe_b37(h_u01), Some(c_zero));
            assert_eq!(
                resolve_canon_for_test(&lm, c_zero, &mut scratch),
                h_zero_str.as_bytes()
            );

            // Unlinked hex32 misses
            assert_eq!(lm.probe_hex(hash_hex128(hx_miss), hx_miss), None);

            lm.drop_lookup_tables();
            assert!(!lm.bloom_may_contain_hex(hash_hex128(hx_root)));
            assert_eq!(lm.probe_hex(hash_hex128(hx_root), hx_root), None);
            assert_eq!(
                resolve_canon_for_test(&lm, c_root, &mut scratch),
                h_root_str.as_bytes()
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_link_group64_overflow_and_inline_root() {
        let dir = std::env::temp_dir().join("ss_test_links_grp64_ovf");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // Force multi-group overflow within shards + inline root ("!z") smaller than 'u*'
        let mut content = String::from("user_id_a,user_id_b\n");
        for i in 1..=2200 {
            content.push_str(&format!("u{i},!z\n"));
        }
        for i in 5000..5200 {
            content.push_str(&format!("u{i},u0\n"));
        }
        let p = dir.join("part-0.csv");
        fs::write(&p, content).unwrap();

        let lm = build_link_map(&[p], 4).unwrap();
        let mut scratch = [0u8; 40];
        let mut pad = [0u8; 32];
        for i in 1..=2200 {
            let s = format!("u{i}");
            pad[..s.len()].copy_from_slice(s.as_bytes());
            let h = biject42(encode_b37_padded(&pad, 0, s.len(), b'u').unwrap());
            let canon = lm.probe_b37(h).expect("inline root member must hit");
            assert_eq!(resolve_canon_for_test(&lm, canon, &mut scratch), b"!z");
        }
        let h_u0 = biject42(encode_b37_padded(b"u0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0, 2, b'u').unwrap());
        assert_eq!(lm.probe_b37(h_u0), None);
        for i in 5000..5200 {
            let s = format!("u{i}");
            pad[..s.len()].copy_from_slice(s.as_bytes());
            let h = biject42(encode_b37_padded(&pad, 0, s.len(), b'u').unwrap());
            let canon = lm.probe_b37(h).expect("u0 member must hit");
            assert_eq!(resolve_canon_for_test(&lm, canon, &mut scratch), b"u0");
        }
        let h_miss = biject42(encode_b37_padded(b"umiss99\0\0\0\0\0\0\0\0\0", 0, 7, b'u').unwrap());
        assert_eq!(lm.probe_b37(h_miss), None);

        let _ = fs::remove_dir_all(&dir);
    }
}
