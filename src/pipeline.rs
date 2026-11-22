use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[inline(always)]
fn rdtsc_now() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

#[derive(Default)]
struct EvMicro {
    classify_cyc: u64,
    dec_f1_cyc: u64,
    dec_f3_cyc: u64,
    dec_oth_cyc: u64,
    n_f1: u64,
    n_f3: u64,
    n_oth: u64,
    n_fast_b37: u64,
    n_fast_uhex: u64,
    n_ext_b37: u64,
    n_inv_b37: u64,
    n_hex_ev: u64,
    n_ext_gen: u64,
    n_inv_gen: u64,
    n_purch: u64,
}

#[derive(Default)]
struct P2Micro {
    bloom_cyc: u64,
    probe_cyc: u64,
    push_cyc: u64,
    hex_cyc: u64,
    b37_bloom_hits: u64,
    b37_slot_hits: u64,
    b37_misses: u64,
    hex_bloom_hits: u64,
    hex_slot_hits: u64,
    hex_misses: u64,
    surv_total: u64,
}

#[derive(Default)]
struct DetailStats {
    links_w_ns: AtomicU64,
    ev_io_scan_ns: AtomicU64,
    ev_pread_ns: AtomicU64,
    ev_scan_ns: AtomicU64,
    ev_dec_ns: AtomicU64,
    ev_classify_ns: AtomicU64,
    ev_dec_f1_ns: AtomicU64,
    ev_dec_f3_ns: AtomicU64,
    ev_dec_oth_ns: AtomicU64,
    ev_n_f1: AtomicU64,
    ev_n_f3: AtomicU64,
    ev_n_oth: AtomicU64,
    ev_n_fast_b37: AtomicU64,
    ev_n_fast_uhex: AtomicU64,
    ev_n_ext_b37: AtomicU64,
    ev_n_inv_b37: AtomicU64,
    ev_n_hex_ev: AtomicU64,
    ev_n_ext_gen: AtomicU64,
    ev_n_inv_gen: AtomicU64,
    ev_n_purch: AtomicU64,
    cl_ns: AtomicU64,
    dedup_p1_ns: AtomicU64,
    dedup_p2_ns: AtomicU64,
    p2_unpack_ns: AtomicU64,
    p2_bloom_ns: AtomicU64,
    p2_probe_ns: AtomicU64,
    p2_push_ns: AtomicU64,
    p2_hex_ns: AtomicU64,
    p2_b37_bloom_hits: AtomicU64,
    p2_b37_slot_hits: AtomicU64,
    p2_b37_misses: AtomicU64,
    p2_hex_bloom_hits: AtomicU64,
    p2_hex_slot_hits: AtomicU64,
    p2_hex_misses: AtomicU64,
    p2_surv_total: AtomicU64,
    ev_drop_w_ns: AtomicU64,
    s5_ev_csr_ns: AtomicU64,
    s5_ev_csr_p1_ns: AtomicU64,
    s5_ev_csr_p2_ns: AtomicU64,
    s5_cl_csr_ns: AtomicU64,
    s5_sort_ns: AtomicU64,
    s5_sess_attr_ns: AtomicU64,
    s5_ud_ns: AtomicU64,
}

use hashbrown::{HashMap, HashTable};

use crate::csv::{
    biject42, cmp_raw_keys, decode_b37, decode_hex32, encode_b37_padded, encode_b37_pair_padded,
    encode_hex32_padded, eq_raw_keys, field_span, for_each_line_fields_slice, hash_bytes_fast,
    hash_hex128, hash_raw_key, inv_biject42, list_csv_files, mix64, CompactKey64, CsvSource,
    DirectLineRef, Hex128, LongArena, B37_MASK42, CHUNK_BYTES,
};
use crate::links::{build_link_map, LinkMap};
use crate::parse::{
    parse_price_cents, parse_ts_ms, DateCache, Manifest, MS_CLICK_REACH, MS_DAY, MS_SECOND,
    MS_SESSION_GAP,
};
use crate::parquet_out::{clean_parquet_dir, write_campaign_daily, CampaignRow, UserDailyWriter};
use crate::slab::{MutChunkRef, SlabArena, SlabBuckets};

const P_DEDUP: usize = 128;
const DEDUP_SWCB_W: usize = 8;
const P_PERSON: usize = 128;
const PERSON_SWCB_W: usize = 8;
const EV_CHUNK_LEN: usize = 1024;
const EV_CHUNK_SHIFT: u32 = 10;
const EV_CHUNK_MASK: u32 = (EV_CHUNK_LEN as u32) - 1;
const MAX_DEDUP_U32_CHUNKS: usize = 1023;
const PE_CHUNK_LEN: usize = 2048;
const CL_CHUNK_LEN: usize = 1024;
const P_HEX_DEDUP: usize = 64;
const HX_CHUNK_LEN: usize = 256;
const HX_CHUNK_SHIFT: u32 = 8;
const HX_CHUNK_MASK: u32 = (HX_CHUNK_LEN as u32) - 1;
const MAX_HX_U32_CHUNKS: usize = 4095;
const _: () = assert!(MAX_HX_U32_CHUNKS * HX_CHUNK_LEN <= 0x000F_FFFF);
const HX_TS_DEAD: u32 = u32::MAX - 2;
const HX_TS_EXT: u32 = u32::MAX - 1;
const HX_TS_INVALID: u32 = u32::MAX;
const HX_ING_BIAS: i64 = 1i64 << 30;
const USER_DAILY_BATCH_ROWS: usize = 131_072;

const PE_TAG_SHIFT: u32 = 61;
const PE_FAST_B37: u64 = 0u64 << PE_TAG_SHIFT;
const PE_FAST_UHEX: u64 = 1u64 << PE_TAG_SHIFT;
const PE_EXT_B37: u64 = 2u64 << PE_TAG_SHIFT;
const PE_INV_B37: u64 = 3u64 << PE_TAG_SHIFT;
const PE_DEAD: u64 = 5u64 << PE_TAG_SHIFT;
const PE_EXT_GEN: u64 = 6u64 << PE_TAG_SHIFT;
const PE_TAG_MASK: u64 = 7u64 << PE_TAG_SHIFT;
const PE_EV_REM_MASK: u64 = (1u64 << 35) - 1;
const PE_EXT_IDX_MASK: u64 = (1u64 << 40) - 1;
const PE_ING_BIAS: i64 = 40_000;
const PE_ING_MAX: i64 = (1i64 << 17) - PE_ING_BIAS;

#[derive(Clone, Copy)]
#[repr(C)]
struct ParsedEvent16 {
    w0: u64,
    w1: u64,
}

const _: () = assert!(std::mem::size_of::<ParsedEvent16>() == 16);

#[derive(Clone, Copy)]
struct ExtEvent {
    person_key: CompactKey64,
    ts_ms: i64,
    ingest_ts_ms: i64,
    price_cents: u32,
    cat_id: u32, // u32::MAX marks invalid event (kept for dedup ingest_ts check)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct HexEvent32 {
    ev_hi: u64,
    ev_lo: u64,
    person_key: CompactKey64,
    ts_rel_ms: u32,
    ing_sec_off: u32,
}

const _: () = assert!(std::mem::size_of::<HexEvent32>() == 32);

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonEvent16 {
    person_key: CompactKey64,
    ts_rel_ms: u32,
    price_cat: u32,
}

const _: () = assert!(std::mem::size_of::<PersonEvent16>() == 16);

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonEventWide {
    person_key: CompactKey64,
    ts_ms: i64,
    price_cents: u32,
    cat_id: u32,
}

const _: () = assert!(std::mem::size_of::<PersonEventWide>() == 24);

const CL_TAG_SHIFT: u32 = 62;
const CL_UB37: u64 = 0u64 << CL_TAG_SHIFT;
const CL_EXT: u64 = 1u64 << CL_TAG_SHIFT;
const CL_TAG_MASK: u64 = 3u64 << CL_TAG_SHIFT;
const CL_REM34_MASK: u64 = (1u64 << 34) - 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct ExtClick {
    click_id_key: CompactKey64,
    ts_rel_ms: u32,
    camp_id: u32,
}

const _: () = assert!(std::mem::size_of::<ExtClick>() == 16);

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonClick16 {
    w0: u64,
    w1: u64,
}

const _: () = assert!(std::mem::size_of::<PersonClick16>() == 16);

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonClickWide {
    person_key: CompactKey64,
    click_id_key: CompactKey64,
    ts_ms: i64,
    camp_id: u32,
    _pad: u32,
}

const _: () = assert!(std::mem::size_of::<PersonClickWide>() == 32);

#[derive(Clone, Copy)]
enum ClickPerson {
    Uh42Rem(u64),
    Gen(CompactKey64),
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactEventWide {
    ts_ms: i64,
    price_cents: u32,
    cat_id: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactClick16 {
    ts_rel_ms: u32,
    camp_id: u32,
    click_id_key: CompactKey64,
}

const _: () = assert!(std::mem::size_of::<CompactClick16>() == 16);

#[derive(Clone, Copy)]
#[repr(C)]
struct CompactClickWide {
    ts_ms: i64,
    camp_id: u32,
    _pad: u32,
    click_id_key: CompactKey64,
}

#[derive(Clone, Copy)]
struct SessionInfo {
    start_cmp: i64,
    day: i32,
    has_purchase: u32,
    revenue_cents: i64,
}

const _: () = assert!(std::mem::size_of::<SessionInfo>() == 24);

#[derive(Clone, Copy)]
struct DayRange {
    day: i32,
    lo_idx: u32,
    hi_idx: u32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CampCredit {
    sessions: u32,
    purchasing_sessions: u32,
    revenue_cents: i64,
}

const _: () = assert!(std::mem::size_of::<CampCredit>() == 16);

#[derive(Clone, Copy, Default)]
struct CampDayAgg {
    sessions: i64,
    purchasing_sessions: i64,
    revenue_cents: i64,
    assisted_sessions: i64,
}

impl CampDayAgg {
    #[inline(always)]
    fn add_assign(&mut self, other: &CampDayAgg) {
        self.sessions += other.sessions;
        self.purchasing_sessions += other.purchasing_sessions;
        self.revenue_cents += other.revenue_cents;
        self.assisted_sessions += other.assisted_sessions;
    }
}

enum CampDailyAcc {
    Dense {
        start_day: i32,
        num_days: usize,
        day_shift: u32,
        num_camps: usize,
        assists: Vec<u32>,
        credits: Vec<CampCredit>,
    },
    Sparse(HashMap<(u32, i32), CampDayAgg>),
}

impl CampDailyAcc {
    fn new(num_camps: usize, min_day: i32, max_day: i32, total_events: usize) -> Self {
        let span = (max_day as i64 - min_day as i64 + 1).max(1) as usize;
        let day_stride = span.next_power_of_two();
        let day_shift = day_stride.trailing_zeros();
        if span <= 4096
            && num_camps <= 16_384
            && day_stride.saturating_mul(num_camps) <= 1_048_576
            && total_events < (u32::MAX as usize)
        {
            let total_cells = num_camps << day_shift;
            Self::Dense {
                start_day: min_day,
                num_days: span,
                day_shift,
                num_camps,
                assists: vec![0u32; total_cells],
                credits: vec![CampCredit::default(); total_cells],
            }
        } else {
            Self::Sparse(HashMap::with_capacity(4096))
        }
    }

    #[inline(always)]
    fn add_credit(&mut self, camp_id: u32, day: i32, has_purchase: u32, rev: i64) {
        match self {
            Self::Dense {
                start_day,
                num_days,
                day_shift,
                num_camps,
                credits,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days && (camp_id as usize) < *num_camps);
                let idx = ((camp_id as usize) << *day_shift) + d_off;
                let c = unsafe { credits.get_unchecked_mut(idx) };
                c.sessions += 1;
                c.purchasing_sessions += has_purchase;
                c.revenue_cents += rev;
            }
            Self::Sparse(map) => {
                let c = map.entry((camp_id, day)).or_default();
                c.sessions += 1;
                c.purchasing_sessions += has_purchase as i64;
                c.revenue_cents += rev;
            }
        }
    }

    #[inline(always)]
    fn add_credit_batch(
        &mut self,
        camp_id: u32,
        day: i32,
        sessions: u32,
        purch_sessions: u32,
        rev: i64,
    ) {
        match self {
            Self::Dense {
                start_day,
                num_days,
                day_shift,
                num_camps,
                credits,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days && (camp_id as usize) < *num_camps);
                let idx = ((camp_id as usize) << *day_shift) + d_off;
                let c = unsafe { credits.get_unchecked_mut(idx) };
                c.sessions += sessions;
                c.purchasing_sessions += purch_sessions;
                c.revenue_cents += rev;
            }
            Self::Sparse(map) => {
                let c = map.entry((camp_id, day)).or_default();
                c.sessions += sessions as i64;
                c.purchasing_sessions += purch_sessions as i64;
                c.revenue_cents += rev;
            }
        }
    }

    #[inline(always)]
    fn add_assist(&mut self, camp_id: u32, day: i32, cnt: i64) {
        match self {
            Self::Dense {
                start_day,
                num_days,
                day_shift,
                num_camps,
                assists,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days && (camp_id as usize) < *num_camps);
                let idx = ((camp_id as usize) << *day_shift) + d_off;
                unsafe {
                    *assists.get_unchecked_mut(idx) += cnt as u32;
                }
            }
            Self::Sparse(map) => {
                map.entry((camp_id, day)).or_default().assisted_sessions += cnt;
            }
        }
    }

    #[inline(always)]
    fn add_assists_batch(&mut self, camps: &[u32], day: i32, cnt: u32) {
        if camps.is_empty() {
            return;
        }
        match self {
            Self::Dense {
                start_day,
                num_days,
                day_shift,
                num_camps,
                assists,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days);
                let sh = *day_shift;
                let n_c = *num_camps;
                for &camp_id in camps {
                    let c = camp_id as usize;
                    debug_assert!(c < n_c);
                    unsafe {
                        *assists.get_unchecked_mut((c << sh) + d_off) += cnt;
                    }
                }
            }
            Self::Sparse(map) => {
                let c64 = cnt as i64;
                for &camp_id in camps {
                    map.entry((camp_id, day)).or_default().assisted_sessions += c64;
                }
            }
        }
    }

    fn merge_into(&mut self, other: CampDailyAcc) {
        match (self, other) {
            (
                Self::Dense {
                    assists: dst_a,
                    credits: dst_c,
                    ..
                },
                Self::Dense {
                    assists: src_a,
                    credits: src_c,
                    ..
                },
            ) => {
                for (da, sa) in dst_a.iter_mut().zip(src_a.iter()) {
                    *da += *sa;
                }
                for (dc, sc) in dst_c.iter_mut().zip(src_c.iter()) {
                    dc.sessions += sc.sessions;
                    dc.purchasing_sessions += sc.purchasing_sessions;
                    dc.revenue_cents += sc.revenue_cents;
                }
            }
            (Self::Sparse(dst), Self::Sparse(src)) => {
                for (k, v) in src {
                    dst.entry(k).or_default().add_assign(&v);
                }
            }
            _ => unreachable!("mismatched CampDailyAcc variants"),
        }
    }
}

#[inline(always)]
fn fast_range32(h: u64, cap: usize) -> usize {
    (((h as u32 as u64).wrapping_mul(cap as u64)) >> 32) as usize
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FlatKvSlot {
    key: u64,
    val: u32,
}

impl FlatKvSlot {
    const EMPTY: Self = Self { key: 0, val: 0 };
}

fn insert_flat_kv(
    slots: &mut Vec<FlatKvSlot>,
    mask: &mut usize,
    count: &mut usize,
    key: u64,
    val: u32,
) {
    if (*count + 1) * 10 >= slots.len() * 6 {
        let new_cap = (slots.len() * 2).max(16);
        let new_mask = new_cap - 1;
        let mut new_slots = vec![FlatKvSlot::EMPTY; new_cap];
        for s in slots.iter() {
            if s.key != 0 {
                let mut pos = (mix64(s.key) as usize) & new_mask;
                while new_slots[pos].key != 0 {
                    pos = (pos + 1) & new_mask;
                }
                new_slots[pos] = *s;
            }
        }
        *slots = new_slots;
        *mask = new_mask;
    }
    let m = *mask;
    let mut pos = (mix64(key) as usize) & m;
    loop {
        let cur = slots[pos];
        if cur.key == key {
            slots[pos].val = val;
            return;
        }
        if cur.key == 0 {
            slots[pos] = FlatKvSlot { key, val };
            *count += 1;
            return;
        }
        pos = (pos + 1) & m;
    }
}

fn repack_flat_kv(src: Vec<FlatKvSlot>, count: usize) -> (Vec<FlatKvSlot>, usize) {
    let cap = ((count * 10 + 6) / 7).max(count + 1).max(2);
    let mut dst = vec![FlatKvSlot::EMPTY; cap];
    for s in src {
        if s.key != 0 {
            let mut pos = fast_range32(mix64(s.key), cap);
            while dst[pos].key != 0 {
                pos += 1;
                if pos == cap {
                    pos = 0;
                }
            }
            dst[pos] = s;
        }
    }
    (dst, cap)
}

#[inline(always)]
fn parse_canonical_uint_padded(ptr: *const u8, len: usize) -> Option<usize> {
    if len == 0 || len > 6 {
        return None;
    }
    unsafe {
        let b0 = *ptr;
        if b0 == b'0' {
            return if len == 1 { Some(0) } else { None };
        }
        let d0 = b0.wrapping_sub(b'0');
        if d0 == 0 || d0 >= 10 {
            return None;
        }
        let mut val = d0 as usize;
        let mut i = 1usize;
        while i < len {
            let d = (*ptr.add(i)).wrapping_sub(b'0');
            if d >= 10 {
                return None;
            }
            val = val * 10 + (d as usize);
            i += 1;
        }
        Some(val)
    }
}

struct CampEntry {
    cid_off: usize,
    cid_len: usize,
    ch_off: usize,
    ch_len: usize,
}

struct Lookups {
    prod_fast: Vec<u8>,
    prod_slots: Vec<FlatKvSlot>,
    prod_cap: usize,
    long_prod_map: HashMap<Box<[u8]>, u32>,
    has_long_prod: bool,
    categories: Vec<Box<[u8]>>,
    unknown_cat_id: u32,
    camp_buf: Vec<u8>,
    camp_entries: Vec<CampEntry>,
    camp_fast: Vec<u16>,
    camp_slots: Vec<FlatKvSlot>,
    camp_cap: usize,
    long_camp_map: HashMap<Box<[u8]>, u32>,
    has_long_camp: bool,
    organic_camp_id: u32,
}

impl Lookups {
    #[inline(always)]
    fn get_product_cat_padded(&self, padded: &[u8], start: usize, len: usize) -> u32 {
        let ptr = unsafe { padded.as_ptr().add(start) };
        if !self.prod_fast.is_empty() && len >= 2 && unsafe { *ptr } == b'p' {
            if let Some(idx) = parse_canonical_uint_padded(unsafe { ptr.add(1) }, len - 1) {
                if idx < self.prod_fast.len() {
                    return unsafe { *self.prod_fast.get_unchecked(idx) } as u32;
                }
            }
        }
        if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, start, len) {
            let cap = self.prod_cap;
            let mut pos = fast_range32(mix64(k.0), cap);
            loop {
                let s = unsafe { *self.prod_slots.get_unchecked(pos) };
                if s.key == k.0 {
                    return s.val;
                }
                if s.key == 0 {
                    return self.unknown_cat_id;
                }
                pos += 1;
                if pos == cap {
                    pos = 0;
                }
            }
        } else if self.has_long_prod {
            let pid = unsafe { padded.get_unchecked(start..start + len) };
            self.long_prod_map
                .get(pid)
                .copied()
                .unwrap_or(self.unknown_cat_id)
        } else {
            self.unknown_cat_id
        }
    }

    #[inline(always)]
    fn get_campaign_padded(&self, padded: &[u8], start: usize, len: usize) -> Option<u32> {
        let ptr = unsafe { padded.as_ptr().add(start) };
        if !self.camp_fast.is_empty()
            && len >= 3
            && unsafe { *ptr == b'c' && *ptr.add(1) == b'_' }
        {
            if let Some(idx) = parse_canonical_uint_padded(unsafe { ptr.add(2) }, len - 2) {
                if idx < self.camp_fast.len() {
                    let v = unsafe { *self.camp_fast.get_unchecked(idx) };
                    return if v != u16::MAX { Some(v as u32) } else { None };
                }
            }
        }
        if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, start, len) {
            let cap = self.camp_cap;
            let mut pos = fast_range32(mix64(k.0), cap);
            loop {
                let s = unsafe { *self.camp_slots.get_unchecked(pos) };
                if s.key == k.0 {
                    return Some(s.val);
                }
                if s.key == 0 {
                    return None;
                }
                pos += 1;
                if pos == cap {
                    pos = 0;
                }
            }
        } else if self.has_long_camp {
            let cid = unsafe { padded.get_unchecked(start..start + len) };
            self.long_camp_map.get(cid).copied()
        } else {
            None
        }
    }

    #[inline(always)]
    fn camp_name(&self, cid: usize) -> &[u8] {
        let e = &self.camp_entries[cid];
        &self.camp_buf[e.cid_off..e.cid_off + e.cid_len]
    }

    #[inline(always)]
    fn camp_channel(&self, cid: usize) -> &[u8] {
        let e = &self.camp_entries[cid];
        &self.camp_buf[e.ch_off..e.ch_off + e.ch_len]
    }
}

#[inline(always)]
fn scan_buf_skip_header<const K: usize>(buf: &[u8], f: impl FnMut([&[u8]; K])) {
    let Some(hdr_end) = memchr::memchr(b'\n', buf) else {
        return;
    };
    for_each_line_fields_slice::<K>(&buf[hdr_end + 1..], f);
}

fn load_lookups(data_dir: &Path) -> io::Result<Lookups> {
    let prod_path = data_dir.join("products.csv");
    let prod_buf = if prod_path.is_file() {
        fs::read(&prod_path)?
    } else {
        Vec::new()
    };
    let prod_base = prod_buf.as_ptr() as usize;

    let mut raw_cats: Vec<(usize, usize, u64)> = Vec::with_capacity(64);
    let mut cat_table: HashTable<u32> = HashTable::with_capacity(64);
    let est_prods = (prod_buf.len() / 16).max(16);
    let p_cap = ((est_prods * 10) / 6).max(16).next_power_of_two();
    let mut tmp_prod_slots = vec![FlatKvSlot::EMPTY; p_cap];
    let mut tmp_prod_mask = p_cap - 1;
    let mut prod_count = 0usize;
    let mut long_prod_map: HashMap<Box<[u8]>, u32> = HashMap::new();

    scan_buf_skip_header::<2>(&prod_buf, |[pid, cat]| {
        if pid.is_empty() || cat.is_empty() {
            return;
        }
        let ch = hash_bytes_fast(cat);
        let tmp_cat = match cat_table.find(ch, |&idx| {
            let &(coff, clen, c_h) = &raw_cats[idx as usize];
            c_h == ch && &prod_buf[coff..coff + clen] == cat
        }) {
            Some(&idx) => idx,
            None => {
                let idx = raw_cats.len() as u32;
                let coff = cat.as_ptr() as usize - prod_base;
                raw_cats.push((coff, cat.len(), ch));
                cat_table.insert_unique(ch, idx, |&i| raw_cats[i as usize].2);
                idx
            }
        };

        if let Some(k) = CompactKey64::encode_raw_inline(pid) {
            insert_flat_kv(
                &mut tmp_prod_slots,
                &mut tmp_prod_mask,
                &mut prod_count,
                k.0,
                tmp_cat,
            );
        } else {
            long_prod_map.insert(pid.to_vec().into_boxed_slice(), tmp_cat);
        }
    });

    // Sort unique categories (+ "unknown") byte-wise ascending so tie-breaks compare cat_id integer.
    let mut cat_slices: Vec<(Vec<u8>, Option<u32>)> = raw_cats
        .iter()
        .enumerate()
        .map(|(i, &(off, len, _))| (prod_buf[off..off + len].to_vec(), Some(i as u32)))
        .collect();
    if !cat_slices.iter().any(|(b, _)| b.as_slice() == b"unknown") {
        cat_slices.push((b"unknown".to_vec(), None));
    }
    cat_slices.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    let mut remap = vec![0u32; raw_cats.len()];
    let mut categories: Vec<Box<[u8]>> = Vec::with_capacity(cat_slices.len());
    let mut unknown_cat_id = 0u32;
    for (sorted_id, (bytes, maybe_tmp)) in cat_slices.into_iter().enumerate() {
        if bytes.as_slice() == b"unknown" {
            unknown_cat_id = sorted_id as u32;
        }
        if let Some(tmp_id) = maybe_tmp {
            remap[tmp_id as usize] = sorted_id as u32;
        }
        categories.push(bytes.into_boxed_slice());
    }
    for s in &mut tmp_prod_slots {
        if s.key != 0 {
            s.val = remap[s.val as usize];
        }
    }
    for v in long_prod_map.values_mut() {
        *v = remap[*v as usize];
    }
    const MAX_FAST_PROD: usize = 262_144;
    let mut prod_fast = Vec::new();
    if categories.len() <= 256 {
        let mut kbuf = [0u8; 10];
        let mut max_pidx = None;
        for s in &tmp_prod_slots {
            if s.key != 0 {
                let len = CompactKey64(s.key).decode_inline(&mut kbuf);
                if len >= 2 && kbuf[0] == b'p' {
                    if let Some(idx) =
                        parse_canonical_uint_padded(unsafe { kbuf.as_ptr().add(1) }, len - 1)
                    {
                        if idx < MAX_FAST_PROD {
                            max_pidx = Some(max_pidx.map_or(idx, |m: usize| m.max(idx)));
                        }
                    }
                }
            }
        }
        if let Some(max_i) = max_pidx {
            prod_fast = vec![unknown_cat_id as u8; max_i + 1];
            for s in &tmp_prod_slots {
                if s.key != 0 {
                    let len = CompactKey64(s.key).decode_inline(&mut kbuf);
                    if len >= 2 && kbuf[0] == b'p' {
                        if let Some(idx) =
                            parse_canonical_uint_padded(unsafe { kbuf.as_ptr().add(1) }, len - 1)
                        {
                            if idx < MAX_FAST_PROD {
                                prod_fast[idx] = s.val as u8;
                            }
                        }
                    }
                }
            }
        }
    }
    let (prod_slots, prod_cap) = repack_flat_kv(tmp_prod_slots, prod_count);

    let camp_path = data_dir.join("campaigns.csv");
    let mut camp_buf = if camp_path.is_file() {
        fs::read(&camp_path)?
    } else {
        Vec::new()
    };
    let camp_base = camp_buf.as_ptr() as usize;
    let est_camps = (camp_buf.len() / 12).max(16);
    let c_cap = (est_camps * 2).next_power_of_two();
    let mut camp_entries: Vec<CampEntry> = Vec::with_capacity(est_camps);
    let mut tmp_camp_slots = vec![FlatKvSlot::EMPTY; c_cap];
    let mut tmp_camp_mask = c_cap - 1;
    let mut camp_count = 0usize;
    let mut long_camp_map: HashMap<Box<[u8]>, u32> = HashMap::new();

    scan_buf_skip_header::<2>(&camp_buf, |[cid, ch_name]| {
        if cid.is_empty() || ch_name.is_empty() {
            return;
        }
        let cid_off = cid.as_ptr() as usize - camp_base;
        let ch_off = ch_name.as_ptr() as usize - camp_base;
        let idx = camp_entries.len() as u32;
        camp_entries.push(CampEntry {
            cid_off,
            cid_len: cid.len(),
            ch_off,
            ch_len: ch_name.len(),
        });
        if let Some(k) = CompactKey64::encode_raw_inline(cid) {
            insert_flat_kv(
                &mut tmp_camp_slots,
                &mut tmp_camp_mask,
                &mut camp_count,
                k.0,
                idx,
            );
        } else {
            long_camp_map.insert(cid.to_vec().into_boxed_slice(), idx);
        }
    });

    let organic_camp_id = camp_entries.len() as u32;
    let org_off = camp_buf.len();
    camp_buf.extend_from_slice(b"organic");
    camp_entries.push(CampEntry {
        cid_off: org_off,
        cid_len: 7,
        ch_off: org_off,
        ch_len: 7,
    });

    const MAX_FAST_CAMP: usize = 65_536;
    let mut camp_fast = Vec::new();
    if camp_entries.len() < u16::MAX as usize {
        let mut kbuf = [0u8; 10];
        let mut max_cidx = None;
        for s in &tmp_camp_slots {
            if s.key != 0 {
                let len = CompactKey64(s.key).decode_inline(&mut kbuf);
                if len >= 3 && kbuf[0] == b'c' && kbuf[1] == b'_' {
                    if let Some(idx) =
                        parse_canonical_uint_padded(unsafe { kbuf.as_ptr().add(2) }, len - 2)
                    {
                        if idx < MAX_FAST_CAMP {
                            max_cidx = Some(max_cidx.map_or(idx, |m: usize| m.max(idx)));
                        }
                    }
                }
            }
        }
        if let Some(max_i) = max_cidx {
            camp_fast = vec![u16::MAX; max_i + 1];
            for s in &tmp_camp_slots {
                if s.key != 0 {
                    let len = CompactKey64(s.key).decode_inline(&mut kbuf);
                    if len >= 3 && kbuf[0] == b'c' && kbuf[1] == b'_' {
                        if let Some(idx) =
                            parse_canonical_uint_padded(unsafe { kbuf.as_ptr().add(2) }, len - 2)
                        {
                            if idx < MAX_FAST_CAMP {
                                camp_fast[idx] = s.val as u16;
                            }
                        }
                    }
                }
            }
        }
    }
    let (camp_slots, camp_cap) = repack_flat_kv(tmp_camp_slots, camp_count);
    let has_long_prod = !long_prod_map.is_empty();
    let has_long_camp = !long_camp_map.is_empty();

    Ok(Lookups {
        prod_fast,
        prod_slots,
        prod_cap,
        long_prod_map,
        has_long_prod,
        categories,
        unknown_cat_id,
        camp_buf,
        camp_entries,
        camp_fast,
        camp_slots,
        camp_cap,
        long_camp_map,
        has_long_camp,
        organic_camp_id,
    })
}

#[inline(always)]
fn resolve_person_bytes<'a>(
    key: CompactKey64,
    link_map: &'a LinkMap,
    ev_arenas: &'a [LongArena],
    ev_hex: &'a [Vec<Hex128>],
    stack_buf: &'a mut [u8; 40],
) -> &'a [u8] {
    if key.is_uh42() {
        let s10: &mut [u8; 10] = (&mut stack_buf[..10]).try_into().unwrap();
        let len = decode_b37(inv_biject42(key.uh42_val()), b'u', s10);
        &stack_buf[..len]
    } else if key.is_comp() {
        link_map.resolve_comp_bytes(key.comp_id(), stack_buf)
    } else if key.is_hex() {
        let len = decode_hex32(key.resolve_hex(ev_hex), b'u', stack_buf);
        &stack_buf[..len]
    } else if key.is_ref() {
        LongArena::resolve_in(ev_arenas, key)
    } else {
        let s10: &mut [u8; 10] = (&mut stack_buf[..10]).try_into().unwrap();
        let len = key.decode_inline(s10);
        &stack_buf[..len]
    }
}

#[inline(always)]
fn hx32_ingest_ms(hx: &HexEvent32, window_start_sec: i64, ext_by_worker: &[Vec<ExtEvent>]) -> i64 {
    if hx.ts_rel_ms == HX_TS_EXT {
        let wid = (hx.person_key.0 >> 40) as usize;
        let idx = (hx.person_key.0 & PE_EXT_IDX_MASK) as usize;
        unsafe { ext_by_worker.get_unchecked(wid).get_unchecked(idx).ingest_ts_ms }
    } else {
        let ing_off = (hx.ing_sec_off as i64) - HX_ING_BIAS;
        (window_start_sec + ing_off) * 1_000
    }
}

#[inline(always)]
fn ev16_ingest_ts(
    ev: &ParsedEvent16,
    window_start_sec: i64,
    ext_by_worker: &[Vec<ExtEvent>],
) -> i64 {
    let tag = ev.w0 & PE_TAG_MASK;
    if tag <= PE_FAST_UHEX {
        let ing_off = (((ev.w0 >> 44) & 0x1_FFFF) as i64) - PE_ING_BIAS;
        let ts_rel = (((ev.w0 >> 35) & 0x1FF) << 22) | (ev.w1 >> 42);
        (window_start_sec + ((ts_rel / 1_000) as i64) + ing_off) * 1_000
    } else if tag == PE_INV_B37 {
        ev.w1 as i64
    } else if tag == PE_EXT_B37 {
        let wid = (ev.w1 >> 40) as usize;
        let idx = (ev.w1 & PE_EXT_IDX_MASK) as usize;
        unsafe { ext_by_worker.get_unchecked(wid).get_unchecked(idx).ingest_ts_ms }
    } else {
        let payload = ev.w0 & !PE_TAG_MASK;
        let wid = (payload >> 40) as usize;
        let idx = (payload & PE_EXT_IDX_MASK) as usize;
        unsafe { ext_by_worker.get_unchecked(wid).get_unchecked(idx).ingest_ts_ms }
    }
}

trait Stage5Event: Copy + Send + Sync {
    const FAST_DAY_BOUND: bool;
    type Grouped: Copy + Send;
    fn person_key(&self) -> CompactKey64;
    fn to_grouped(&self) -> Self::Grouped;
    fn sort_grouped(slice: &mut [Self::Grouped], scratch: &mut Vec<u64>);
    fn unpack_cmp_price_cat(g: Self::Grouped) -> (i64, u32, u32);
    fn day_from_cmp(cmp_ts: i64, ws_day: i32, ws_rem: u64) -> i32;
    fn day_end_cmp(day: i32, ws_day: i32, ws_rem: u64) -> i64;
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool;
}

trait Stage5Click: Copy + Send + Sync {
    type Grouped: Copy + Send;
    fn click_person(&self, cl_ext: &[Vec<ExtClick>]) -> ClickPerson;
    fn to_grouped(&self, cl_ext: &[Vec<ExtClick>]) -> Self::Grouped;
    fn sort_grouped(slice: &mut [Self::Grouped]);
    fn unpack_full(g: &Self::Grouped) -> (i64, u32, CompactKey64);
    fn within_reach(sess_cmp: i64, click_cmp: i64) -> bool;
}

trait ClickEmit: Stage5Click {
    fn make_b37_pending(
        h42: u64,
        k_b37: u64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self;
    fn apply_canon(&mut self, canon: CompactKey64, wid: usize, cl_ext: &mut Vec<ExtClick>);
    fn make_direct(
        wid: usize,
        cl_ext: &mut Vec<ExtClick>,
        person_key: CompactKey64,
        click_id_key: CompactKey64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self;
}

trait DedupEmit: Stage5Event {
    fn empty_tmpl() -> Self;
    fn from_fast_ms_b37(h42: u64, ts_rel_ms: u32) -> Self;
    fn from_ext_fields(
        person_key: CompactKey64,
        ts_ms: i64,
        window_start_ms: i64,
        price_cents: u32,
        cat_id: u32,
    ) -> Self;
    fn apply_canon(&mut self, canon: CompactKey64);
}

impl DedupEmit for PersonEvent16 {
    #[inline(always)]
    fn empty_tmpl() -> Self {
        Self {
            person_key: CompactKey64::EMPTY,
            ts_rel_ms: 0,
            price_cat: 0,
        }
    }

    #[inline(always)]
    fn from_fast_ms_b37(h42: u64, ts_rel_ms: u32) -> Self {
        Self {
            person_key: CompactKey64::from_uh42(h42),
            ts_rel_ms,
            price_cat: 0,
        }
    }

    #[inline(always)]
    fn from_ext_fields(
        person_key: CompactKey64,
        ts_ms: i64,
        window_start_ms: i64,
        price_cents: u32,
        cat_id: u32,
    ) -> Self {
        Self {
            person_key,
            ts_rel_ms: (ts_ms - window_start_ms) as u32,
            price_cat: (cat_id << 24) | price_cents,
        }
    }

    #[inline(always)]
    fn apply_canon(&mut self, canon: CompactKey64) {
        self.person_key = canon;
    }
}

impl DedupEmit for PersonEventWide {
    #[inline(always)]
    fn empty_tmpl() -> Self {
        Self {
            person_key: CompactKey64::EMPTY,
            ts_ms: 0,
            price_cents: 0,
            cat_id: 0,
        }
    }

    #[inline(always)]
    fn from_fast_ms_b37(_h42: u64, _ts_rel_ms: u32) -> Self {
        unreachable!("PE_FAST_B37 is only emitted in compact mode")
    }

    #[inline(always)]
    fn from_ext_fields(
        person_key: CompactKey64,
        ts_ms: i64,
        _window_start_ms: i64,
        price_cents: u32,
        cat_id: u32,
    ) -> Self {
        Self {
            person_key,
            ts_ms,
            price_cents,
            cat_id,
        }
    }

    #[inline(always)]
    fn apply_canon(&mut self, canon: CompactKey64) {
        self.person_key = canon;
    }
}

#[derive(Clone, Copy)]
struct DedupProbeU32 {
    tag12: u32,
    slot: u32,
}

#[inline(always)]
fn pshard_for_person_key(pk: CompactKey64, arenas: &[LongArena]) -> usize {
    if pk.is_uh42() {
        ((pk.uh42_val() >> 34) as usize) & (P_PERSON - 1)
    } else if pk.is_hex() {
        (pk.0 as usize) & (P_PERSON - 1)
    } else if !pk.is_ref() {
        ((mix64(pk.0) >> 52) as usize) & (P_PERSON - 1)
    } else {
        ((hash_bytes_fast(LongArena::resolve_in(arenas, pk)) >> 52) as usize) & (P_PERSON - 1)
    }
}

#[inline(always)]
fn hash_person_key(k: CompactKey64, arenas: &[LongArena], hex_pools: &[Vec<Hex128>]) -> u64 {
    if k.is_hex() {
        hash_hex128(k.resolve_hex(hex_pools))
    } else if !k.is_ref() {
        mix64(k.0)
    } else {
        hash_bytes_fast(LongArena::resolve_in(arenas, k))
    }
}

#[inline(always)]
fn eq_person_keys(
    a: CompactKey64,
    b: CompactKey64,
    arenas_a: &[LongArena],
    hex_a: &[Vec<Hex128>],
    arenas_b: &[LongArena],
    hex_b: &[Vec<Hex128>],
) -> bool {
    if a.is_hex() && b.is_hex() {
        a.resolve_hex(hex_a) == b.resolve_hex(hex_b)
    } else if !a.is_ref() && !a.is_hex() && !b.is_ref() && !b.is_hex() {
        a.0 == b.0
    } else if a.is_ref() && b.is_ref() {
        LongArena::resolve_in(arenas_a, a) == LongArena::resolve_in(arenas_b, b)
    } else {
        false
    }
}

struct ClicksDedupOut<E: Copy, C: Copy> {
    pe_slabs: Vec<SlabArena>,
    cl_slabs: Vec<SlabArena>,
    person_event_chunks: Vec<Vec<MutChunkRef<E>>>,
    person_event_counts: Vec<usize>,
    person_click_chunks: Vec<Vec<MutChunkRef<C>>>,
    person_click_counts: Vec<usize>,
    cl_worker_arenas: Vec<LongArena>,
    cl_worker_hex: Vec<Vec<Hex128>>,
    cl_worker_ext: Vec<Vec<ExtClick>>,
}

const LINK_PENDING: usize = 32;

#[inline(always)]
fn flush_cl_pending<C: ClickEmit>(
    n: usize,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h42: &[u64; LINK_PENDING],
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
    link_map: &LinkMap,
    wid: usize,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>,
) {
    let mut nh = 0usize;
    let mut nm = 0usize;
    for j in 0..n {
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let hit = link_map.bloom_may_contain_b37(h42);
        unsafe {
            *hit_idxs.get_unchecked_mut(nh) = j as u8;
            *miss_idxs.get_unchecked_mut(nm) = j as u8;
        }
        nh += hit as usize;
        nm += (!hit) as usize;
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        link_map.prefetch_slot_b37(unsafe { *pending_h42.get_unchecked(j) });
    }
    for k in 0..nm {
        let j = unsafe { *miss_idxs.get_unchecked(k) } as usize;
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
        cl_buckets.push(pshard, unsafe { *pending_cl.get_unchecked(j) });
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let mut item = unsafe { *pending_cl.get_unchecked(j) };
        let pshard = if let Some(canon) = link_map.probe_b37(h42) {
            item.apply_canon(canon, wid, cl_ext_out);
            pshard_for_person_key(canon, &[])
        } else {
            ((h42 >> 34) as usize) & (P_PERSON - 1)
        };
        cl_buckets.push(pshard, item);
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn flush_cl_hex_pending<C: ClickEmit>(
    n: usize,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h64: &[u64; LINK_PENDING],
    pending_hex: &[Hex128; LINK_PENDING],
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
    link_map: &LinkMap,
    wid: usize,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>,
) {
    let mut nh = 0usize;
    let mut nm = 0usize;
    for j in 0..n {
        let h64 = unsafe { *pending_h64.get_unchecked(j) };
        let hit = link_map.bloom_may_contain_hex(h64);
        unsafe {
            *hit_idxs.get_unchecked_mut(nh) = j as u8;
            *miss_idxs.get_unchecked_mut(nm) = j as u8;
        }
        nh += hit as usize;
        nm += (!hit) as usize;
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        link_map.prefetch_slot_hex(unsafe { *pending_h64.get_unchecked(j) });
    }
    for k in 0..nm {
        let j = unsafe { *miss_idxs.get_unchecked(k) } as usize;
        let h64 = unsafe { *pending_h64.get_unchecked(j) };
        let pshard = (h64 as usize) & (P_PERSON - 1);
        cl_buckets.push(pshard, unsafe { *pending_cl.get_unchecked(j) });
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        let h64 = unsafe { *pending_h64.get_unchecked(j) };
        let hx = unsafe { *pending_hex.get_unchecked(j) };
        let mut item = unsafe { *pending_cl.get_unchecked(j) };
        let pshard = if let Some(canon) = link_map.probe_hex(h64, hx) {
            item.apply_canon(canon, wid, cl_ext_out);
            pshard_for_person_key(canon, &[])
        } else {
            (h64 as usize) & (P_PERSON - 1)
        };
        cl_buckets.push(pshard, item);
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn flush_dedup_pending<E: DedupEmit, const PD: bool>(
    n: usize,
    pending_ev: &mut [E; LINK_PENDING],
    pending_h42: &[u64; LINK_PENDING],
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
    link_map: &LinkMap,
    person_out: &mut SlabBuckets<E, P_PERSON, PE_CHUNK_LEN, PERSON_SWCB_W>,
    mc: &mut P2Micro,
) {
    let c0 = if PD { rdtsc_now() } else { 0 };
    let mut nh = 0usize;
    let mut nm = 0usize;
    for j in 0..n {
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let hit = link_map.bloom_may_contain_b37(h42);
        unsafe {
            *hit_idxs.get_unchecked_mut(nh) = j as u8;
            *miss_idxs.get_unchecked_mut(nm) = j as u8;
        }
        nh += hit as usize;
        nm += (!hit) as usize;
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        link_map.prefetch_slot_b37(unsafe { *pending_h42.get_unchecked(j) });
    }
    let c1 = if PD { rdtsc_now() } else { 0 };
    if PD {
        mc.bloom_cyc += c1.wrapping_sub(c0);
        mc.b37_bloom_hits += nh as u64;
        mc.b37_misses += nm as u64;
    }
    for k in 0..nm {
        let j = unsafe { *miss_idxs.get_unchecked(k) } as usize;
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
        person_out.push(pshard, unsafe { *pending_ev.get_unchecked(j) });
    }
    let c2 = if PD { rdtsc_now() } else { 0 };
    if PD {
        mc.push_cyc += c2.wrapping_sub(c1);
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let mut item = unsafe { *pending_ev.get_unchecked(j) };
        let pshard = if let Some(canon) = link_map.probe_b37(h42) {
            if PD {
                mc.b37_slot_hits += 1;
            }
            item.apply_canon(canon);
            pshard_for_person_key(canon, &[])
        } else {
            ((h42 >> 34) as usize) & (P_PERSON - 1)
        };
        person_out.push(pshard, item);
    }
    if PD {
        mc.probe_cyc += rdtsc_now().wrapping_sub(c2);
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn flush_dedup_hex_pending<E: DedupEmit, const PD: bool>(
    n: usize,
    pending_ev: &mut [E; LINK_PENDING],
    pending_pk: &[CompactKey64; LINK_PENDING],
    ev_worker_hex: &[Vec<Hex128>],
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
    link_map: &LinkMap,
    person_out: &mut SlabBuckets<E, P_PERSON, PE_CHUNK_LEN, PERSON_SWCB_W>,
    mc: &mut P2Micro,
) {
    let c0 = if PD { rdtsc_now() } else { 0 };
    let mut vals = [Hex128::default(); LINK_PENDING];
    let mut h64s = [0u64; LINK_PENDING];
    for j in 0..n {
        let pk = unsafe { *pending_pk.get_unchecked(j) };
        let hx = pk.resolve_hex(ev_worker_hex);
        let h64 = hash_hex128(hx);
        unsafe {
            *vals.get_unchecked_mut(j) = hx;
            *h64s.get_unchecked_mut(j) = h64;
        }
        link_map.prefetch_bloom_hex(h64);
    }
    let mut nh = 0usize;
    let mut nm = 0usize;
    for j in 0..n {
        let h64 = unsafe { *h64s.get_unchecked(j) };
        let hit = link_map.bloom_may_contain_hex(h64);
        unsafe {
            *hit_idxs.get_unchecked_mut(nh) = j as u8;
            *miss_idxs.get_unchecked_mut(nm) = j as u8;
        }
        nh += hit as usize;
        nm += (!hit) as usize;
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        link_map.prefetch_slot_hex(unsafe { *h64s.get_unchecked(j) });
    }
    for k in 0..nm {
        let j = unsafe { *miss_idxs.get_unchecked(k) } as usize;
        let h64 = unsafe { *h64s.get_unchecked(j) };
        let pk = unsafe { *pending_pk.get_unchecked(j) };
        let mut item = unsafe { *pending_ev.get_unchecked(j) };
        item.apply_canon(CompactKey64::from_hex(
            pk.hex_wid(),
            pk.hex_idx(),
            false,
            (h64 & 0xF_FFFF) as u32,
        ));
        let pshard = (h64 as usize) & (P_PERSON - 1);
        person_out.push(pshard, item);
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        let h64 = unsafe { *h64s.get_unchecked(j) };
        let hx = unsafe { *vals.get_unchecked(j) };
        let pk = unsafe { *pending_pk.get_unchecked(j) };
        let mut item = unsafe { *pending_ev.get_unchecked(j) };
        let pshard = if let Some(canon) = link_map.probe_hex(h64, hx) {
            if PD {
                mc.hex_slot_hits += 1;
            }
            item.apply_canon(canon);
            pshard_for_person_key(canon, &[])
        } else {
            item.apply_canon(CompactKey64::from_hex(
                pk.hex_wid(),
                pk.hex_idx(),
                false,
                (h64 & 0xF_FFFF) as u32,
            ));
            (h64 as usize) & (P_PERSON - 1)
        };
        person_out.push(pshard, item);
    }
    if PD {
        mc.hex_cyc += rdtsc_now().wrapping_sub(c0);
        mc.hex_bloom_hits += nh as u64;
        mc.hex_misses += nm as u64;
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn emit_cl_non_b37<C: ClickEmit>(
    padded: &[u8],
    cl_s: usize,
    cl_len: usize,
    cl_e: usize,
    u_s: usize,
    u_len: usize,
    u_e: usize,
    cid: u32,
    ts_ms: i64,
    link_map: &LinkMap,
    lm_empty: bool,
    wid: usize,
    click_window_start_ms: i64,
    cl_arena_out: &mut LongArena,
    cl_hex_out: &mut Vec<Hex128>,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h42: &mut [u64; LINK_PENDING],
    n_pending: &mut usize,
    pending_cl_hex: &mut [C; LINK_PENDING],
    pending_cl_hex_h64: &mut [u64; LINK_PENDING],
    pending_cl_hex_val: &mut [Hex128; LINK_PENDING],
    n_hex_pending: &mut usize,
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
) {
    let click_id_key = if let Some(k_b37) = encode_b37_padded(padded, cl_s, cl_len, b'k') {
        CompactKey64::from_kb37(k_b37)
    } else if let Some(hx_k) = encode_hex32_padded(padded, cl_s, cl_len, b'k') {
        let h20 = (hash_hex128(hx_k) & 0xF_FFFF) as u32;
        let idx = cl_hex_out.len();
        cl_hex_out.push(hx_k);
        CompactKey64::from_hex(wid, idx, true, h20)
    } else if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, cl_s, cl_len) {
        k
    } else {
        let click_id = unsafe { padded.get_unchecked(cl_s..cl_e) };
        cl_arena_out.push_ref(wid, click_id)
    };

    if let Some(u_b37) = encode_b37_padded(padded, u_s, u_len, b'u') {
        let h42 = biject42(u_b37);
        let item = C::make_direct(
            wid,
            cl_ext_out,
            CompactKey64::from_uh42(h42),
            click_id_key,
            ts_ms,
            click_window_start_ms,
            cid,
        );
        if lm_empty {
            let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
            cl_buckets.push(pshard, item);
        } else {
            link_map.prefetch_bloom_b37(h42);
            let np = *n_pending;
            unsafe {
                *pending_cl.get_unchecked_mut(np) = item;
                *pending_h42.get_unchecked_mut(np) = h42;
            }
            let next_np = np + 1;
            if next_np == LINK_PENDING {
                flush_cl_pending(
                    LINK_PENDING,
                    pending_cl,
                    pending_h42,
                    hit_idxs,
                    miss_idxs,
                    link_map,
                    wid,
                    cl_ext_out,
                    cl_buckets,
                );
                *n_pending = 0;
            } else {
                *n_pending = next_np;
            }
        }
        return;
    }

    if let Some(hx_u) = encode_hex32_padded(padded, u_s, u_len, b'u') {
        let h64 = hash_hex128(hx_u);
        let uidx = cl_hex_out.len();
        cl_hex_out.push(hx_u);
        let pk = CompactKey64::from_hex(wid, uidx, false, (h64 & 0xF_FFFF) as u32);
        let item = C::make_direct(
            wid,
            cl_ext_out,
            pk,
            click_id_key,
            ts_ms,
            click_window_start_ms,
            cid,
        );
        if lm_empty {
            let pshard = (h64 as usize) & (P_PERSON - 1);
            cl_buckets.push(pshard, item);
        } else {
            link_map.prefetch_bloom_hex(h64);
            let nhp = *n_hex_pending;
            unsafe {
                *pending_cl_hex.get_unchecked_mut(nhp) = item;
                *pending_cl_hex_h64.get_unchecked_mut(nhp) = h64;
                *pending_cl_hex_val.get_unchecked_mut(nhp) = hx_u;
            }
            let next_nhp = nhp + 1;
            if next_nhp == LINK_PENDING {
                flush_cl_hex_pending(
                    LINK_PENDING,
                    pending_cl_hex,
                    pending_cl_hex_h64,
                    pending_cl_hex_val,
                    hit_idxs,
                    miss_idxs,
                    link_map,
                    wid,
                    cl_ext_out,
                    cl_buckets,
                );
                *n_hex_pending = 0;
            } else {
                *n_hex_pending = next_nhp;
            }
        }
        return;
    }

    let (person_key, pshard) =
        if let Some(uk) = CompactKey64::encode_raw_inline_padded(padded, u_s, u_len) {
            if !lm_empty {
                if let Some(canon) = link_map.resolve_other_inline(uk) {
                    (canon, pshard_for_person_key(canon, &[]))
                } else {
                    (uk, ((mix64(uk.0) >> 52) as usize) & (P_PERSON - 1))
                }
            } else {
                (uk, ((mix64(uk.0) >> 52) as usize) & (P_PERSON - 1))
            }
        } else {
            let uid = unsafe { padded.get_unchecked(u_s..u_e) };
            if !lm_empty {
                if let Some(canon) = link_map.resolve_long(uid) {
                    (canon, pshard_for_person_key(canon, &[]))
                } else {
                    let pk = cl_arena_out.push_ref(wid, uid);
                    (pk, ((hash_bytes_fast(uid) >> 52) as usize) & (P_PERSON - 1))
                }
            } else {
                let pk = cl_arena_out.push_ref(wid, uid);
                (pk, ((hash_bytes_fast(uid) >> 52) as usize) & (P_PERSON - 1))
            }
        };

    let pc = C::make_direct(
        wid,
        cl_ext_out,
        person_key,
        click_id_key,
        ts_ms,
        click_window_start_ms,
        cid,
    );
    cl_buckets.push(pshard, pc);
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn process_cl_line<C: ClickEmit, const TS_KIND: u8>(
    padded: &[u8],
    base: *const u8,
    cm_ptr: *const u32,
    dl: &DirectLineRef,
    ts_s: usize,
    ts_len: usize,
    dcache: &mut DateCache,
    lookups: &Lookups,
    link_map: &LinkMap,
    lm_empty: bool,
    wid: usize,
    click_window_start_ms: i64,
    window_end_ms: i64,
    cl_arena_out: &mut LongArena,
    cl_hex_out: &mut Vec<Hex128>,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h42: &mut [u64; LINK_PENDING],
    n_pending: &mut usize,
    pending_cl_hex: &mut [C; LINK_PENDING],
    pending_cl_hex_h64: &mut [u64; LINK_PENDING],
    pending_cl_hex_val: &mut [Hex128; LINK_PENDING],
    n_hex_pending: &mut usize,
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
) {
    let ls = dl.ls as usize;
    let cm = unsafe { cm_ptr.add(dl.cm_off as usize) };
    let c0 = unsafe { *cm } as usize;
    let c1 = unsafe { *cm.add(1) } as usize;
    let c2 = unsafe { *cm.add(2) } as usize;

    let (cl_s, cl_e) = unsafe { field_span(base, ls, c0) };
    let cl_len = cl_e - cl_s;
    let (u_s, u_e) = unsafe { field_span(base, c0 + 1, c1) };
    let u_len = u_e - u_s;
    if cl_len == 0 || u_len == 0 {
        return;
    }
    let (c_s, c_e) = unsafe { field_span(base, c1 + 1, c2) };
    let Some(cid) = lookups.get_campaign_padded(padded, c_s, c_e - c_s) else {
        return;
    };
    let parsed_ts = match TS_KIND {
        0 => dcache.parse_f1_only_padded_hint::<false>(padded, ts_s, 0, 0, 0),
        1 => DateCache::parse_f3_only_13_padded(padded, ts_s),
        _ => dcache.parse_other_ts_padded_hint::<false, false>(padded, ts_s, ts_len, 0, 0, 0),
    };
    let Some((ts_ms, _)) = parsed_ts else {
        return;
    };
    if ts_ms < click_window_start_ms || ts_ms >= window_end_ms {
        return;
    }

    if (cl_len.wrapping_sub(2) <= 7) & (u_len.wrapping_sub(2) <= 7) {
        if let Some((k_b37, u_b37)) =
            encode_b37_pair_padded(padded, cl_s, cl_len, b'k', u_s, u_len, b'u')
        {
            let h42 = biject42(u_b37);
            let item = C::make_b37_pending(h42, k_b37, ts_ms, click_window_start_ms, cid);
            if lm_empty {
                let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
                cl_buckets.push(pshard, item);
            } else {
                link_map.prefetch_bloom_b37(h42);
                let np = *n_pending;
                unsafe {
                    *pending_cl.get_unchecked_mut(np) = item;
                    *pending_h42.get_unchecked_mut(np) = h42;
                }
                let next_np = np + 1;
                if next_np == LINK_PENDING {
                    flush_cl_pending(
                        LINK_PENDING,
                        pending_cl,
                        pending_h42,
                        hit_idxs,
                        miss_idxs,
                        link_map,
                        wid,
                        cl_ext_out,
                        cl_buckets,
                    );
                    *n_pending = 0;
                } else {
                    *n_pending = next_np;
                }
            }
            return;
        }
    }

    emit_cl_non_b37::<C>(
        padded,
        cl_s,
        cl_len,
        cl_e,
        u_s,
        u_len,
        u_e,
        cid,
        ts_ms,
        link_map,
        lm_empty,
        wid,
        click_window_start_ms,
        cl_arena_out,
        cl_hex_out,
        cl_ext_out,
        cl_buckets,
        pending_cl,
        pending_h42,
        n_pending,
        pending_cl_hex,
        pending_cl_hex_h64,
        pending_cl_hex_val,
        n_hex_pending,
        hit_idxs,
        miss_idxs,
    );
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn process_cl_batch_direct<C: ClickEmit>(
    padded: &[u8],
    cm_buf: &[u32],
    lines: &[DirectLineRef],
    dcache: &mut DateCache,
    lookups: &Lookups,
    link_map: &LinkMap,
    lm_empty: bool,
    wid: usize,
    click_window_start_ms: i64,
    window_end_ms: i64,
    cl_arena_out: &mut LongArena,
    cl_hex_out: &mut Vec<Hex128>,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h42: &mut [u64; LINK_PENDING],
    n_pending: &mut usize,
    pending_cl_hex: &mut [C; LINK_PENDING],
    pending_cl_hex_h64: &mut [u64; LINK_PENDING],
    pending_cl_hex_val: &mut [Hex128; LINK_PENDING],
    n_hex_pending: &mut usize,
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
) {
    debug_assert!(lines.len() <= 64);
    let base = padded.as_ptr();
    let cm_ptr = cm_buf.as_ptr();
    let mut f1_idxs = [0u8; 64];
    let mut f3_idxs = [0u8; 64];
    let mut oth_idxs = [0u8; 64];
    let mut ts_starts = [0u32; 64];
    let mut ts_lens = [0u32; 64];
    let mut nf1 = 0usize;
    let mut nf3 = 0usize;
    let mut noth = 0usize;
    for (i, dl) in lines.iter().enumerate() {
        let c2 = unsafe { *cm_ptr.add(dl.cm_off as usize + 2) } as usize;
        let le = dl.le as usize;
        let (ts_s, ts_e) = unsafe { field_span(base, c2 + 1, le) };
        let ts_len = ts_e - ts_s;
        unsafe {
            *ts_starts.get_unchecked_mut(i) = ts_s as u32;
            *ts_lens.get_unchecked_mut(i) = ts_len as u32;
        }
        let is_f1 = ts_len == 20;
        let is_f3 = ts_len == 13;
        unsafe {
            *f1_idxs.get_unchecked_mut(nf1) = i as u8;
            *f3_idxs.get_unchecked_mut(nf3) = i as u8;
            *oth_idxs.get_unchecked_mut(noth) = i as u8;
        }
        nf1 += is_f1 as usize;
        nf3 += is_f3 as usize;
        noth += (!(is_f1 | is_f3)) as usize;
    }

    for &idx in &f1_idxs[..nf1] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_cl_line::<C, 0>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            link_map,
            lm_empty,
            wid,
            click_window_start_ms,
            window_end_ms,
            cl_arena_out,
            cl_hex_out,
            cl_ext_out,
            cl_buckets,
            pending_cl,
            pending_h42,
            n_pending,
            pending_cl_hex,
            pending_cl_hex_h64,
            pending_cl_hex_val,
            n_hex_pending,
            hit_idxs,
            miss_idxs,
        );
    }
    for &idx in &f3_idxs[..nf3] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_cl_line::<C, 1>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            link_map,
            lm_empty,
            wid,
            click_window_start_ms,
            window_end_ms,
            cl_arena_out,
            cl_hex_out,
            cl_ext_out,
            cl_buckets,
            pending_cl,
            pending_h42,
            n_pending,
            pending_cl_hex,
            pending_cl_hex_h64,
            pending_cl_hex_val,
            n_hex_pending,
            hit_idxs,
            miss_idxs,
        );
    }
    for &idx in &oth_idxs[..noth] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_cl_line::<C, 2>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            link_map,
            lm_empty,
            wid,
            click_window_start_ms,
            window_end_ms,
            cl_arena_out,
            cl_hex_out,
            cl_ext_out,
            cl_buckets,
            pending_cl,
            pending_h42,
            n_pending,
            pending_cl_hex,
            pending_cl_hex_h64,
            pending_cl_hex_val,
            n_hex_pending,
            hit_idxs,
            miss_idxs,
        );
    }
}

#[inline(always)]
unsafe fn make_dedup_probe_u32(
    w0: u64,
    cap: usize,
    dedup_u32_ptr: *const u32,
) -> DedupProbeU32 {
    if w0 < PE_DEAD {
        let ev_rem = w0 & PE_EV_REM_MASK;
        let slot = fast_range32(ev_rem, cap);
        #[cfg(target_arch = "x86_64")]
        std::arch::x86_64::_mm_prefetch(
            dedup_u32_ptr.add(slot) as *const i8,
            std::arch::x86_64::_MM_HINT_T0,
        );
        DedupProbeU32 {
            tag12: ((ev_rem as u32) & 0xFFF) << 20,
            slot: slot as u32,
        }
    } else {
        DedupProbeU32 {
            tag12: 0,
            slot: u32::MAX,
        }
    }
}

#[inline(always)]
unsafe fn make_hx_probe_u32(
    ev_hi: u64,
    ev_lo: u64,
    cap: usize,
    dedup_u32_ptr: *const u32,
) -> DedupProbeU32 {
    let eh = hash_hex128(Hex128 { hi: ev_hi, lo: ev_lo });
    let slot = fast_range32(eh, cap);
    #[cfg(target_arch = "x86_64")]
    std::arch::x86_64::_mm_prefetch(
        dedup_u32_ptr.add(slot) as *const i8,
        std::arch::x86_64::_MM_HINT_T0,
    );
    DedupProbeU32 {
        tag12: (((eh >> 46) as u32) & 0xFFF) << 20,
        slot: slot as u32,
    }
}

#[inline(always)]
fn wide_dedup_hash(ev: &ParsedEvent16, ev_worker_arenas: &[LongArena]) -> u64 {
    hash_raw_key(CompactKey64(ev.w1), ev_worker_arenas, &[])
}

#[inline(always)]
fn wide_dedup_eq(a: &ParsedEvent16, b: &ParsedEvent16, ev_worker_arenas: &[LongArena]) -> bool {
    eq_raw_keys(
        CompactKey64(a.w1),
        CompactKey64(b.w1),
        ev_worker_arenas,
        &[],
        ev_worker_arenas,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn run_clicks_and_dedup<
    E: DedupEmit,
    C: ClickEmit,
    const PD: bool,
>(
    dedup_slots: &[Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>],
    hex_dedup_slots: &[Mutex<Option<Vec<MutChunkRef<HexEvent32>>>>],
    ev_worker_ext: &[Vec<ExtEvent>],
    ev_worker_arenas: &[LongArena],
    ev_worker_hex: &[Vec<Hex128>],
    click_src: &CsvSource,
    cl_chunks: &[crate::csv::ChunkTask],
    cl_hint_bytes: usize,
    pe_hint_bytes: usize,
    lookups: &Lookups,
    link_map: &LinkMap,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    click_window_start_ms: i64,
    ncpu: usize,
    detail: &DetailStats,
) -> io::Result<ClicksDedupOut<E, C>> {
    const RING: usize = 16;

    let n_workers = ncpu.clamp(1, 63);
    let lm_empty = link_map.is_empty();
    let next_cl = AtomicUsize::new(0);
    let next_d_shard = AtomicUsize::new(0);
    let next_hx_shard = AtomicUsize::new(0);

    let mut cl_worker_slabs: Vec<Option<SlabArena>> = (0..n_workers).map(|_| None).collect();
    let mut cl_worker_chunks: Vec<Vec<Vec<MutChunkRef<C>>>> =
        (0..n_workers).map(|_| Vec::new()).collect();
    let mut cl_worker_arenas: Vec<LongArena> = (0..n_workers).map(|_| LongArena::default()).collect();
    let mut cl_worker_hex: Vec<Vec<Hex128>> = (0..n_workers).map(|_| Vec::new()).collect();
    let mut cl_worker_ext: Vec<Vec<ExtClick>> = (0..n_workers).map(|_| Vec::new()).collect();

    let mut pe_worker_slabs: Vec<Option<SlabArena>> = (0..n_workers).map(|_| None).collect();
    let mut dedup_worker_chunks: Vec<Vec<Vec<MutChunkRef<E>>>> =
        (0..n_workers).map(|_| Vec::new()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..n_workers).map(|_| None).collect();

    std::thread::scope(|scope| {
        for (
            wid,
            (
                ((((cl_slab_slot, cl_chunks_slot), (cl_arena_out, cl_hex_out)), cl_ext_out),
                (pe_slab_slot, ev_out_slot)),
                err_out,
            ),
        ) in cl_worker_slabs
            .iter_mut()
            .zip(cl_worker_chunks.iter_mut())
            .zip(cl_worker_arenas.iter_mut().zip(cl_worker_hex.iter_mut()))
            .zip(cl_worker_ext.iter_mut())
            .zip(
                pe_worker_slabs
                    .iter_mut()
                    .zip(dedup_worker_chunks.iter_mut()),
            )
            .zip(worker_errs.iter_mut())
            .enumerate()
        {
            let next_cl_ref = &next_cl;
            let next_d_ref = &next_d_shard;
            let next_hx_ref = &next_hx_shard;
            scope.spawn(move || {
                let mut hit_idxs = [0u8; LINK_PENDING];
                let mut miss_idxs = [0u8; LINK_PENDING];

                // Phase A: Parse clicks into SlabBuckets<C, P_PERSON, CL_CHUNK_LEN>.
                let t_cl = if PD { Some(Instant::now()) } else { None };
                let mut buf = Vec::new();
                if !cl_chunks.is_empty() {
                    let first = next_cl_ref.fetch_add(1, Ordering::Relaxed);
                    if first < cl_chunks.len() {
                        let mut dcache =
                            DateCache::new_for_window(click_window_start_ms, window_end_ms);
                        let mut cl_buckets =
                            SlabBuckets::<C, P_PERSON, CL_CHUNK_LEN, PERSON_SWCB_W>::new(cl_hint_bytes);
                        let tmpl =
                            C::make_b37_pending(0, 0, click_window_start_ms, click_window_start_ms, 0);
                        let mut pending_cl = [tmpl; LINK_PENDING];
                        let mut pending_h42 = [0u64; LINK_PENDING];
                        let mut n_pending = 0usize;
                        let mut pending_cl_hex = [tmpl; LINK_PENDING];
                        let mut pending_cl_hex_h64 = [0u64; LINK_PENDING];
                        let mut pending_cl_hex_val = [Hex128::default(); LINK_PENDING];
                        let mut n_hex_pending = 0usize;

                        let mut cidx = first;
                        while let Some(&task) = cl_chunks.get(cidx) {
                            if let Err(e) = click_src.for_each_chunk_direct_batched::<4>(
                                task,
                                &mut buf,
                                |padded, cm_buf, lines| {
                                    process_cl_batch_direct::<C>(
                                        padded,
                                        cm_buf,
                                        lines,
                                        &mut dcache,
                                        lookups,
                                        link_map,
                                        lm_empty,
                                        wid,
                                        click_window_start_ms,
                                        window_end_ms,
                                        cl_arena_out,
                                        cl_hex_out,
                                        cl_ext_out,
                                        &mut cl_buckets,
                                        &mut pending_cl,
                                        &mut pending_h42,
                                        &mut n_pending,
                                        &mut pending_cl_hex,
                                        &mut pending_cl_hex_h64,
                                        &mut pending_cl_hex_val,
                                        &mut n_hex_pending,
                                        &mut hit_idxs,
                                        &mut miss_idxs,
                                    );
                                },
                            ) {
                                *err_out = Some(e);
                                return;
                            }
                            cidx = next_cl_ref.fetch_add(1, Ordering::Relaxed);
                        }
                        if n_pending > 0 {
                            flush_cl_pending(
                                n_pending,
                                &mut pending_cl,
                                &pending_h42,
                                &mut hit_idxs,
                                &mut miss_idxs,
                                link_map,
                                wid,
                                cl_ext_out,
                                &mut cl_buckets,
                            );
                        }
                        if n_hex_pending > 0 {
                            flush_cl_hex_pending(
                                n_hex_pending,
                                &mut pending_cl_hex,
                                &pending_cl_hex_h64,
                                &pending_cl_hex_val,
                                &mut hit_idxs,
                                &mut miss_idxs,
                                link_map,
                                wid,
                                cl_ext_out,
                                &mut cl_buckets,
                            );
                        }
                        let (cl_slab, cl_done) = cl_buckets.finish();
                        *cl_slab_slot = Some(cl_slab);
                        *cl_chunks_slot = cl_done;
                    }
                }
                drop(buf);
                if let Some(t) = t_cl {
                    detail
                        .cl_ns
                        .fetch_add(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
                }

                // Phase B (ZERO barrier): pull P_DEDUP shards & emit into SlabBuckets<E, P_PERSON, PE_CHUNK_LEN, PERSON_SWCB_W>.
                let mut person_out: Option<SlabBuckets<E, P_PERSON, PE_CHUNK_LEN, PERSON_SWCB_W>> = None;
                let mut dedup_u32: Vec<u32> = Vec::new();
                let mut dedup_keys: Vec<u64> = Vec::new();
                let mut dedup_idxs: Vec<u32> = Vec::new();
                let mut gen_table: Option<HashTable<u32>> = None;
                let mut ring_u32 = [DedupProbeU32 {
                    tag12: 0,
                    slot: u32::MAX,
                }; RING];
                let mut ring_wide = [0usize; RING];

                let mut pending_ev = [E::empty_tmpl(); LINK_PENDING];
                let mut pending_h42 = [0u64; LINK_PENDING];
                let mut pending_ev_hex = [E::empty_tmpl(); LINK_PENDING];
                let mut pending_ev_hex_pk = [CompactKey64::EMPTY; LINK_PENDING];
                let mut p1_ns = 0u64;
                let mut p2_ns = 0u64;
                let mut p2_unpack_ns = 0u64;
                let mut p2_bloom_ns = 0u64;
                let mut p2_probe_ns = 0u64;
                let mut p2_push_ns = 0u64;
                let mut p2_hex_ns = 0u64;
                let mut p2_counts = P2Micro::default();

                loop {
                    let ds = next_d_ref.fetch_add(1, Ordering::Relaxed);
                    if ds >= P_DEDUP {
                        break;
                    }
                    let Some(shard_chunks) = dedup_slots[ds].lock().unwrap().take() else {
                        continue;
                    };
                    let total: usize = shard_chunks.iter().map(|c| c.len).sum();
                    if total == 0 {
                        continue;
                    }
                    let t_p1 = if PD { Some(Instant::now()) } else { None };
                    let buckets_out =
                        person_out.get_or_insert_with(|| SlabBuckets::new(pe_hint_bytes));
                    if let Some(gt) = &mut gen_table {
                        gt.clear();
                    }

                    let n_chunks = shard_chunks.len();
                    if n_chunks <= MAX_DEDUP_U32_CHUNKS {
                        let cap = (total * 2).max(16);
                        dedup_u32.clear();
                        dedup_u32.resize(cap, 0u32);
                        let dedup_u32_ptr = dedup_u32.as_ptr();

                        for cidx in 0..n_chunks {
                            let c_len = shard_chunks[cidx].len;
                            let c_ptr = shard_chunks[cidx].ptr;
                            let cbase = (cidx as u32) << EV_CHUNK_SHIFT;
                            let pre = c_len.min(RING);
                            for i in 0..pre {
                                let w0 = unsafe { (*c_ptr.add(i)).w0 };
                                ring_u32[i] =
                                    unsafe { make_dedup_probe_u32(w0, cap, dedup_u32_ptr) };
                            }

                            for ridx in 0..c_len {
                                let prb = ring_u32[ridx & (RING - 1)];
                                if ridx + RING < c_len {
                                    let w0_a = unsafe { (*c_ptr.add(ridx + RING)).w0 };
                                    ring_u32[ridx & (RING - 1)] =
                                        unsafe { make_dedup_probe_u32(w0_a, cap, dedup_u32_ptr) };
                                }

                                let ev = unsafe { *c_ptr.add(ridx) };
                                if prb.slot != u32::MAX {
                                    let ev_rem = ev.w0 & PE_EV_REM_MASK;
                                    let mut slot = prb.slot as usize;
                                    loop {
                                        let entry = unsafe { *dedup_u32.get_unchecked(slot) };
                                        if entry == 0 {
                                            unsafe {
                                                *dedup_u32.get_unchecked_mut(slot) =
                                                    prb.tag12 | (cbase + (ridx as u32) + 1);
                                            }
                                            break;
                                        }
                                        if (entry & 0xFFF0_0000) == prb.tag12 {
                                            let prev_packed = (entry & 0x000F_FFFF) - 1;
                                            let pc = (prev_packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (prev_packed & EV_CHUNK_MASK) as usize;
                                            let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                            let prev_ev = unsafe { *prev_ptr };
                                            if (prev_ev.w0 & PE_EV_REM_MASK) == ev_rem {
                                                let ev_ing = ev16_ingest_ts(
                                                    &ev,
                                                    window_start_sec,
                                                    ev_worker_ext,
                                                );
                                                let cur_ing = ev16_ingest_ts(
                                                    &prev_ev,
                                                    window_start_sec,
                                                    ev_worker_ext,
                                                );
                                                unsafe {
                                                    if ev_ing < cur_ing {
                                                        *prev_ptr = ev;
                                                    }
                                                    (*c_ptr.add(ridx)).w0 = PE_DEAD;
                                                }
                                                break;
                                            }
                                        }
                                        slot += 1;
                                        if slot == cap {
                                            slot = 0;
                                        }
                                    }
                                } else {
                                    let gt = gen_table.get_or_insert_with(HashTable::new);
                                    let ev_key = CompactKey64(ev.w1);
                                    let eh = hash_raw_key(ev_key, ev_worker_arenas, &[]);
                                    match gt.entry(
                                        eh,
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_k = CompactKey64(unsafe {
                                                (*shard_chunks[pc].ptr.add(pr)).w1
                                            });
                                            eq_raw_keys(
                                                prev_k,
                                                ev_key,
                                                ev_worker_arenas,
                                                &[],
                                                ev_worker_arenas,
                                                &[],
                                            )
                                        },
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_k = CompactKey64(unsafe {
                                                (*shard_chunks[pc].ptr.add(pr)).w1
                                            });
                                            hash_raw_key(prev_k, ev_worker_arenas, &[])
                                        },
                                    ) {
                                        hashbrown::hash_table::Entry::Occupied(occ) => {
                                            let packed = *occ.get();
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                            let ev_ing = ev16_ingest_ts(
                                                &ev,
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            let cur_ing = ev16_ingest_ts(
                                                unsafe { &*prev_ptr },
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            unsafe {
                                                if ev_ing < cur_ing {
                                                    *prev_ptr = ev;
                                                }
                                                (*c_ptr.add(ridx)).w0 = PE_DEAD;
                                            }
                                        }
                                        hashbrown::hash_table::Entry::Vacant(vac) => {
                                            vac.insert(cbase | (ridx as u32));
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        let cap = (total * 10 / 6).max(16).next_power_of_two();
                        let mask = cap - 1;
                        dedup_keys.clear();
                        dedup_keys.resize(cap, 0u64);
                        dedup_idxs.resize(cap, 0u32);

                        for cidx in 0..n_chunks {
                            let c_len = shard_chunks[cidx].len;
                            let c_ptr = shard_chunks[cidx].ptr;
                            let cbase = (cidx as u32) << EV_CHUNK_SHIFT;
                            let pre = c_len.min(RING);
                            for i in 0..pre {
                                let w0 = unsafe { (*c_ptr.add(i)).w0 };
                                ring_wide[i] = if w0 < PE_DEAD {
                                    let ev_rem = w0 & PE_EV_REM_MASK;
                                    let slot = (ev_rem as usize) & mask;
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            dedup_keys.as_ptr().add(slot) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                    slot
                                } else {
                                    usize::MAX
                                };
                            }
                            for ridx in 0..c_len {
                                let pslot = ring_wide[ridx & (RING - 1)];
                                if ridx + RING < c_len {
                                    let w0_a = unsafe { (*c_ptr.add(ridx + RING)).w0 };
                                    ring_wide[ridx & (RING - 1)] = if w0_a < PE_DEAD {
                                        let ev_rem = w0_a & PE_EV_REM_MASK;
                                        let slot = (ev_rem as usize) & mask;
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                dedup_keys.as_ptr().add(slot) as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                        slot
                                    } else {
                                        usize::MAX
                                    };
                                }
                                let ev = unsafe { *c_ptr.add(ridx) };
                                if pslot != usize::MAX {
                                    let ev_key_u = (ev.w0 & PE_EV_REM_MASK) + 1;
                                    let mut slot = pslot;
                                    loop {
                                        let cur = unsafe { *dedup_keys.get_unchecked(slot) };
                                        if cur == ev_key_u {
                                            let packed = unsafe { *dedup_idxs.get_unchecked(slot) };
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                            let ev_ing = ev16_ingest_ts(
                                                &ev,
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            let cur_ing = ev16_ingest_ts(
                                                unsafe { &*prev_ptr },
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            unsafe {
                                                if ev_ing < cur_ing {
                                                    *prev_ptr = ev;
                                                }
                                                (*c_ptr.add(ridx)).w0 = PE_DEAD;
                                            }
                                            break;
                                        }
                                        if cur == 0 {
                                            unsafe {
                                                *dedup_keys.get_unchecked_mut(slot) = ev_key_u;
                                                *dedup_idxs.get_unchecked_mut(slot) =
                                                    cbase | (ridx as u32);
                                            }
                                            break;
                                        }
                                        slot = (slot + 1) & mask;
                                    }
                                } else {
                                    let gt = gen_table.get_or_insert_with(HashTable::new);
                                    let eh = wide_dedup_hash(&ev, ev_worker_arenas);
                                    match gt.entry(
                                        eh,
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev = unsafe { &*shard_chunks[pc].ptr.add(pr) };
                                            wide_dedup_eq(prev, &ev, ev_worker_arenas)
                                        },
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev = unsafe { &*shard_chunks[pc].ptr.add(pr) };
                                            wide_dedup_hash(prev, ev_worker_arenas)
                                        },
                                    ) {
                                        hashbrown::hash_table::Entry::Occupied(occ) => {
                                            let packed = *occ.get();
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                            let ev_ing = ev16_ingest_ts(
                                                &ev,
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            let cur_ing = ev16_ingest_ts(
                                                unsafe { &*prev_ptr },
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            unsafe {
                                                if ev_ing < cur_ing {
                                                    *prev_ptr = ev;
                                                }
                                                (*c_ptr.add(ridx)).w0 = PE_DEAD;
                                            }
                                        }
                                        hashbrown::hash_table::Entry::Vacant(vac) => {
                                            vac.insert(cbase | (ridx as u32));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if let Some(t) = t_p1 {
                        p1_ns += t.elapsed().as_nanos() as u64;
                    }
                    let t_p2 = if PD { Some(Instant::now()) } else { None };
                    let c_p2_0 = if PD { rdtsc_now() } else { 0 };
                    let mut shard_mc = P2Micro::default();

                    // Pass 2: stream survivors through 2-stage batch-32 Bloom+Slot prefetch -> SlabBuckets<E>.
                    let mut n_p2_pending = 0usize;
                    let mut n_p2_hex_pending = 0usize;
                    for chunk in shard_chunks {
                        let slice = unsafe { chunk.as_slice() };
                        let blen = slice.len();
                        for ridx in 0..blen {
                            if ridx + RING < blen {
                                let ev_a = unsafe { *slice.get_unchecked(ridx + RING) };
                                let t_a = (ev_a.w0 >> PE_TAG_SHIFT) as u32;
                                #[cfg(target_arch = "x86_64")]
                                unsafe {
                                    if t_a == 1 {
                                        let wid_a = ((ev_a.w1 >> 36) & 63) as usize;
                                        let idx_a = (ev_a.w1 & 0xF_FFFF_FFFF) as usize;
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_hex
                                                .get_unchecked(wid_a)
                                                .as_ptr()
                                                .add(idx_a)
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    } else if t_a == 2 {
                                        let wid_a = (ev_a.w1 >> 40) as usize;
                                        let idx_a = (ev_a.w1 & PE_EXT_IDX_MASK) as usize;
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_ext
                                                .get_unchecked(wid_a)
                                                .as_ptr()
                                                .add(idx_a)
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    } else if t_a == 6 {
                                        let pay = ev_a.w0 & !PE_TAG_MASK;
                                        let wid_a = (pay >> 40) as usize;
                                        let idx_a = (pay & PE_EXT_IDX_MASK) as usize;
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_ext
                                                .get_unchecked(wid_a)
                                                .as_ptr()
                                                .add(idx_a)
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                }
                            }

                            let ev = unsafe { *slice.get_unchecked(ridx) };
                            let tag = (ev.w0 >> PE_TAG_SHIFT) as u32;
                            if ((0x47u32 >> tag) & 1) == 0 {
                                continue;
                            }
                            if PD {
                                shard_mc.surv_total += 1;
                            }
                            let (item, h42) = if tag == 0 {
                                let ts_rel_u =
                                    ((((ev.w0 >> 35) & 0x1FF) << 22) | (ev.w1 >> 42)) as u32;
                                let h42 = ev.w1 & B37_MASK42;
                                (E::from_fast_ms_b37(h42, ts_rel_u), h42)
                            } else if tag == 1 {
                                let ts_rel_u =
                                    ((((ev.w0 >> 35) & 0x1FF) << 22) | (ev.w1 >> 42)) as u32;
                                let u_wid = ((ev.w1 >> 36) & 63) as usize;
                                let u_idx = (ev.w1 & 0xF_FFFF_FFFF) as usize;
                                let pk = CompactKey64::from_hex(u_wid, u_idx, false, 0);
                                let mut item = E::from_ext_fields(
                                    pk,
                                    window_start_ms + (ts_rel_u as i64),
                                    window_start_ms,
                                    0,
                                    0,
                                );
                                if lm_empty {
                                    let hx = pk.resolve_hex(ev_worker_hex);
                                    let h64 = hash_hex128(hx);
                                    item.apply_canon(CompactKey64::from_hex(
                                        u_wid,
                                        u_idx,
                                        false,
                                        (h64 & 0xF_FFFF) as u32,
                                    ));
                                    let pshard = (h64 as usize) & (P_PERSON - 1);
                                    buckets_out.push(pshard, item);
                                } else {
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_hex
                                                .get_unchecked(u_wid)
                                                .as_ptr()
                                                .add(u_idx)
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                    unsafe {
                                        *pending_ev_hex.get_unchecked_mut(n_p2_hex_pending) = item;
                                        *pending_ev_hex_pk.get_unchecked_mut(n_p2_hex_pending) = pk;
                                    }
                                    n_p2_hex_pending += 1;
                                    if n_p2_hex_pending == LINK_PENDING {
                                        flush_dedup_hex_pending::<E, PD>(
                                            LINK_PENDING,
                                            &mut pending_ev_hex,
                                            &pending_ev_hex_pk,
                                            ev_worker_hex,
                                            &mut hit_idxs,
                                            &mut miss_idxs,
                                            link_map,
                                            buckets_out,
                                            &mut shard_mc,
                                        );
                                        n_p2_hex_pending = 0;
                                    }
                                }
                                continue;
                            } else {
                                let (e_wid, e_idx) = if tag == 2 {
                                    (
                                        (ev.w1 >> 40) as usize,
                                        (ev.w1 & PE_EXT_IDX_MASK) as usize,
                                    )
                                } else {
                                    let payload = ev.w0 & !PE_TAG_MASK;
                                    (
                                        (payload >> 40) as usize,
                                        (payload & PE_EXT_IDX_MASK) as usize,
                                    )
                                };
                                let ex = unsafe {
                                    *ev_worker_ext.get_unchecked(e_wid).get_unchecked(e_idx)
                                };
                                if tag == 6 && ex.cat_id == u32::MAX {
                                    continue;
                                }
                                let person_key = ex.person_key;
                                let ts_ms = ex.ts_ms;
                                let price_cents = ex.price_cents;
                                let cat_id = ex.cat_id;

                                if person_key.is_uh42() {
                                    let h42 = person_key.uh42_val();
                                    (
                                        E::from_ext_fields(
                                            person_key,
                                            ts_ms,
                                            window_start_ms,
                                            price_cents,
                                            cat_id,
                                        ),
                                        h42,
                                    )
                                } else if person_key.is_hex() {
                                    let mut item = E::from_ext_fields(
                                        person_key,
                                        ts_ms,
                                        window_start_ms,
                                        price_cents,
                                        cat_id,
                                    );
                                    if lm_empty {
                                        let hx = person_key.resolve_hex(ev_worker_hex);
                                        let h64 = hash_hex128(hx);
                                        item.apply_canon(CompactKey64::from_hex(
                                            person_key.hex_wid(),
                                            person_key.hex_idx(),
                                            false,
                                            (h64 & 0xF_FFFF) as u32,
                                        ));
                                        let pshard = (h64 as usize) & (P_PERSON - 1);
                                        buckets_out.push(pshard, item);
                                    } else {
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                ev_worker_hex
                                                    .get_unchecked(person_key.hex_wid())
                                                    .as_ptr()
                                                    .add(person_key.hex_idx())
                                                    as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                        unsafe {
                                            *pending_ev_hex.get_unchecked_mut(n_p2_hex_pending) =
                                                item;
                                            *pending_ev_hex_pk
                                                .get_unchecked_mut(n_p2_hex_pending) = person_key;
                                        }
                                        n_p2_hex_pending += 1;
                                        if n_p2_hex_pending == LINK_PENDING {
                                            flush_dedup_hex_pending::<E, PD>(
                                                LINK_PENDING,
                                                &mut pending_ev_hex,
                                                &pending_ev_hex_pk,
                                                ev_worker_hex,
                                                &mut hit_idxs,
                                                &mut miss_idxs,
                                                link_map,
                                                buckets_out,
                                                &mut shard_mc,
                                            );
                                            n_p2_hex_pending = 0;
                                        }
                                    }
                                    continue;
                                } else {
                                    let pk0 = person_key;
                                    let (pk, pshard) = if !lm_empty {
                                        if !pk0.is_ref() {
                                            if let Some(canon) = link_map.resolve_other_inline(pk0)
                                            {
                                                (canon, pshard_for_person_key(canon, &[]))
                                            } else {
                                                (pk0, ((mix64(pk0.0) >> 52) as usize) & (P_PERSON - 1))
                                            }
                                        } else {
                                            let uid = LongArena::resolve_in(ev_worker_arenas, pk0);
                                            if let Some(canon) = link_map.resolve_long(uid) {
                                                (canon, pshard_for_person_key(canon, &[]))
                                            } else {
                                                (
                                                    pk0,
                                                    ((hash_bytes_fast(uid) >> 52) as usize)
                                                        & (P_PERSON - 1),
                                                )
                                            }
                                        }
                                    } else {
                                        (pk0, pshard_for_person_key(pk0, ev_worker_arenas))
                                    };
                                    buckets_out.push(
                                        pshard,
                                        E::from_ext_fields(
                                            pk,
                                            ts_ms,
                                            window_start_ms,
                                            price_cents,
                                            cat_id,
                                        ),
                                    );
                                    continue;
                                }
                            };

                            if lm_empty {
                                let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
                                buckets_out.push(pshard, item);
                            } else {
                                link_map.prefetch_bloom_b37(h42);
                                unsafe {
                                    *pending_ev.get_unchecked_mut(n_p2_pending) = item;
                                    *pending_h42.get_unchecked_mut(n_p2_pending) = h42;
                                }
                                n_p2_pending += 1;
                                if n_p2_pending == LINK_PENDING {
                                    flush_dedup_pending::<E, PD>(
                                        LINK_PENDING,
                                        &mut pending_ev,
                                        &pending_h42,
                                        &mut hit_idxs,
                                        &mut miss_idxs,
                                        link_map,
                                        buckets_out,
                                        &mut shard_mc,
                                    );
                                    n_p2_pending = 0;
                                }
                            }
                        }
                    }
                    if n_p2_pending > 0 {
                        flush_dedup_pending::<E, PD>(
                            n_p2_pending,
                            &mut pending_ev,
                            &pending_h42,
                            &mut hit_idxs,
                            &mut miss_idxs,
                            link_map,
                            buckets_out,
                            &mut shard_mc,
                        );
                    }
                    if n_p2_hex_pending > 0 {
                        flush_dedup_hex_pending::<E, PD>(
                            n_p2_hex_pending,
                            &mut pending_ev_hex,
                            &pending_ev_hex_pk,
                            ev_worker_hex,
                            &mut hit_idxs,
                            &mut miss_idxs,
                            link_map,
                            buckets_out,
                            &mut shard_mc,
                        );
                    }
                    if let Some(t) = t_p2 {
                        let s_ns = t.elapsed().as_nanos() as u64;
                        p2_ns += s_ns;
                        let tot_cyc = rdtsc_now().wrapping_sub(c_p2_0).max(1);
                        let tracked = shard_mc.bloom_cyc
                            + shard_mc.probe_cyc
                            + shard_mc.push_cyc
                            + shard_mc.hex_cyc;
                        let unpack_cyc = tot_cyc.saturating_sub(tracked);
                        let cyc_to_ns = |c: u64| -> u64 {
                            ((s_ns as u128 * c as u128) / tot_cyc as u128) as u64
                        };
                        let u_ns = cyc_to_ns(unpack_cyc);
                        let b_ns = cyc_to_ns(shard_mc.bloom_cyc);
                        let pr_ns = cyc_to_ns(shard_mc.probe_cyc);
                        let pu_ns = cyc_to_ns(shard_mc.push_cyc);
                        p2_unpack_ns += u_ns;
                        p2_bloom_ns += b_ns;
                        p2_probe_ns += pr_ns;
                        p2_push_ns += pu_ns;
                        p2_hex_ns += s_ns.saturating_sub(u_ns + b_ns + pr_ns + pu_ns);
                        p2_counts.b37_bloom_hits += shard_mc.b37_bloom_hits;
                        p2_counts.b37_slot_hits += shard_mc.b37_slot_hits;
                        p2_counts.b37_misses += shard_mc.b37_misses;
                        p2_counts.hex_bloom_hits += shard_mc.hex_bloom_hits;
                        p2_counts.hex_slot_hits += shard_mc.hex_slot_hits;
                        p2_counts.hex_misses += shard_mc.hex_misses;
                        p2_counts.surv_total += shard_mc.surv_total;
                    }
                }

                // Pull P_HEX_DEDUP shards & emit HexEvent32 survivors into SlabBuckets<E>.
                loop {
                    let hs = next_hx_ref.fetch_add(1, Ordering::Relaxed);
                    if hs >= P_HEX_DEDUP {
                        break;
                    }
                    let Some(shard_chunks) = hex_dedup_slots[hs].lock().unwrap().take() else {
                        continue;
                    };
                    let total: usize = shard_chunks.iter().map(|c| c.len).sum();
                    if total == 0 {
                        continue;
                    }
                    let t_p1 = if PD { Some(Instant::now()) } else { None };
                    let buckets_out =
                        person_out.get_or_insert_with(|| SlabBuckets::new(pe_hint_bytes));
                    let n_chunks = shard_chunks.len();
                    if n_chunks <= MAX_HX_U32_CHUNKS {
                        let cap = (total * 2).max(16);
                        dedup_u32.clear();
                        dedup_u32.resize(cap, 0u32);
                        let dedup_u32_ptr = dedup_u32.as_ptr();

                        for cidx in 0..n_chunks {
                            let c_len = shard_chunks[cidx].len;
                            let c_ptr = shard_chunks[cidx].ptr;
                            let cbase = (cidx as u32) << HX_CHUNK_SHIFT;
                            let pre = c_len.min(RING);
                            for i in 0..pre {
                                let hx_i = unsafe { &*c_ptr.add(i) };
                                ring_u32[i] = unsafe {
                                    make_hx_probe_u32(hx_i.ev_hi, hx_i.ev_lo, cap, dedup_u32_ptr)
                                };
                            }
                            for ridx in 0..c_len {
                                let prb = ring_u32[ridx & (RING - 1)];
                                if ridx + RING < c_len {
                                    let hx_a = unsafe { &*c_ptr.add(ridx + RING) };
                                    ring_u32[ridx & (RING - 1)] = unsafe {
                                        make_hx_probe_u32(
                                            hx_a.ev_hi,
                                            hx_a.ev_lo,
                                            cap,
                                            dedup_u32_ptr,
                                        )
                                    };
                                }
                                let hx = unsafe { *c_ptr.add(ridx) };
                                let mut slot = prb.slot as usize;
                                loop {
                                    let entry = unsafe { *dedup_u32.get_unchecked(slot) };
                                    if entry == 0 {
                                        unsafe {
                                            *dedup_u32.get_unchecked_mut(slot) =
                                                prb.tag12 | (cbase + (ridx as u32) + 1);
                                        }
                                        break;
                                    }
                                    if (entry & 0xFFF0_0000) == prb.tag12 {
                                        let prev_packed = (entry & 0x000F_FFFF) - 1;
                                        let pc = (prev_packed >> HX_CHUNK_SHIFT) as usize;
                                        let pr = (prev_packed & HX_CHUNK_MASK) as usize;
                                        let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                        let prev_hx = unsafe { *prev_ptr };
                                        if prev_hx.ev_hi == hx.ev_hi && prev_hx.ev_lo == hx.ev_lo {
                                            let hx_ing = hx32_ingest_ms(
                                                &hx,
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            let cur_ing = hx32_ingest_ms(
                                                &prev_hx,
                                                window_start_sec,
                                                ev_worker_ext,
                                            );
                                            unsafe {
                                                if hx_ing < cur_ing {
                                                    *prev_ptr = hx;
                                                }
                                                (*c_ptr.add(ridx)).ts_rel_ms = HX_TS_DEAD;
                                            }
                                            break;
                                        }
                                    }
                                    slot += 1;
                                    if slot == cap {
                                        slot = 0;
                                    }
                                }
                            }
                        }
                    } else {
                        let gt = gen_table.get_or_insert_with(HashTable::new);
                        gt.clear();
                        for cidx in 0..n_chunks {
                            let c_len = shard_chunks[cidx].len;
                            let c_ptr = shard_chunks[cidx].ptr;
                            let cbase = (cidx as u32) << HX_CHUNK_SHIFT;
                            for ridx in 0..c_len {
                                let hx = unsafe { *c_ptr.add(ridx) };
                                let eh = hash_hex128(Hex128 {
                                    hi: hx.ev_hi,
                                    lo: hx.ev_lo,
                                });
                                match gt.entry(
                                    eh,
                                    |&packed| {
                                        let pc = (packed >> HX_CHUNK_SHIFT) as usize;
                                        let pr = (packed & HX_CHUNK_MASK) as usize;
                                        let prev = unsafe { &*shard_chunks[pc].ptr.add(pr) };
                                        prev.ev_hi == hx.ev_hi && prev.ev_lo == hx.ev_lo
                                    },
                                    |&packed| {
                                        let pc = (packed >> HX_CHUNK_SHIFT) as usize;
                                        let pr = (packed & HX_CHUNK_MASK) as usize;
                                        let prev = unsafe { &*shard_chunks[pc].ptr.add(pr) };
                                        hash_hex128(Hex128 {
                                            hi: prev.ev_hi,
                                            lo: prev.ev_lo,
                                        })
                                    },
                                ) {
                                    hashbrown::hash_table::Entry::Occupied(occ) => {
                                        let packed = *occ.get();
                                        let pc = (packed >> HX_CHUNK_SHIFT) as usize;
                                        let pr = (packed & HX_CHUNK_MASK) as usize;
                                        let prev_ptr = unsafe { shard_chunks[pc].ptr.add(pr) };
                                        let prev_hx = unsafe { *prev_ptr };
                                        let hx_ing =
                                            hx32_ingest_ms(&hx, window_start_sec, ev_worker_ext);
                                        let cur_ing = hx32_ingest_ms(
                                            &prev_hx,
                                            window_start_sec,
                                            ev_worker_ext,
                                        );
                                        unsafe {
                                            if hx_ing < cur_ing {
                                                *prev_ptr = hx;
                                            }
                                            (*c_ptr.add(ridx)).ts_rel_ms = HX_TS_DEAD;
                                        }
                                    }
                                    hashbrown::hash_table::Entry::Vacant(vac) => {
                                        vac.insert(cbase | (ridx as u32));
                                    }
                                }
                            }
                        }
                    }
                    if let Some(t) = t_p1 {
                        p1_ns += t.elapsed().as_nanos() as u64;
                    }
                    let t_p2 = if PD { Some(Instant::now()) } else { None };
                    let c_p2_0 = if PD { rdtsc_now() } else { 0 };
                    let mut shard_mc = P2Micro::default();

                    let mut n_p2_pending = 0usize;
                    let mut n_p2_hex_pending = 0usize;
                    for chunk in shard_chunks {
                        let slice = unsafe { chunk.as_slice() };
                        let blen = slice.len();
                        for ridx in 0..blen {
                            if ridx + RING < blen {
                                let hx_a = unsafe { *slice.get_unchecked(ridx + RING) };
                                #[cfg(target_arch = "x86_64")]
                                unsafe {
                                    if hx_a.ts_rel_ms == HX_TS_EXT {
                                        let wid_a = (hx_a.person_key.0 >> 40) as usize;
                                        let idx_a = (hx_a.person_key.0 & PE_EXT_IDX_MASK) as usize;
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_ext.get_unchecked(wid_a).as_ptr().add(idx_a)
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    } else if hx_a.ts_rel_ms < HX_TS_DEAD && hx_a.person_key.is_hex() {
                                        let pk_a = hx_a.person_key;
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_hex
                                                .get_unchecked(pk_a.hex_wid())
                                                .as_ptr()
                                                .add(pk_a.hex_idx())
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                }
                            }
                            let hx = unsafe { *slice.get_unchecked(ridx) };
                            if hx.ts_rel_ms == HX_TS_DEAD || hx.ts_rel_ms == HX_TS_INVALID {
                                continue;
                            }
                            if PD {
                                shard_mc.surv_total += 1;
                            }
                            let (person_key, ts_ms, price_cents, cat_id) =
                                if hx.ts_rel_ms == HX_TS_EXT {
                                    let wid = (hx.person_key.0 >> 40) as usize;
                                    let idx = (hx.person_key.0 & PE_EXT_IDX_MASK) as usize;
                                    let ex = unsafe {
                                        *ev_worker_ext.get_unchecked(wid).get_unchecked(idx)
                                    };
                                    if ex.cat_id == u32::MAX {
                                        continue;
                                    }
                                    (ex.person_key, ex.ts_ms, ex.price_cents, ex.cat_id)
                                } else {
                                    (hx.person_key, window_start_ms + (hx.ts_rel_ms as i64), 0, 0)
                                };

                            if person_key.is_uh42() {
                                let h42 = person_key.uh42_val();
                                let item = E::from_ext_fields(
                                    person_key,
                                    ts_ms,
                                    window_start_ms,
                                    price_cents,
                                    cat_id,
                                );
                                if lm_empty {
                                    let pshard = ((h42 >> 34) as usize) & (P_PERSON - 1);
                                    buckets_out.push(pshard, item);
                                } else {
                                    link_map.prefetch_bloom_b37(h42);
                                    unsafe {
                                        *pending_ev.get_unchecked_mut(n_p2_pending) = item;
                                        *pending_h42.get_unchecked_mut(n_p2_pending) = h42;
                                    }
                                    n_p2_pending += 1;
                                    if n_p2_pending == LINK_PENDING {
                                        flush_dedup_pending::<E, PD>(
                                            LINK_PENDING,
                                            &mut pending_ev,
                                            &pending_h42,
                                            &mut hit_idxs,
                                            &mut miss_idxs,
                                            link_map,
                                            buckets_out,
                                            &mut shard_mc,
                                        );
                                        n_p2_pending = 0;
                                    }
                                }
                            } else if person_key.is_hex() {
                                let mut item = E::from_ext_fields(
                                    person_key,
                                    ts_ms,
                                    window_start_ms,
                                    price_cents,
                                    cat_id,
                                );
                                if lm_empty {
                                    let hx_u = person_key.resolve_hex(ev_worker_hex);
                                    let h64 = hash_hex128(hx_u);
                                    item.apply_canon(CompactKey64::from_hex(
                                        person_key.hex_wid(),
                                        person_key.hex_idx(),
                                        false,
                                        (h64 & 0xF_FFFF) as u32,
                                    ));
                                    let pshard = (h64 as usize) & (P_PERSON - 1);
                                    buckets_out.push(pshard, item);
                                } else {
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_worker_hex
                                                .get_unchecked(person_key.hex_wid())
                                                .as_ptr()
                                                .add(person_key.hex_idx())
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                    unsafe {
                                        *pending_ev_hex.get_unchecked_mut(n_p2_hex_pending) = item;
                                        *pending_ev_hex_pk.get_unchecked_mut(n_p2_hex_pending) =
                                            person_key;
                                    }
                                    n_p2_hex_pending += 1;
                                    if n_p2_hex_pending == LINK_PENDING {
                                        flush_dedup_hex_pending::<E, PD>(
                                            LINK_PENDING,
                                            &mut pending_ev_hex,
                                            &pending_ev_hex_pk,
                                            ev_worker_hex,
                                            &mut hit_idxs,
                                            &mut miss_idxs,
                                            link_map,
                                            buckets_out,
                                            &mut shard_mc,
                                        );
                                        n_p2_hex_pending = 0;
                                    }
                                }
                            } else {
                                let pk0 = person_key;
                                let (pk, pshard) = if !lm_empty {
                                    if !pk0.is_ref() {
                                        if let Some(canon) = link_map.resolve_other_inline(pk0) {
                                            (canon, pshard_for_person_key(canon, &[]))
                                        } else {
                                            (pk0, ((mix64(pk0.0) >> 52) as usize) & (P_PERSON - 1))
                                        }
                                    } else {
                                        let uid = LongArena::resolve_in(ev_worker_arenas, pk0);
                                        if let Some(canon) = link_map.resolve_long(uid) {
                                            (canon, pshard_for_person_key(canon, &[]))
                                        } else {
                                            (
                                                pk0,
                                                ((hash_bytes_fast(uid) >> 52) as usize)
                                                    & (P_PERSON - 1),
                                            )
                                        }
                                    }
                                } else {
                                    (pk0, pshard_for_person_key(pk0, ev_worker_arenas))
                                };
                                buckets_out.push(
                                    pshard,
                                    E::from_ext_fields(
                                        pk,
                                        ts_ms,
                                        window_start_ms,
                                        price_cents,
                                        cat_id,
                                    ),
                                );
                            }
                        }
                    }
                    if n_p2_pending > 0 {
                        flush_dedup_pending::<E, PD>(
                            n_p2_pending,
                            &mut pending_ev,
                            &pending_h42,
                            &mut hit_idxs,
                            &mut miss_idxs,
                            link_map,
                            buckets_out,
                            &mut shard_mc,
                        );
                    }
                    if n_p2_hex_pending > 0 {
                        flush_dedup_hex_pending::<E, PD>(
                            n_p2_hex_pending,
                            &mut pending_ev_hex,
                            &pending_ev_hex_pk,
                            ev_worker_hex,
                            &mut hit_idxs,
                            &mut miss_idxs,
                            link_map,
                            buckets_out,
                            &mut shard_mc,
                        );
                    }
                    if let Some(t) = t_p2 {
                        let s_ns = t.elapsed().as_nanos() as u64;
                        p2_ns += s_ns;
                        let tot_cyc = rdtsc_now().wrapping_sub(c_p2_0).max(1);
                        let tracked = shard_mc.bloom_cyc
                            + shard_mc.probe_cyc
                            + shard_mc.push_cyc
                            + shard_mc.hex_cyc;
                        let unpack_cyc = tot_cyc.saturating_sub(tracked);
                        let cyc_to_ns = |c: u64| -> u64 {
                            ((s_ns as u128 * c as u128) / tot_cyc as u128) as u64
                        };
                        let u_ns = cyc_to_ns(unpack_cyc);
                        let b_ns = cyc_to_ns(shard_mc.bloom_cyc);
                        let pr_ns = cyc_to_ns(shard_mc.probe_cyc);
                        let pu_ns = cyc_to_ns(shard_mc.push_cyc);
                        p2_unpack_ns += u_ns;
                        p2_bloom_ns += b_ns;
                        p2_probe_ns += pr_ns;
                        p2_push_ns += pu_ns;
                        p2_hex_ns += s_ns.saturating_sub(u_ns + b_ns + pr_ns + pu_ns);
                        p2_counts.b37_bloom_hits += shard_mc.b37_bloom_hits;
                        p2_counts.b37_slot_hits += shard_mc.b37_slot_hits;
                        p2_counts.b37_misses += shard_mc.b37_misses;
                        p2_counts.hex_bloom_hits += shard_mc.hex_bloom_hits;
                        p2_counts.hex_slot_hits += shard_mc.hex_slot_hits;
                        p2_counts.hex_misses += shard_mc.hex_misses;
                        p2_counts.surv_total += shard_mc.surv_total;
                    }
                }

                if let Some(buckets_out) = person_out {
                    let t_fin = if PD { Some(Instant::now()) } else { None };
                    let (pe_slab, pe_done) = buckets_out.finish();
                    *pe_slab_slot = Some(pe_slab);
                    *ev_out_slot = pe_done;
                    if let Some(t) = t_fin {
                        let f_ns = t.elapsed().as_nanos() as u64;
                        p2_ns += f_ns;
                        p2_push_ns += f_ns;
                    }
                }
                if PD {
                    detail.dedup_p1_ns.fetch_add(p1_ns, Ordering::Relaxed);
                    detail.dedup_p2_ns.fetch_add(p2_ns, Ordering::Relaxed);
                    detail.p2_unpack_ns.fetch_add(p2_unpack_ns, Ordering::Relaxed);
                    detail.p2_bloom_ns.fetch_add(p2_bloom_ns, Ordering::Relaxed);
                    detail.p2_probe_ns.fetch_add(p2_probe_ns, Ordering::Relaxed);
                    detail.p2_push_ns.fetch_add(p2_push_ns, Ordering::Relaxed);
                    detail.p2_hex_ns.fetch_add(p2_hex_ns, Ordering::Relaxed);
                    detail
                        .p2_b37_bloom_hits
                        .fetch_add(p2_counts.b37_bloom_hits, Ordering::Relaxed);
                    detail
                        .p2_b37_slot_hits
                        .fetch_add(p2_counts.b37_slot_hits, Ordering::Relaxed);
                    detail
                        .p2_b37_misses
                        .fetch_add(p2_counts.b37_misses, Ordering::Relaxed);
                    detail
                        .p2_hex_bloom_hits
                        .fetch_add(p2_counts.hex_bloom_hits, Ordering::Relaxed);
                    detail
                        .p2_hex_slot_hits
                        .fetch_add(p2_counts.hex_slot_hits, Ordering::Relaxed);
                    detail
                        .p2_hex_misses
                        .fetch_add(p2_counts.hex_misses, Ordering::Relaxed);
                    detail
                        .p2_surv_total
                        .fetch_add(p2_counts.surv_total, Ordering::Relaxed);
                }
            });
        }
    });

    for e in worker_errs.into_iter().flatten() {
        return Err(e);
    }

    let pe_slabs: Vec<SlabArena> = pe_worker_slabs.into_iter().flatten().collect();
    let cl_slabs: Vec<SlabArena> = cl_worker_slabs.into_iter().flatten().collect();

    let mut person_event_chunks: Vec<Vec<MutChunkRef<E>>> = (0..P_PERSON)
        .map(|_| Vec::new())
        .collect();
    let mut person_event_counts = vec![0usize; P_PERSON];
    for wouts in dedup_worker_chunks {
        for (ps, v) in wouts.into_iter().enumerate() {
            for c in v {
                person_event_counts[ps] += c.len;
                person_event_chunks[ps].push(c);
            }
        }
    }

    let mut person_click_chunks: Vec<Vec<MutChunkRef<C>>> = (0..P_PERSON)
        .map(|_| Vec::new())
        .collect();
    let mut person_click_counts = vec![0usize; P_PERSON];
    for wouts in cl_worker_chunks {
        for (ps, v) in wouts.into_iter().enumerate() {
            for c in v {
                person_click_counts[ps] += c.len;
                person_click_chunks[ps].push(c);
            }
        }
    }

    Ok(ClicksDedupOut {
        pe_slabs,
        cl_slabs,
        person_event_chunks,
        person_event_counts,
        person_click_chunks,
        person_click_counts,
        cl_worker_arenas,
        cl_worker_hex,
        cl_worker_ext,
    })
}

impl ClickEmit for PersonClick16 {
    #[inline(always)]
    fn make_b37_pending(
        h42: u64,
        k_b37: u64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self {
        let ts_rel = (ts_ms - click_window_start_ms) as u64;
        Self {
            w0: CL_UB37 | ((camp_id as u64) << 43) | ((ts_rel >> 22) << 34) | (h42 & CL_REM34_MASK),
            w1: ((ts_rel & 0x3F_FFFF) << 42) | k_b37,
        }
    }

    #[inline(always)]
    fn apply_canon(&mut self, canon: CompactKey64, wid: usize, cl_ext: &mut Vec<ExtClick>) {
        if (self.w0 & CL_TAG_MASK) == CL_EXT {
            self.w1 = canon.0;
            return;
        }
        if canon.is_uh42() {
            self.w0 = CL_UB37 | (self.w0 & !CL_REM34_MASK) | (canon.uh42_val() & CL_REM34_MASK);
        } else {
            let ts_rel_ms =
                ((((self.w0 >> 34) & 0x1FF) << 22) | ((self.w1 >> 42) & 0x3F_FFFF)) as u32;
            let camp_id = ((self.w0 >> 43) & 0x7_FFFF) as u32;
            let click_id_key = CompactKey64::from_kb37(self.w1 & B37_MASK42);
            let idx = cl_ext.len() as u64;
            cl_ext.push(ExtClick {
                click_id_key,
                ts_rel_ms,
                camp_id,
            });
            self.w0 = CL_EXT | ((wid as u64) << 40) | idx;
            self.w1 = canon.0;
        }
    }

    #[inline(always)]
    fn make_direct(
        wid: usize,
        cl_ext: &mut Vec<ExtClick>,
        person_key: CompactKey64,
        click_id_key: CompactKey64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self {
        let idx = cl_ext.len() as u64;
        cl_ext.push(ExtClick {
            click_id_key,
            ts_rel_ms: (ts_ms - click_window_start_ms) as u32,
            camp_id,
        });
        Self {
            w0: CL_EXT | ((wid as u64) << 40) | idx,
            w1: person_key.0,
        }
    }
}

impl ClickEmit for PersonClickWide {
    #[inline(always)]
    fn make_b37_pending(
        h42: u64,
        k_b37: u64,
        ts_ms: i64,
        _click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self {
        Self {
            person_key: CompactKey64::from_uh42(h42),
            click_id_key: CompactKey64::from_kb37(k_b37),
            ts_ms,
            camp_id,
            _pad: 0,
        }
    }

    #[inline(always)]
    fn apply_canon(&mut self, canon: CompactKey64, _wid: usize, _cl_ext: &mut Vec<ExtClick>) {
        self.person_key = canon;
    }

    #[inline(always)]
    fn make_direct(
        _wid: usize,
        _cl_ext: &mut Vec<ExtClick>,
        person_key: CompactKey64,
        click_id_key: CompactKey64,
        ts_ms: i64,
        _click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self {
        Self {
            person_key,
            click_id_key,
            ts_ms,
            camp_id,
            _pad: 0,
        }
    }
}

struct EvParseOutput {
    ev_slabs: Vec<SlabArena>,
    dedup_chunks: Vec<Vec<MutChunkRef<ParsedEvent16>>>,
    hex_slabs: Vec<SlabArena>,
    hex_dedup_chunks: Vec<Vec<MutChunkRef<HexEvent32>>>,
    ev_worker_arenas: Vec<LongArena>,
    ev_worker_hex: Vec<Vec<Hex128>>,
    ev_worker_ext: Vec<Vec<ExtEvent>>,
}

#[inline(always)]
fn encode_ev_person_key_fast(
    padded: &[u8],
    u_s: usize,
    u_len: usize,
    u_e: usize,
    wid: usize,
    ev_hex_out: &mut Vec<Hex128>,
    ev_arena_out: &mut LongArena,
) -> CompactKey64 {
    if let Some(u37) = encode_b37_padded(padded, u_s, u_len, b'u') {
        return CompactKey64::from_uh42(biject42(u37));
    }
    if let Some(hx) = encode_hex32_padded(padded, u_s, u_len, b'u') {
        let idx = ev_hex_out.len();
        ev_hex_out.push(hx);
        return CompactKey64::from_hex(wid, idx, false, 0);
    }
    if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, u_s, u_len) {
        return k;
    }
    let uid = unsafe { padded.get_unchecked(u_s..u_e) };
    ev_arena_out.push_ref(wid, uid)
}

#[inline(always)]
fn emit_hex_ev32<const COMPACT: bool, const PD: bool>(
    padded: &[u8],
    ev_hex: Hex128,
    u_s: usize,
    u_len: usize,
    u_e: usize,
    valid: bool,
    is_purchase: bool,
    ingest_sec: i64,
    ingest_ms: i64,
    ts_ms: i64,
    price_val: u32,
    cat_id: u32,
    wid: usize,
    window_start_ms: i64,
    window_start_sec: i64,
    ev_arena_out: &mut LongArena,
    ev_hex_out: &mut Vec<Hex128>,
    ext_out: &mut Vec<ExtEvent>,
    hex_buckets: &mut Option<SlabBuckets<HexEvent32, P_HEX_DEDUP, HX_CHUNK_LEN, 2>>,
    ev_hint_bytes: usize,
    mc: &mut EvMicro,
) {
    let eh = hash_hex128(ev_hex);
    let h_shard = (eh >> 58) as usize;
    let ing_off = ingest_sec.wrapping_sub(window_start_sec);
    let ing_fits = (-HX_ING_BIAS..HX_ING_BIAS).contains(&ing_off);
    let hx_b = hex_buckets.get_or_insert_with(|| SlabBuckets::new(ev_hint_bytes / 4));
    if PD {
        mc.n_hex_ev += 1;
    }
    if COMPACT
        && valid
        && !is_purchase
        && ing_fits
        && ((ts_ms - window_start_ms) as u64) < (HX_TS_DEAD as u64)
    {
        let person_key = encode_ev_person_key_fast(
            padded,
            u_s,
            u_len,
            u_e,
            wid,
            ev_hex_out,
            ev_arena_out,
        );
        hx_b.push(
            h_shard,
            HexEvent32 {
                ev_hi: ev_hex.hi,
                ev_lo: ev_hex.lo,
                person_key,
                ts_rel_ms: (ts_ms - window_start_ms) as u32,
                ing_sec_off: (ing_off + HX_ING_BIAS) as u32,
            },
        );
    } else if !valid && ing_fits {
        hx_b.push(
            h_shard,
            HexEvent32 {
                ev_hi: ev_hex.hi,
                ev_lo: ev_hex.lo,
                person_key: CompactKey64::EMPTY,
                ts_rel_ms: HX_TS_INVALID,
                ing_sec_off: (ing_off + HX_ING_BIAS) as u32,
            },
        );
    } else {
        let ext_idx = ext_out.len() as u64;
        if !valid {
            ext_out.push(ExtEvent {
                person_key: CompactKey64::EMPTY,
                ts_ms: 0,
                ingest_ts_ms: ingest_ms,
                price_cents: 0,
                cat_id: u32::MAX,
            });
        } else {
            let person_key = encode_ev_person_key_fast(
                padded,
                u_s,
                u_len,
                u_e,
                wid,
                ev_hex_out,
                ev_arena_out,
            );
            ext_out.push(ExtEvent {
                person_key,
                ts_ms,
                ingest_ts_ms: ingest_ms,
                price_cents: price_val,
                cat_id,
            });
        }
        hx_b.push(
            h_shard,
            HexEvent32 {
                ev_hi: ev_hex.hi,
                ev_lo: ev_hex.lo,
                person_key: CompactKey64(((wid as u64) << 40) | ext_idx),
                ts_rel_ms: HX_TS_EXT,
                ing_sec_off: 0,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn process_ev_emit_fallback<const COMPACT: bool, const PD: bool>(
    padded: &[u8],
    ev_s: usize,
    ev_len: usize,
    u_s: usize,
    u_len: usize,
    valid: bool,
    is_purchase: bool,
    ingest_sec: i64,
    ts_ms: i64,
    ts_sec_val: i64,
    price_val: u32,
    cat_id: u32,
    wid: usize,
    window_start_ms: i64,
    window_start_sec: i64,
    ev_arena_out: &mut LongArena,
    ev_hex_out: &mut Vec<Hex128>,
    ext_out: &mut Vec<ExtEvent>,
    ev_buckets: &mut SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN, DEDUP_SWCB_W>,
    hex_buckets: &mut Option<SlabBuckets<HexEvent32, P_HEX_DEDUP, HX_CHUNK_LEN, 2>>,
    ev_hint_bytes: usize,
    mc: &mut EvMicro,
) {
    if ev_len == 0 {
        return;
    }
    let ev_e = ev_s + ev_len;
    let u_e = u_s + u_len;
    let ingest_ms = ingest_sec * MS_SECOND;

    if ev_len == 33 {
        if let Some(ev_hex) = encode_hex32_padded(padded, ev_s, ev_len, b'e') {
            emit_hex_ev32::<COMPACT, PD>(
                padded,
                ev_hex,
                u_s,
                u_len,
                u_e,
                valid,
                is_purchase,
                ingest_sec,
                ingest_ms,
                ts_ms,
                price_val,
                cat_id,
                wid,
                window_start_ms,
                window_start_sec,
                ev_arena_out,
                ev_hex_out,
                ext_out,
                hex_buckets,
                ev_hint_bytes,
                mc,
            );
            return;
        }
    }

    if COMPACT && valid && !is_purchase && ev_len.wrapping_sub(2) <= 7 {
        let ing_off = ingest_sec - ts_sec_val;
        if (-PE_ING_BIAS..PE_ING_MAX).contains(&ing_off) {
            if u_len.wrapping_sub(2) <= 7 {
                if let Some((ev_b37, u_b37)) =
                    encode_b37_pair_padded(padded, ev_s, ev_len, b'e', u_s, u_len, b'u')
                {
                    let h42 = biject42(ev_b37);
                    let d_shard = (h42 >> 35) as usize;
                    let ev_rem = h42 & PE_EV_REM_MASK;
                    let biased = (ing_off + PE_ING_BIAS) as u64;
                    let ts_rel_u = (ts_ms - window_start_ms) as u64;
                    let u_h42 = biject42(u_b37);
                    if PD {
                        mc.n_fast_b37 += 1;
                    }
                    ev_buckets.push(
                        d_shard,
                        ParsedEvent16 {
                            w0: PE_FAST_B37 | (biased << 44) | ((ts_rel_u >> 22) << 35) | ev_rem,
                            w1: ((ts_rel_u & 0x3F_FFFF) << 42) | u_h42,
                        },
                    );
                    return;
                }
            } else if u_len == 33 && ev_hex_out.len() < (1 << 26) {
                if let Some(ev_b37) = encode_b37_padded(padded, ev_s, ev_len, b'e') {
                    if let Some(hx_u) = encode_hex32_padded(padded, u_s, u_len, b'u') {
                        let h42 = biject42(ev_b37);
                        let d_shard = (h42 >> 35) as usize;
                        let ev_rem = h42 & PE_EV_REM_MASK;
                        let uidx = ev_hex_out.len() as u64;
                        ev_hex_out.push(hx_u);
                        let biased = (ing_off + PE_ING_BIAS) as u64;
                        let ts_rel_u = (ts_ms - window_start_ms) as u64;
                        if PD {
                            mc.n_fast_uhex += 1;
                        }
                        ev_buckets.push(
                            d_shard,
                            ParsedEvent16 {
                                w0: PE_FAST_UHEX
                                    | (biased << 44)
                                    | ((ts_rel_u >> 22) << 35)
                                    | ev_rem,
                                w1: ((ts_rel_u & 0x3F_FFFF) << 42)
                                    | ((wid as u64) << 36)
                                    | uidx,
                            },
                        );
                        return;
                    }
                }
            }
        }
    }

    if let Some(ev_b37) = encode_b37_padded(padded, ev_s, ev_len, b'e') {
        let h42 = biject42(ev_b37);
        let d_shard = (h42 >> 35) as usize;
        let ev_rem = h42 & PE_EV_REM_MASK;
        if !valid {
            if PD {
                mc.n_inv_b37 += 1;
            }
            ev_buckets.push(
                d_shard,
                ParsedEvent16 {
                    w0: PE_INV_B37 | ev_rem,
                    w1: ingest_ms as u64,
                },
            );
            return;
        }
        if COMPACT && !is_purchase && ev_hex_out.len() < (1 << 26) {
            let ing_off = ingest_sec - ts_sec_val;
            if (-PE_ING_BIAS..PE_ING_MAX).contains(&ing_off) {
                if let Some(hx_u) = encode_hex32_padded(padded, u_s, u_len, b'u') {
                    let uidx = ev_hex_out.len() as u64;
                    ev_hex_out.push(hx_u);
                    let biased = (ing_off + PE_ING_BIAS) as u64;
                    let ts_rel_u = (ts_ms - window_start_ms) as u64;
                    if PD {
                        mc.n_fast_uhex += 1;
                    }
                    ev_buckets.push(
                        d_shard,
                        ParsedEvent16 {
                            w0: PE_FAST_UHEX | (biased << 44) | ((ts_rel_u >> 22) << 35) | ev_rem,
                            w1: ((ts_rel_u & 0x3F_FFFF) << 42) | ((wid as u64) << 36) | uidx,
                        },
                    );
                    return;
                }
            }
        }
        let person_key = encode_ev_person_key_fast(
            padded,
            u_s,
            u_len,
            u_e,
            wid,
            ev_hex_out,
            ev_arena_out,
        );
        let ext_idx = ext_out.len() as u64;
        ext_out.push(ExtEvent {
            person_key,
            ts_ms,
            ingest_ts_ms: ingest_ms,
            price_cents: price_val,
            cat_id,
        });
        if PD {
            mc.n_ext_b37 += 1;
        }
        ev_buckets.push(
            d_shard,
            ParsedEvent16 {
                w0: PE_EXT_B37 | ev_rem,
                w1: ((wid as u64) << 40) | ext_idx,
            },
        );
    } else if let Some(ev_hex) = encode_hex32_padded(padded, ev_s, ev_len, b'e') {
        emit_hex_ev32::<COMPACT, PD>(
            padded,
            ev_hex,
            u_s,
            u_len,
            u_e,
            valid,
            is_purchase,
            ingest_sec,
            ingest_ms,
            ts_ms,
            price_val,
            cat_id,
            wid,
            window_start_ms,
            window_start_sec,
            ev_arena_out,
            ev_hex_out,
            ext_out,
            hex_buckets,
            ev_hint_bytes,
            mc,
        );
    } else {
        let (ev_key, ev_hash) =
            if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, ev_s, ev_len) {
                (k, mix64(k.0))
            } else {
                let ev_id = unsafe { padded.get_unchecked(ev_s..ev_e) };
                (ev_arena_out.push_ref(wid, ev_id), hash_bytes_fast(ev_id))
            };
        let d_shard = ((ev_hash >> 52) as usize) & (P_DEDUP - 1);
        let ext_idx = ext_out.len() as u64;
        if !valid {
            ext_out.push(ExtEvent {
                person_key: CompactKey64::EMPTY,
                ts_ms: 0,
                ingest_ts_ms: ingest_ms,
                price_cents: 0,
                cat_id: u32::MAX,
            });
            if PD {
                mc.n_inv_gen += 1;
            }
        } else {
            let person_key = encode_ev_person_key_fast(
                padded,
                u_s,
                u_len,
                u_e,
                wid,
                ev_hex_out,
                ev_arena_out,
            );
            ext_out.push(ExtEvent {
                person_key,
                ts_ms,
                ingest_ts_ms: ingest_ms,
                price_cents: price_val,
                cat_id,
            });
            if PD {
                mc.n_ext_gen += 1;
            }
        }
        ev_buckets.push(
            d_shard,
            ParsedEvent16 {
                w0: PE_EXT_GEN | ((wid as u64) << 40) | ext_idx,
                w1: ev_key.0,
            },
        );
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn process_ev_line<const COMPACT: bool, const TS_KIND: u8, const PD: bool>(
    padded: &[u8],
    base: *const u8,
    cm_ptr: *const u32,
    dl: &DirectLineRef,
    ts_s: usize,
    ts_len: usize,
    dcache: &mut DateCache,
    lookups: &Lookups,
    wid: usize,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    window_span_u64: u64,
    ev_arena_out: &mut LongArena,
    ev_hex_out: &mut Vec<Hex128>,
    ext_out: &mut Vec<ExtEvent>,
    ev_buckets: &mut SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN, DEDUP_SWCB_W>,
    hex_buckets: &mut Option<SlabBuckets<HexEvent32, P_HEX_DEDUP, HX_CHUNK_LEN, 2>>,
    ev_hint_bytes: usize,
    mc: &mut EvMicro,
) {
    const VIEW_U32: u32 = u32::from_ne_bytes(*b"view");
    const CART_U32: u32 = u32::from_ne_bytes(*b"cart");
    const PURCHASE_U64: u64 = u64::from_ne_bytes(*b"purchase");

    let ls = dl.ls as usize;
    let cm = unsafe { cm_ptr.add(dl.cm_off as usize) };
    let c0 = unsafe { *cm } as usize;
    let c1 = unsafe { *cm.add(1) } as usize;
    let c2 = unsafe { *cm.add(2) } as usize;
    let c3 = unsafe { *cm.add(3) } as usize;
    let c4 = unsafe { *cm.add(4) } as usize;
    let c5 = unsafe { *cm.add(5) } as usize;
    let le = dl.le as usize;

    let (ev_s, ev_e) = unsafe { field_span(base, ls, c0) };
    let ev_len = ev_e - ev_s;
    if ev_len == 0 {
        return;
    }
    let (ing_s, ing_e) = unsafe { field_span(base, c2 + 1, c3) };
    let Some((ingest_sec, hint_hi, hint_lo, hint_day_sec)) =
        dcache.parse_f1_sec_padded_with_hint(padded, ing_s, ing_e - ing_s)
    else {
        return;
    };

    let (u_s, u_e) = unsafe { field_span(base, c0 + 1, c1) };
    let u_len = u_e - u_s;
    let (et_s, et_e) = unsafe { field_span(base, c3 + 1, c4) };
    let et_len = et_e - et_s;
    let (p_s, p_e) = unsafe { field_span(base, c4 + 1, c5) };
    let p_len = p_e - p_s;

    let mut valid = false;
    let mut ts_ms = 0i64;
    let mut ts_sec_val = 0i64;
    let mut price_val = 0u32;
    let mut cat_id = 0u32;
    let mut is_purchase = false;

    if u_len > 0 && p_len > 0 {
        let mut need_ts = false;
        if et_len == 4 {
            let w = unsafe { u32::from_ne_bytes(*(base.add(et_s) as *const [u8; 4])) };
            need_ts = (w == VIEW_U32) | (w == CART_U32);
        } else if et_len == 8 {
            let w8 = unsafe { u64::from_ne_bytes(*(base.add(et_s) as *const [u8; 8])) };
            if w8 == PURCHASE_U64 {
                let (pr_s, pr_e) = unsafe { field_span(base, c5 + 1, le) };
                let price = unsafe { padded.get_unchecked(pr_s..pr_e) };
                if let Some(p) = parse_price_cents(price) {
                    price_val = p;
                    is_purchase = true;
                    need_ts = true;
                }
            }
        }
        if need_ts {
            let parsed_ts = match TS_KIND {
                0 => dcache.parse_f1_only_padded_hint::<true>(
                    padded,
                    ts_s,
                    hint_hi,
                    hint_lo,
                    hint_day_sec,
                ),
                1 => DateCache::parse_f3_only_13_padded(padded, ts_s),
                _ => dcache.parse_other_ts_padded_hint::<true, true>(
                    padded,
                    ts_s,
                    ts_len,
                    hint_hi,
                    hint_lo,
                    hint_day_sec,
                ),
            };
            if let Some((t, t_sec)) = parsed_ts {
                let in_win = if COMPACT {
                    let ts_rel = t.wrapping_sub(window_start_ms) as u64;
                    ts_rel < window_span_u64 && (ingest_sec - t_sec) <= 86_400
                } else {
                    let ingest_ms = ingest_sec * MS_SECOND;
                    t >= window_start_ms
                        && t < window_end_ms
                        && (ingest_ms as i128 - t as i128) <= MS_DAY as i128
                };
                if in_win {
                    ts_ms = t;
                    ts_sec_val = t_sec;
                    if is_purchase {
                        if PD {
                            mc.n_purch += 1;
                        }
                        cat_id = lookups.get_product_cat_padded(padded, p_s, p_len);
                    }
                    valid = true;
                }
            }
        }
    }

    if COMPACT
        && valid
        && !is_purchase
        && (ev_len.wrapping_sub(2) <= 7)
        && (u_len.wrapping_sub(2) <= 7)
    {
        let ing_off = ingest_sec - ts_sec_val;
        if (-PE_ING_BIAS..PE_ING_MAX).contains(&ing_off) {
            if let Some((ev_b37, u_b37)) =
                encode_b37_pair_padded(padded, ev_s, ev_len, b'e', u_s, u_len, b'u')
            {
                let h42 = biject42(ev_b37);
                let d_shard = (h42 >> 35) as usize;
                let ev_rem = h42 & PE_EV_REM_MASK;
                let biased = (ing_off + PE_ING_BIAS) as u64;
                let ts_rel_u = (ts_ms - window_start_ms) as u64;
                let u_h42 = biject42(u_b37);
                if PD {
                    mc.n_fast_b37 += 1;
                }
                ev_buckets.push(
                    d_shard,
                    ParsedEvent16 {
                        w0: PE_FAST_B37 | (biased << 44) | ((ts_rel_u >> 22) << 35) | ev_rem,
                        w1: ((ts_rel_u & 0x3F_FFFF) << 42) | u_h42,
                    },
                );
                return;
            }
        }
    }

    process_ev_emit_fallback::<COMPACT, PD>(
        padded,
        ev_s,
        ev_len,
        u_s,
        u_len,
        valid,
        is_purchase,
        ingest_sec,
        ts_ms,
        ts_sec_val,
        price_val,
        cat_id,
        wid,
        window_start_ms,
        window_start_sec,
        ev_arena_out,
        ev_hex_out,
        ext_out,
        ev_buckets,
        hex_buckets,
        ev_hint_bytes,
        mc,
    );
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn process_ev_batch_direct<const COMPACT: bool, const PD: bool>(
    padded: &[u8],
    cm_buf: &[u32],
    lines: &[DirectLineRef],
    dcache: &mut DateCache,
    lookups: &Lookups,
    wid: usize,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    ev_arena_out: &mut LongArena,
    ev_hex_out: &mut Vec<Hex128>,
    ext_out: &mut Vec<ExtEvent>,
    ev_buckets: &mut SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN, DEDUP_SWCB_W>,
    hex_buckets: &mut Option<SlabBuckets<HexEvent32, P_HEX_DEDUP, HX_CHUNK_LEN, 2>>,
    ev_hint_bytes: usize,
    mc: &mut EvMicro,
) {
    debug_assert!(lines.len() <= 64);
    let base = padded.as_ptr();
    let cm_ptr = cm_buf.as_ptr();
    let window_span_u64 = (window_end_ms - window_start_ms).max(0) as u64;

    let c0 = if PD { rdtsc_now() } else { 0 };
    let mut f1_idxs = [0u8; 64];
    let mut f3_idxs = [0u8; 64];
    let mut oth_idxs = [0u8; 64];
    let mut ts_starts = [0u32; 64];
    let mut ts_lens = [0u32; 64];
    let mut nf1 = 0usize;
    let mut nf3 = 0usize;
    let mut noth = 0usize;
    for (i, dl) in lines.iter().enumerate() {
        let cm = unsafe { cm_ptr.add(dl.cm_off as usize) };
        let c1 = unsafe { *cm.add(1) } as usize;
        let c2 = unsafe { *cm.add(2) } as usize;
        let (ts_s, ts_e) = unsafe { field_span(base, c1 + 1, c2) };
        let ts_len = ts_e - ts_s;
        unsafe {
            *ts_starts.get_unchecked_mut(i) = ts_s as u32;
            *ts_lens.get_unchecked_mut(i) = ts_len as u32;
        }
        let is_f1 = ts_len == 20;
        let is_f3 = ts_len == 13;
        unsafe {
            *f1_idxs.get_unchecked_mut(nf1) = i as u8;
            *f3_idxs.get_unchecked_mut(nf3) = i as u8;
            *oth_idxs.get_unchecked_mut(noth) = i as u8;
        }
        nf1 += is_f1 as usize;
        nf3 += is_f3 as usize;
        noth += (!(is_f1 | is_f3)) as usize;
    }
    let c1 = if PD { rdtsc_now() } else { 0 };
    if PD {
        mc.classify_cyc += c1.wrapping_sub(c0);
        mc.n_f1 += nf1 as u64;
        mc.n_f3 += nf3 as u64;
        mc.n_oth += noth as u64;
    }

    for &idx in &f1_idxs[..nf1] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_ev_line::<COMPACT, 0, PD>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            wid,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            window_span_u64,
            ev_arena_out,
            ev_hex_out,
            ext_out,
            ev_buckets,
            hex_buckets,
            ev_hint_bytes,
            mc,
        );
    }
    let c2 = if PD { rdtsc_now() } else { 0 };
    if PD {
        mc.dec_f1_cyc += c2.wrapping_sub(c1);
    }
    for &idx in &f3_idxs[..nf3] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_ev_line::<COMPACT, 1, PD>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            wid,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            window_span_u64,
            ev_arena_out,
            ev_hex_out,
            ext_out,
            ev_buckets,
            hex_buckets,
            ev_hint_bytes,
            mc,
        );
    }
    let c3 = if PD { rdtsc_now() } else { 0 };
    if PD {
        mc.dec_f3_cyc += c3.wrapping_sub(c2);
    }
    for &idx in &oth_idxs[..noth] {
        let dl = unsafe { lines.get_unchecked(idx as usize) };
        let ts_s = unsafe { *ts_starts.get_unchecked(idx as usize) as usize };
        let ts_len = unsafe { *ts_lens.get_unchecked(idx as usize) as usize };
        process_ev_line::<COMPACT, 2, PD>(
            padded,
            base,
            cm_ptr,
            dl,
            ts_s,
            ts_len,
            dcache,
            lookups,
            wid,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            window_span_u64,
            ev_arena_out,
            ev_hex_out,
            ext_out,
            ev_buckets,
            hex_buckets,
            ev_hint_bytes,
            mc,
        );
    }
    if PD {
        mc.dec_oth_cyc += rdtsc_now().wrapping_sub(c3);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parse_events_worker<const COMPACT: bool, const PD: bool>(
    event_src: &CsvSource,
    ev_chunks: &[crate::csv::ChunkTask],
    order: &[usize],
    next_ord: &AtomicUsize,
    ev_hint_bytes: usize,
    lookups: &Lookups,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    wid: usize,
    detail: &DetailStats,
    slab_slot: &mut Option<SlabArena>,
    dedup_slot: &mut Vec<Vec<MutChunkRef<ParsedEvent16>>>,
    hex_slab_slot: &mut Option<SlabArena>,
    hex_dedup_slot: &mut Vec<Vec<MutChunkRef<HexEvent32>>>,
    arena_out: &mut LongArena,
    hex_out: &mut Vec<Hex128>,
    ext_out: &mut Vec<ExtEvent>,
    err_out: &mut Option<io::Error>,
) {
    let mut buf = Vec::new();
    let mut dcache = DateCache::new_for_window(window_start_ms, window_end_ms);
    let mut ev_buckets: Option<SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN, DEDUP_SWCB_W>> =
        None;
    let mut hex_buckets: Option<SlabBuckets<HexEvent32, P_HEX_DEDUP, HX_CHUNK_LEN, 2>> = None;
    let mut io_scan_ns = 0u64;
    let mut pread_ns = 0u64;
    let mut ev_dec_ns = 0u64;
    let mut mc = EvMicro::default();

    loop {
        let o = next_ord.fetch_add(1, Ordering::Relaxed);
        let Some(&cidx) = order.get(o) else {
            break;
        };
        let task = ev_chunks[cidx];
        let t_c = if PD { Some(Instant::now()) } else { None };
        let mut dec_ns = 0u64;
        let res = {
            let buckets = ev_buckets.get_or_insert_with(|| SlabBuckets::new(ev_hint_bytes));
            event_src.for_each_chunk_direct_batched_timed::<7, PD>(
                task,
                &mut buf,
                &mut pread_ns,
                |padded, cm_buf, lines| {
                    let t_d = if PD { Some(Instant::now()) } else { None };
                    process_ev_batch_direct::<COMPACT, PD>(
                        padded,
                        cm_buf,
                        lines,
                        &mut dcache,
                        lookups,
                        wid,
                        window_start_ms,
                        window_end_ms,
                        window_start_sec,
                        arena_out,
                        hex_out,
                        ext_out,
                        buckets,
                        &mut hex_buckets,
                        ev_hint_bytes,
                        &mut mc,
                    );
                    if let Some(t) = t_d {
                        dec_ns += t.elapsed().as_nanos() as u64;
                    }
                },
            )
        };
        if let Some(tc) = t_c {
            let tot = tc.elapsed().as_nanos() as u64;
            ev_dec_ns += dec_ns;
            io_scan_ns += tot.saturating_sub(dec_ns);
        }
        if let Err(e) = res {
            *err_out = Some(e);
            return;
        }
    }

    if let Some(buckets) = ev_buckets {
        let (slab, w_chunks) = buckets.finish();
        *slab_slot = Some(slab);
        *dedup_slot = w_chunks;
    }
    if let Some(hb) = hex_buckets {
        let (h_slab, h_chunks) = hb.finish();
        *hex_slab_slot = Some(h_slab);
        *hex_dedup_slot = h_chunks;
    }
    if PD {
        let scan_ns = io_scan_ns.saturating_sub(pread_ns);
        let tot_cyc = (mc.classify_cyc + mc.dec_f1_cyc + mc.dec_f3_cyc + mc.dec_oth_cyc).max(1);
        let cyc_to_ns = |c: u64| -> u64 { ((ev_dec_ns as u128 * c as u128) / tot_cyc as u128) as u64 };
        let c_ns = cyc_to_ns(mc.classify_cyc);
        let f1_ns = cyc_to_ns(mc.dec_f1_cyc);
        let f3_ns = cyc_to_ns(mc.dec_f3_cyc);
        let o_ns = ev_dec_ns.saturating_sub(c_ns + f1_ns + f3_ns);
        detail.ev_io_scan_ns.fetch_add(io_scan_ns, Ordering::Relaxed);
        detail.ev_pread_ns.fetch_add(pread_ns, Ordering::Relaxed);
        detail.ev_scan_ns.fetch_add(scan_ns, Ordering::Relaxed);
        detail.ev_dec_ns.fetch_add(ev_dec_ns, Ordering::Relaxed);
        detail.ev_classify_ns.fetch_add(c_ns, Ordering::Relaxed);
        detail.ev_dec_f1_ns.fetch_add(f1_ns, Ordering::Relaxed);
        detail.ev_dec_f3_ns.fetch_add(f3_ns, Ordering::Relaxed);
        detail.ev_dec_oth_ns.fetch_add(o_ns, Ordering::Relaxed);
        detail.ev_n_f1.fetch_add(mc.n_f1, Ordering::Relaxed);
        detail.ev_n_f3.fetch_add(mc.n_f3, Ordering::Relaxed);
        detail.ev_n_oth.fetch_add(mc.n_oth, Ordering::Relaxed);
        detail.ev_n_fast_b37.fetch_add(mc.n_fast_b37, Ordering::Relaxed);
        detail.ev_n_fast_uhex.fetch_add(mc.n_fast_uhex, Ordering::Relaxed);
        detail.ev_n_ext_b37.fetch_add(mc.n_ext_b37, Ordering::Relaxed);
        detail.ev_n_inv_b37.fetch_add(mc.n_inv_b37, Ordering::Relaxed);
        detail.ev_n_hex_ev.fetch_add(mc.n_hex_ev, Ordering::Relaxed);
        detail.ev_n_ext_gen.fetch_add(mc.n_ext_gen, Ordering::Relaxed);
        detail.ev_n_inv_gen.fetch_add(mc.n_inv_gen, Ordering::Relaxed);
        detail.ev_n_purch.fetch_add(mc.n_purch, Ordering::Relaxed);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parse_events_and_links<const COMPACT: bool, const PD: bool>(
    event_src: &CsvSource,
    ev_chunks: &[crate::csv::ChunkTask],
    ev_hint_bytes: usize,
    link_paths: &[std::path::PathBuf],
    lookups: &Lookups,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    ncpu: usize,
    detail: &DetailStats,
) -> io::Result<(LinkMap, EvParseOutput, Instant, bool)> {
    let n_threads = ncpu.clamp(1, 63);
    let overlap_links = n_threads >= 2 && !link_paths.is_empty() && ev_chunks.len() >= 4;

    let mut link_map_opt: Option<LinkMap> = None;
    let mut links_w_done = Instant::now();
    if !overlap_links {
        let t_l0 = Instant::now();
        let lm = build_link_map(link_paths, n_threads)?;
        links_w_done = Instant::now();
        if PD {
            detail
                .links_w_ns
                .store((links_w_done - t_l0).as_nanos() as u64, Ordering::Relaxed);
        }
        link_map_opt = Some(lm);
    }

    if ev_chunks.is_empty() {
        return Ok((
            link_map_opt.unwrap_or_else(LinkMap::empty),
            EvParseOutput {
                ev_slabs: Vec::new(),
                dedup_chunks: (0..P_DEDUP).map(|_| Vec::new()).collect(),
                hex_slabs: Vec::new(),
                hex_dedup_chunks: (0..P_HEX_DEDUP).map(|_| Vec::new()).collect(),
                ev_worker_arenas: Vec::new(),
                ev_worker_hex: Vec::new(),
                ev_worker_ext: Vec::new(),
            },
            links_w_done,
            false,
        ));
    }

    let n_slots = n_threads.min(ev_chunks.len());
    let mut order: Vec<usize> = (0..ev_chunks.len()).collect();
    order.sort_unstable_by(|&a, &b| {
        let la = ev_chunks[a].end.saturating_sub(ev_chunks[a].start);
        let lb = ev_chunks[b].end.saturating_sub(ev_chunks[b].start);
        lb.cmp(&la)
    });
    let next_ord = AtomicUsize::new(0);

    let mut worker_slabs: Vec<Option<SlabArena>> = (0..n_slots).map(|_| None).collect();
    let mut worker_dedup: Vec<Vec<Vec<MutChunkRef<ParsedEvent16>>>> =
        (0..n_slots).map(|_| Vec::new()).collect();
    let mut worker_hex_slabs: Vec<Option<SlabArena>> = (0..n_slots).map(|_| None).collect();
    let mut worker_hex_dedup: Vec<Vec<Vec<MutChunkRef<HexEvent32>>>> =
        (0..n_slots).map(|_| Vec::new()).collect();
    let mut ev_worker_arenas: Vec<LongArena> = (0..n_slots).map(|_| LongArena::default()).collect();
    let mut ev_worker_hex: Vec<Vec<Hex128>> = (0..n_slots).map(|_| Vec::new()).collect();
    let mut ev_worker_ext: Vec<Vec<ExtEvent>> = (0..n_slots).map(|_| Vec::new()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..n_slots).map(|_| None).collect();

    if overlap_links {
        let link_threads = if n_threads >= 4 { 2 } else { 1 }.min(n_slots);
        let mut lm_res: io::Result<LinkMap> = Ok(LinkMap::empty());
        let order_ref = &order;
        let next_ref = &next_ord;
        let slabs_split = worker_slabs.split_at_mut(link_threads);
        let dedup_split = worker_dedup.split_at_mut(link_threads);
        let hex_slabs_split = worker_hex_slabs.split_at_mut(link_threads);
        let hex_dedup_split = worker_hex_dedup.split_at_mut(link_threads);
        let arenas_split = ev_worker_arenas.split_at_mut(link_threads);
        let hex_split = ev_worker_hex.split_at_mut(link_threads);
        let ext_split = ev_worker_ext.split_at_mut(link_threads);
        let errs_split = worker_errs.split_at_mut(link_threads);

        std::thread::scope(|scope| {
            // Immediate events workers for slots link_threads..n_slots
            for (
                idx,
                (
                    ((((((slab_slot, dedup_slot), hex_slab_slot), hex_dedup_slot), arena_out), hex_out), ext_out),
                    err_out,
                ),
            ) in slabs_split
                .1
                .iter_mut()
                .zip(dedup_split.1.iter_mut())
                .zip(hex_slabs_split.1.iter_mut())
                .zip(hex_dedup_split.1.iter_mut())
                .zip(arenas_split.1.iter_mut())
                .zip(hex_split.1.iter_mut())
                .zip(ext_split.1.iter_mut())
                .zip(errs_split.1.iter_mut())
                .enumerate()
            {
                let wid = link_threads + idx;
                scope.spawn(move || {
                    run_parse_events_worker::<COMPACT, PD>(
                        event_src,
                        ev_chunks,
                        order_ref,
                        next_ref,
                        ev_hint_bytes,
                        lookups,
                        window_start_ms,
                        window_end_ms,
                        window_start_sec,
                        wid,
                        detail,
                        slab_slot,
                        dedup_slot,
                        hex_slab_slot,
                        hex_dedup_slot,
                        arena_out,
                        hex_out,
                        ext_out,
                        err_out,
                    );
                });
            }

            // Coordinator builds LinkMap concurrently using `link_threads`, then releases threads to events_parse.
            let t_l0 = Instant::now();
            lm_res = build_link_map(link_paths, link_threads);
            if PD {
                detail
                    .links_w_ns
                    .store(t_l0.elapsed().as_nanos() as u64, Ordering::Relaxed);
            }

            let mut it_slab = slabs_split.0.iter_mut();
            let mut it_dedup = dedup_split.0.iter_mut();
            let mut it_hslab = hex_slabs_split.0.iter_mut();
            let mut it_hdedup = hex_dedup_split.0.iter_mut();
            let mut it_arena = arenas_split.0.iter_mut();
            let mut it_hex = hex_split.0.iter_mut();
            let mut it_ext = ext_split.0.iter_mut();
            let mut it_err = errs_split.0.iter_mut();

            let s0 = it_slab.next().unwrap();
            let d0 = it_dedup.next().unwrap();
            let hs0 = it_hslab.next().unwrap();
            let hd0 = it_hdedup.next().unwrap();
            let a0 = it_arena.next().unwrap();
            let h0 = it_hex.next().unwrap();
            let x0 = it_ext.next().unwrap();
            let e0 = it_err.next().unwrap();

            for (
                idx,
                (
                    ((((((slab_slot, dedup_slot), hex_slab_slot), hex_dedup_slot), arena_out), hex_out), ext_out),
                    err_out,
                ),
            ) in it_slab
                .zip(it_dedup)
                .zip(it_hslab)
                .zip(it_hdedup)
                .zip(it_arena)
                .zip(it_hex)
                .zip(it_ext)
                .zip(it_err)
                .enumerate()
            {
                let wid = 1 + idx;
                scope.spawn(move || {
                    run_parse_events_worker::<COMPACT, PD>(
                        event_src,
                        ev_chunks,
                        order_ref,
                        next_ref,
                        ev_hint_bytes,
                        lookups,
                        window_start_ms,
                        window_end_ms,
                        window_start_sec,
                        wid,
                        detail,
                        slab_slot,
                        dedup_slot,
                        hex_slab_slot,
                        hex_dedup_slot,
                        arena_out,
                        hex_out,
                        ext_out,
                        err_out,
                    );
                });
            }

            run_parse_events_worker::<COMPACT, PD>(
                event_src,
                ev_chunks,
                order_ref,
                next_ref,
                ev_hint_bytes,
                lookups,
                window_start_ms,
                window_end_ms,
                window_start_sec,
                0,
                detail,
                s0,
                d0,
                hs0,
                hd0,
                a0,
                h0,
                x0,
                e0,
            );
        });

        link_map_opt = Some(lm_res?);
    } else if n_slots <= 1 {
        run_parse_events_worker::<COMPACT, PD>(
            event_src,
            ev_chunks,
            &order,
            &next_ord,
            ev_hint_bytes,
            lookups,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            0,
            detail,
            &mut worker_slabs[0],
            &mut worker_dedup[0],
            &mut worker_hex_slabs[0],
            &mut worker_hex_dedup[0],
            &mut ev_worker_arenas[0],
            &mut ev_worker_hex[0],
            &mut ev_worker_ext[0],
            &mut worker_errs[0],
        );
    } else {
        std::thread::scope(|scope| {
            let order_ref = &order;
            let next_ref = &next_ord;
            for (
                wid,
                (
                    ((((((slab_slot, dedup_slot), hex_slab_slot), hex_dedup_slot), arena_out), hex_out), ext_out),
                    err_out,
                ),
            ) in worker_slabs
                .iter_mut()
                .zip(worker_dedup.iter_mut())
                .zip(worker_hex_slabs.iter_mut())
                .zip(worker_hex_dedup.iter_mut())
                .zip(ev_worker_arenas.iter_mut())
                .zip(ev_worker_hex.iter_mut())
                .zip(ev_worker_ext.iter_mut())
                .zip(worker_errs.iter_mut())
                .enumerate()
            {
                scope.spawn(move || {
                    run_parse_events_worker::<COMPACT, PD>(
                        event_src,
                        ev_chunks,
                        order_ref,
                        next_ref,
                        ev_hint_bytes,
                        lookups,
                        window_start_ms,
                        window_end_ms,
                        window_start_sec,
                        wid,
                        detail,
                        slab_slot,
                        dedup_slot,
                        hex_slab_slot,
                        hex_dedup_slot,
                        arena_out,
                        hex_out,
                        ext_out,
                        err_out,
                    );
                });
            }
        });
    }

    for e in worker_errs.into_iter().flatten() {
        return Err(e);
    }

    let mut ev_slabs = Vec::with_capacity(n_slots);
    let mut dedup_chunks: Vec<Vec<MutChunkRef<ParsedEvent16>>> = (0..P_DEDUP)
        .map(|_| Vec::new())
        .collect();
    for (slab_opt, w_chunks) in worker_slabs.into_iter().zip(worker_dedup.into_iter()) {
        if let Some(slab) = slab_opt {
            ev_slabs.push(slab);
            for (ds, v) in w_chunks.into_iter().enumerate() {
                dedup_chunks[ds].extend(v);
            }
        }
    }

    let mut hex_slabs = Vec::with_capacity(n_slots);
    let mut hex_dedup_chunks: Vec<Vec<MutChunkRef<HexEvent32>>> = (0..P_HEX_DEDUP)
        .map(|_| Vec::new())
        .collect();
    for (slab_opt, w_chunks) in worker_hex_slabs
        .into_iter()
        .zip(worker_hex_dedup.into_iter())
    {
        if let Some(slab) = slab_opt {
            hex_slabs.push(slab);
            for (hs, v) in w_chunks.into_iter().enumerate() {
                hex_dedup_chunks[hs].extend(v);
            }
        }
    }

    Ok((
        link_map_opt.unwrap(),
        EvParseOutput {
            ev_slabs,
            dedup_chunks,
            hex_slabs,
            hex_dedup_chunks,
            ev_worker_arenas,
            ev_worker_hex,
            ev_worker_ext,
        },
        links_w_done,
        overlap_links,
    ))
}

#[inline(always)]
fn insertion_sort_u64(s: &mut [u64]) {
    let n = s.len();
    for i in 1..n {
        let key = unsafe { *s.get_unchecked(i) };
        let mut j = i;
        while j > 0 {
            let prev = unsafe { *s.get_unchecked(j - 1) };
            if prev <= key {
                break;
            }
            unsafe {
                *s.get_unchecked_mut(j) = prev;
            }
            j -= 1;
        }
        unsafe {
            *s.get_unchecked_mut(j) = key;
        }
    }
}

fn sort_u64_bucket256(slice: &mut [u64], scratch: &mut Vec<u64>) {
    let n = slice.len();
    if n <= 1 {
        return;
    }
    if scratch.len() < n {
        scratch.resize(n, 0);
    }
    let tmp = &mut scratch[..n];

    let mut counts = [0u16; 256];
    for &x in slice.iter() {
        debug_assert!((x >> 63) == 0);
        counts[((x >> 55) as usize) & 0xFF] += 1;
    }

    let mut offs = [0u16; 256];
    let mut acc = 0u16;
    for b in 0..256 {
        offs[b] = acc;
        acc += counts[b];
    }
    let mut pos = offs;
    for &x in slice.iter() {
        let b = ((x >> 55) as usize) & 0xFF;
        unsafe {
            let p = *pos.get_unchecked(b) as usize;
            *pos.get_unchecked_mut(b) = (p + 1) as u16;
            *tmp.get_unchecked_mut(p) = x;
        }
    }

    for b in 0..256 {
        let s = offs[b] as usize;
        let e = pos[b] as usize;
        let blen = e - s;
        if blen <= 1 {
            continue;
        }
        if blen <= 24 {
            insertion_sort_u64(&mut tmp[s..e]);
        } else {
            tmp[s..e].sort_unstable();
        }
    }

    slice.copy_from_slice(tmp);
}

#[inline(always)]
fn radix_pass_u64(src: &[u64], dst: &mut [u64], counts: &mut [u32], shift: u32, mask: usize) {
    let mut acc = 0u32;
    for c in counts.iter_mut() {
        let v = *c;
        *c = acc;
        acc += v;
    }
    for &x in src {
        let b = ((x >> shift) as usize) & mask;
        unsafe {
            let pos = *counts.get_unchecked(b) as usize;
            *counts.get_unchecked_mut(b) = (pos + 1) as u32;
            *dst.get_unchecked_mut(pos) = x;
        }
    }
}

fn sort_u64_radix21_fixup(slice: &mut [u64], scratch: &mut Vec<u64>) {
    let n = slice.len();
    if n <= 1 {
        return;
    }
    if scratch.len() < n {
        scratch.resize(n, 0);
    }
    let tmp = &mut scratch[..n];

    let mut c0 = [0u32; 2048];
    let mut c1 = [0u32; 1024];
    for &x in slice.iter() {
        c0[((x >> 42) as usize) & 0x7FF] += 1;
        c1[((x >> 53) as usize) & 0x3FF] += 1;
    }

    let k0 = slice[0];
    let skip0 = c0[((k0 >> 42) as usize) & 0x7FF] as usize == n;
    let skip1 = c1[((k0 >> 53) as usize) & 0x3FF] as usize == n;

    let mut in_tmp = false;
    if !skip0 {
        radix_pass_u64(slice, tmp, &mut c0, 42, 0x7FF);
        in_tmp = true;
    }
    if !skip1 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c1, 53, 0x3FF);
        } else {
            radix_pass_u64(slice, tmp, &mut c1, 53, 0x3FF);
        }
        in_tmp = !in_tmp;
    }
    if in_tmp {
        slice.copy_from_slice(tmp);
    }

    let mut i = 1usize;
    while i < n {
        let key = unsafe { *slice.get_unchecked(i) };
        let key_hi = key >> 32;
        let prev = unsafe { *slice.get_unchecked(i - 1) };
        if key_hi < (prev >> 32) {
            let mut j = i - 1;
            let limit = i.saturating_sub(64);
            while j > limit && (unsafe { *slice.get_unchecked(j - 1) } >> 32) > key_hi {
                j -= 1;
            }
            if j == limit && j > 0 && (unsafe { *slice.get_unchecked(j - 1) } >> 32) > key_hi {
                let b_key = key >> 42;
                let mut run_lo = i;
                while run_lo > 0 && (unsafe { *slice.get_unchecked(run_lo - 1) } >> 42) == b_key {
                    run_lo -= 1;
                }
                let mut run_hi = i + 1;
                while run_hi < n && (unsafe { *slice.get_unchecked(run_hi) } >> 42) == b_key {
                    run_hi += 1;
                }
                slice[run_lo..run_hi].sort_unstable_by_key(|v| *v >> 32);
                i = run_hi;
                continue;
            }
            unsafe {
                let ptr = slice.as_mut_ptr();
                std::ptr::copy(ptr.add(j), ptr.add(j + 1), i - j);
                *ptr.add(j) = key;
            }
        }
        i += 1;
    }
}

impl Stage5Event for PersonEvent16 {
    const FAST_DAY_BOUND: bool = true;
    type Grouped = u64;

    #[inline(always)]
    fn person_key(&self) -> CompactKey64 {
        self.person_key
    }

    #[inline(always)]
    fn to_grouped(&self) -> u64 {
        ((self.ts_rel_ms as u64) << 32) | (self.price_cat as u64)
    }

    #[inline(always)]
    fn sort_grouped(slice: &mut [u64], scratch: &mut Vec<u64>) {
        let n = slice.len();
        if n <= 1 {
            return;
        }
        if n == 2 {
            let (a, b) = (slice[0], slice[1]);
            slice[0] = a.min(b);
            slice[1] = a.max(b);
            return;
        }
        if n == 3 {
            let (mut a, mut b, mut c) = (slice[0], slice[1], slice[2]);
            let (a1, b1) = (a.min(b), a.max(b));
            let (b2, c1) = (b1.min(c), b1.max(c));
            a = a1.min(b2);
            b = a1.max(b2);
            c = c1;
            slice[0] = a;
            slice[1] = b;
            slice[2] = c;
            return;
        }
        if n == 4 {
            let (mut a, mut b, mut c, mut d) = (slice[0], slice[1], slice[2], slice[3]);
            let (a1, b1) = (a.min(b), a.max(b));
            let (c1, d1) = (c.min(d), c.max(d));
            let (a2, c2) = (a1.min(c1), a1.max(c1));
            let (b2, d2) = (b1.min(d1), b1.max(d1));
            let (b3, c3) = (b2.min(c2), b2.max(c2));
            a = a2;
            b = b3;
            c = c3;
            d = d2;
            slice[0] = a;
            slice[1] = b;
            slice[2] = c;
            slice[3] = d;
            return;
        }
        if n <= 24 {
            insertion_sort_u64(slice);
            return;
        }
        if n < 256 {
            slice.sort_unstable();
            return;
        }
        if n < 2048 {
            sort_u64_bucket256(slice, scratch);
        } else {
            sort_u64_radix21_fixup(slice, scratch);
        }
    }

    #[inline(always)]
    fn unpack_cmp_price_cat(g: u64) -> (i64, u32, u32) {
        let ts_rel = (g >> 32) as i64;
        let price_cat = g as u32;
        (
            ts_rel + MS_CLICK_REACH,
            price_cat & 0x00FF_FFFF,
            price_cat >> 24,
        )
    }

    #[inline(always)]
    fn day_from_cmp(cmp_ts: i64, ws_day: i32, ws_rem: u64) -> i32 {
        let ts_rel = (cmp_ts - MS_CLICK_REACH) as u64;
        ws_day + ((ws_rem + ts_rel) / (MS_DAY as u64)) as i32
    }

    #[inline(always)]
    fn day_end_cmp(day: i32, ws_day: i32, ws_rem: u64) -> i64 {
        MS_CLICK_REACH + ((day - ws_day + 1) as i64) * MS_DAY - (ws_rem as i64)
    }

    #[inline(always)]
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool {
        (cur_cmp - prev_cmp) > MS_SESSION_GAP
    }
}

impl Stage5Event for PersonEventWide {
    const FAST_DAY_BOUND: bool = false;
    type Grouped = CompactEventWide;

    #[inline(always)]
    fn person_key(&self) -> CompactKey64 {
        self.person_key
    }

    #[inline(always)]
    fn to_grouped(&self) -> CompactEventWide {
        CompactEventWide {
            ts_ms: self.ts_ms,
            price_cents: self.price_cents,
            cat_id: self.cat_id,
        }
    }

    #[inline(always)]
    fn sort_grouped(slice: &mut [CompactEventWide], _scratch: &mut Vec<u64>) {
        if slice.len() > 1 {
            slice.sort_unstable_by_key(|e| e.ts_ms);
        }
    }

    #[inline(always)]
    fn unpack_cmp_price_cat(g: CompactEventWide) -> (i64, u32, u32) {
        (g.ts_ms, g.price_cents, g.cat_id)
    }

    #[inline(always)]
    fn day_from_cmp(cmp_ts: i64, _ws_day: i32, _ws_rem: u64) -> i32 {
        cmp_ts.div_euclid(MS_DAY) as i32
    }

    #[inline(always)]
    fn day_end_cmp(_day: i32, _ws_day: i32, _ws_rem: u64) -> i64 {
        0
    }

    #[inline(always)]
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool {
        (cur_cmp as i128 - prev_cmp as i128) > MS_SESSION_GAP as i128
    }
}

impl Stage5Click for PersonClick16 {
    type Grouped = CompactClick16;

    #[inline(always)]
    fn click_person(&self, _cl_ext: &[Vec<ExtClick>]) -> ClickPerson {
        if (self.w0 & CL_TAG_MASK) == CL_UB37 {
            ClickPerson::Uh42Rem(self.w0 & CL_REM34_MASK)
        } else {
            let pk = CompactKey64(self.w1);
            if pk.is_uh42() {
                ClickPerson::Uh42Rem(pk.uh42_val() & CL_REM34_MASK)
            } else {
                ClickPerson::Gen(pk)
            }
        }
    }

    #[inline(always)]
    fn to_grouped(&self, cl_ext: &[Vec<ExtClick>]) -> CompactClick16 {
        if (self.w0 & CL_TAG_MASK) == CL_UB37 {
            let ts_rel_ms =
                ((((self.w0 >> 34) & 0x1FF) << 22) | ((self.w1 >> 42) & 0x3F_FFFF)) as u32;
            let camp_id = ((self.w0 >> 43) & 0x7_FFFF) as u32;
            CompactClick16 {
                ts_rel_ms,
                camp_id,
                click_id_key: CompactKey64::from_kb37(self.w1 & B37_MASK42),
            }
        } else {
            let payload = self.w0 & !CL_TAG_MASK;
            let wid = (payload >> 40) as usize;
            let idx = (payload & PE_EXT_IDX_MASK) as usize;
            let ec = unsafe { *cl_ext.get_unchecked(wid).get_unchecked(idx) };
            CompactClick16 {
                ts_rel_ms: ec.ts_rel_ms,
                camp_id: ec.camp_id,
                click_id_key: ec.click_id_key,
            }
        }
    }

    #[inline(always)]
    fn sort_grouped(slice: &mut [CompactClick16]) {
        let n = slice.len();
        if n <= 1 {
            return;
        }
        if n == 2 {
            if slice[0].ts_rel_ms > slice[1].ts_rel_ms {
                slice.swap(0, 1);
            }
            return;
        }
        if n <= 24 {
            for i in 1..n {
                let key = unsafe { *slice.get_unchecked(i) };
                let mut j = i;
                while j > 0 {
                    let prev = unsafe { *slice.get_unchecked(j - 1) };
                    if prev.ts_rel_ms <= key.ts_rel_ms {
                        break;
                    }
                    unsafe {
                        *slice.get_unchecked_mut(j) = prev;
                    }
                    j -= 1;
                }
                unsafe {
                    *slice.get_unchecked_mut(j) = key;
                }
            }
            return;
        }
        slice.sort_unstable_by_key(|c| c.ts_rel_ms);
    }

    #[inline(always)]
    fn unpack_full(g: &CompactClick16) -> (i64, u32, CompactKey64) {
        (g.ts_rel_ms as i64, g.camp_id, g.click_id_key)
    }

    #[inline(always)]
    fn within_reach(sess_cmp: i64, click_cmp: i64) -> bool {
        (sess_cmp - click_cmp) <= MS_CLICK_REACH
    }
}

impl Stage5Click for PersonClickWide {
    type Grouped = CompactClickWide;

    #[inline(always)]
    fn click_person(&self, _cl_ext: &[Vec<ExtClick>]) -> ClickPerson {
        if self.person_key.is_uh42() {
            ClickPerson::Uh42Rem(self.person_key.uh42_val() & CL_REM34_MASK)
        } else {
            ClickPerson::Gen(self.person_key)
        }
    }

    #[inline(always)]
    fn to_grouped(&self, _cl_ext: &[Vec<ExtClick>]) -> CompactClickWide {
        CompactClickWide {
            ts_ms: self.ts_ms,
            camp_id: self.camp_id,
            _pad: 0,
            click_id_key: self.click_id_key,
        }
    }

    #[inline(always)]
    fn sort_grouped(slice: &mut [CompactClickWide]) {
        if slice.len() > 1 {
            slice.sort_unstable_by_key(|c| c.ts_ms);
        }
    }

    #[inline(always)]
    fn unpack_full(g: &CompactClickWide) -> (i64, u32, CompactKey64) {
        (g.ts_ms, g.camp_id, g.click_id_key)
    }

    #[inline(always)]
    fn within_reach(sess_cmp: i64, click_cmp: i64) -> bool {
        (sess_cmp as i128 - click_cmp as i128) <= MS_CLICK_REACH as i128
    }
}

#[inline(always)]
fn aux_tag34(pk: CompactKey64) -> u64 {
    if pk.is_comp() {
        pk.comp_id() as u64
    } else {
        (1u64 << 33) | (pk.hex_h20() as u64)
    }
}

#[inline(always)]
fn aux_pos(tag34: u64, aux_mask: usize) -> usize {
    let h = (tag34 ^ (tag34 >> 8)).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    (((h >> 44) ^ (h >> 28)) as usize) & aux_mask
}

#[inline(never)]
#[cold]
fn rehash_p_slots_b37(
    p_slots_b37: &mut Vec<u64>,
    p_cap: &mut usize,
    p_mask: &mut usize,
    p_thresh: &mut usize,
    persons: &[CompactKey64],
) {
    *p_cap *= 2;
    *p_mask = *p_cap - 1;
    *p_thresh = *p_cap * 6 / 10;
    p_slots_b37.clear();
    p_slots_b37.resize(*p_cap, 0u64);
    let mask = *p_mask;
    for (existing_pid, &existing_key) in persons.iter().enumerate() {
        if existing_key.is_uh42() {
            let r34 = existing_key.uh42_val() & CL_REM34_MASK;
            let mut pos = (r34 as usize) & mask;
            while unsafe { *p_slots_b37.get_unchecked(pos) } != 0 {
                pos = (pos + 1) & mask;
            }
            unsafe {
                *p_slots_b37.get_unchecked_mut(pos) = (r34 << 30) | ((existing_pid as u64) + 1);
            }
        }
    }
}

#[inline(never)]
#[cold]
fn rehash_p_slots_aux(
    p_slots_aux: &mut Vec<u64>,
    aux_cap: &mut usize,
    aux_mask: &mut usize,
    aux_thresh: &mut usize,
    persons: &[CompactKey64],
) {
    *aux_cap *= 2;
    *aux_mask = *aux_cap - 1;
    *aux_thresh = *aux_cap * 6 / 10;
    p_slots_aux.clear();
    p_slots_aux.resize(*aux_cap, 0u64);
    let mask = *aux_mask;
    for (existing_pid, &existing_key) in persons.iter().enumerate() {
        if existing_key.is_comp() || existing_key.is_hex() {
            let t34 = aux_tag34(existing_key);
            let mut pos = aux_pos(t34, mask);
            while unsafe { *p_slots_aux.get_unchecked(pos) } != 0 {
                pos = (pos + 1) & mask;
            }
            unsafe {
                *p_slots_aux.get_unchecked_mut(pos) = (t34 << 30) | ((existing_pid as u64) + 1);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_stage5<E: Stage5Event, C: Stage5Click, const PD: bool>(
    person_event_chunks: Vec<Vec<MutChunkRef<E>>>,
    person_click_chunks: Vec<Vec<MutChunkRef<C>>>,
    person_event_counts: &[usize],
    person_click_counts: &[usize],
    cl_ext: &[Vec<ExtClick>],
    ev_arenas: &[LongArena],
    ev_hex: &[Vec<Hex128>],
    cl_arenas: &[LongArena],
    cl_hex: &[Vec<Hex128>],
    link_map: &LinkMap,
    lookups: &Lookups,
    ud_dir: &Path,
    ncpu: usize,
    min_day: i32,
    max_day: i32,
    ws_day: i32,
    ws_rem: u64,
    detail: &DetailStats,
) -> io::Result<(Vec<CampDailyAcc>, usize)> {
    let mut shard_order: Vec<usize> = (0..P_PERSON).collect();
    shard_order.sort_unstable_by(|&a, &b| {
        let wa = person_event_counts[a] + person_click_counts[a];
        let wb = person_event_counts[b] + person_click_counts[b];
        wb.cmp(&wa)
    });

    let mut shard_data: Vec<(Vec<MutChunkRef<E>>, Vec<MutChunkRef<C>>, usize, usize)> =
        person_event_chunks
            .into_iter()
            .zip(person_click_chunks.into_iter())
            .zip(
                person_event_counts
                    .iter()
                    .copied()
                    .zip(person_click_counts.iter().copied()),
            )
            .map(|((eb, cb), (ec, cc))| (eb, cb, ec, cc))
            .collect();
    let shard_slots: Vec<Mutex<Option<(Vec<MutChunkRef<E>>, Vec<MutChunkRef<C>>, usize, usize)>>> =
        shard_data.drain(..).map(|item| Mutex::new(Some(item))).collect();

    let n_out_workers = ncpu.max(1).min(P_PERSON);
    let next_order = AtomicUsize::new(0);
    let num_camps = lookups.camp_entries.len();
    let num_cats = lookups.categories.len();
    let organic_camp = lookups.organic_camp_id;
    let total_events: usize = person_event_counts.iter().sum();
    let ud_batch_rows = (total_events / (8 * n_out_workers).max(1)).clamp(4096, USER_DAILY_BATCH_ROWS);

    let mut worker_accs: Vec<CampDailyAcc> = (0..n_out_workers)
        .map(|_| CampDailyAcc::new(num_camps, min_day, max_day, total_events))
        .collect();
    let mut worker_ud_rows = vec![0usize; n_out_workers];
    let err_lock = Mutex::new(None::<io::Error>);

    std::thread::scope(|scope| {
        for (wid, (acc, ud_rows_out)) in worker_accs
            .iter_mut()
            .zip(worker_ud_rows.iter_mut())
            .enumerate()
        {
            let slots_ref = &shard_slots;
            let order_ref = &shard_order;
            let next_ref = &next_order;
            let err_lock_ref = &err_lock;
            let ud_path = ud_dir.join(format!("part-{wid}.parquet"));

            scope.spawn(move || {
                let mut ev_csr_p1_ns = 0u64;
                let mut ev_csr_p2_ns = 0u64;
                let mut cl_csr_ns = 0u64;
                let mut sort_ns = 0u64;
                let mut sess_attr_ns = 0u64;
                let mut ud_ns = 0u64;

                let t_uc = if PD { Some(Instant::now()) } else { None };
                let mut writer = match UserDailyWriter::create(
                    &ud_path,
                    ud_batch_rows,
                    &lookups.categories,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        *err_lock_ref.lock().unwrap() = Some(e);
                        return;
                    }
                };
                if let Some(t) = t_uc {
                    ud_ns += t.elapsed().as_nanos() as u64;
                }

                // Hoisted per-worker reusable buffers (zero per-shard malloc/free).
                let mut p_slots_b37: Vec<u64> = Vec::new();
                let mut p_slots_aux: Vec<u64> = Vec::new();
                let mut persons: Vec<CompactKey64> = Vec::new();
                let mut ev_counts: Vec<u32> = Vec::new();
                let mut gen_p_table: HashTable<u32> = HashTable::new();
                let mut ev_pids: Vec<u32> = Vec::new();
                let mut ev_offsets: Vec<u32> = Vec::new();
                let mut ev_fill: Vec<u32> = Vec::new();
                let mut grouped_events: Vec<E::Grouped> = Vec::new();
                let mut cl_counts: Vec<u32> = Vec::new();
                let mut cl_pids: Vec<u32> = Vec::new();
                let mut cl_offsets: Vec<u32> = Vec::new();
                let mut cl_fill: Vec<u32> = Vec::new();
                let mut grouped_clicks: Vec<C::Grouped> = Vec::new();
                let mut radix_scratch: Vec<u64> = Vec::new();

                let mut cat_rev = vec![0i64; num_cats];
                let mut touched_cats: Vec<u32> = Vec::with_capacity(32);
                let mut active_count = vec![0u32; num_camps];
                let mut active_pos = vec![0u32; num_camps];
                let mut active_list: Vec<u32> = Vec::with_capacity(64);
                let mut sessions: Vec<SessionInfo> = Vec::with_capacity(256);
                let mut day_ranges: Vec<DayRange> = Vec::with_capacity(32);
                let mut camp_clicks: Vec<(u32, i64)> = Vec::with_capacity(256);
                let mut pbuf = [0u8; 40];
                const RING: usize = 16;

                loop {
                    let ord_idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(&shard_idx) = order_ref.get(ord_idx) else {
                        break;
                    };
                    let Some((evs_chunks, cls_chunks, ev_total, cl_total)) =
                        slots_ref[shard_idx].lock().unwrap().take()
                    else {
                        break;
                    };
                    if ev_total == 0 {
                        continue;
                    }

                    // 1. Unified branchless L1/L2 intern via 8B p_slots_b37, L1 8B p_slots_aux (comp + hex32), and rare gen_p_table.
                    let t_ev = if PD { Some(Instant::now()) } else { None };
                    let mut p_cap = (ev_total / 10).max(256).next_power_of_two();
                    let mut p_mask = p_cap - 1;
                    let mut p_thresh = p_cap * 6 / 10;
                    p_slots_b37.clear();
                    p_slots_b37.resize(p_cap, 0u64);
                    let mut p_b37_count = 0usize;

                    let mut aux_cap = (ev_total / 16).max(256).next_power_of_two();
                    let mut aux_mask = aux_cap - 1;
                    let mut aux_thresh = aux_cap * 6 / 10;
                    p_slots_aux.clear();
                    p_slots_aux.resize(aux_cap, 0u64);
                    let mut p_aux_count = 0usize;

                    persons.clear();
                    ev_counts.clear();
                    gen_p_table.clear();
                    let mut has_gen_p = false;
                    ev_pids.clear();
                    ev_pids.reserve(ev_total);
                    let ev_pids_ptr = ev_pids.as_mut_ptr();
                    let mut ev_pid_pos = 0usize;

                    for chunk in &evs_chunks {
                        let batch = unsafe { chunk.as_slice() };
                        let blen = batch.len();
                        let pre = blen.min(RING);
                        for i in 0..pre {
                            let pk = unsafe { batch.get_unchecked(i).person_key() };
                            if pk.is_uh42() {
                                let rem34 = pk.uh42_val() & CL_REM34_MASK;
                                let npos = (rem34 as usize) & p_mask;
                                #[cfg(target_arch = "x86_64")]
                                unsafe {
                                    std::arch::x86_64::_mm_prefetch(
                                        p_slots_b37.as_ptr().add(npos) as *const i8,
                                        std::arch::x86_64::_MM_HINT_T0,
                                    );
                                }
                            } else if pk.is_comp() || pk.is_hex() {
                                let t34 = aux_tag34(pk);
                                let npos = aux_pos(t34, aux_mask);
                                #[cfg(target_arch = "x86_64")]
                                unsafe {
                                    std::arch::x86_64::_mm_prefetch(
                                        p_slots_aux.as_ptr().add(npos) as *const i8,
                                        std::arch::x86_64::_MM_HINT_T0,
                                    );
                                    if pk.is_hex() {
                                        std::arch::x86_64::_mm_prefetch(
                                            ev_hex
                                                .get_unchecked(pk.hex_wid())
                                                .as_ptr()
                                                .add(pk.hex_idx())
                                                as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                }
                            }
                        }
                        for (ridx, ev) in batch.iter().enumerate() {
                            if ridx + RING < blen {
                                let pk_ahead =
                                    unsafe { batch.get_unchecked(ridx + RING).person_key() };
                                if pk_ahead.is_uh42() {
                                    let nrem = pk_ahead.uh42_val() & CL_REM34_MASK;
                                    let npos = (nrem as usize) & p_mask;
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            p_slots_b37.as_ptr().add(npos) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                } else if pk_ahead.is_comp() || pk_ahead.is_hex() {
                                    let t34 = aux_tag34(pk_ahead);
                                    let npos = aux_pos(t34, aux_mask);
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            p_slots_aux.as_ptr().add(npos) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                        if pk_ahead.is_hex() {
                                            std::arch::x86_64::_mm_prefetch(
                                                ev_hex
                                                    .get_unchecked(pk_ahead.hex_wid())
                                                    .as_ptr()
                                                    .add(pk_ahead.hex_idx())
                                                    as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                    }
                                }
                            }
                            let pk = ev.person_key();
                            let pid = if pk.is_uh42() {
                                let rem34 = pk.uh42_val() & CL_REM34_MASK;
                                let mut pos = (rem34 as usize) & p_mask;
                                loop {
                                    let s = unsafe { *p_slots_b37.get_unchecked(pos) };
                                    if s != 0 {
                                        if (s >> 30) == rem34 {
                                            let id = ((s & ((1 << 30) - 1)) - 1) as u32;
                                            unsafe {
                                                *ev_counts.get_unchecked_mut(id as usize) += 1;
                                            }
                                            break id;
                                        }
                                        pos = (pos + 1) & p_mask;
                                        continue;
                                    }
                                    let id = persons.len() as u32;
                                    persons.push(pk);
                                    ev_counts.push(1);
                                    unsafe {
                                        *p_slots_b37.get_unchecked_mut(pos) =
                                            (rem34 << 30) | ((id as u64) + 1);
                                    }
                                    p_b37_count += 1;
                                    if p_b37_count >= p_thresh {
                                        rehash_p_slots_b37(
                                            &mut p_slots_b37,
                                            &mut p_cap,
                                            &mut p_mask,
                                            &mut p_thresh,
                                            &persons,
                                        );
                                    }
                                    break id;
                                }
                            } else if pk.is_comp() || pk.is_hex() {
                                let is_hex = pk.is_hex();
                                let tag34 = aux_tag34(pk);
                                let mut pos = aux_pos(tag34, aux_mask);
                                loop {
                                    let s = unsafe { *p_slots_aux.get_unchecked(pos) };
                                    if s != 0 {
                                        if (s >> 30) == tag34 {
                                            let id = ((s & ((1 << 30) - 1)) - 1) as u32;
                                            let matched = if is_hex {
                                                unsafe {
                                                    persons
                                                        .get_unchecked(id as usize)
                                                        .resolve_hex(ev_hex)
                                                        == pk.resolve_hex(ev_hex)
                                                }
                                            } else {
                                                true
                                            };
                                            if matched {
                                                unsafe {
                                                    *ev_counts.get_unchecked_mut(id as usize) += 1;
                                                }
                                                break id;
                                            }
                                        }
                                        pos = (pos + 1) & aux_mask;
                                        continue;
                                    }
                                    let id = persons.len() as u32;
                                    persons.push(pk);
                                    ev_counts.push(1);
                                    unsafe {
                                        *p_slots_aux.get_unchecked_mut(pos) =
                                            (tag34 << 30) | ((id as u64) + 1);
                                    }
                                    p_aux_count += 1;
                                    if p_aux_count >= aux_thresh {
                                        rehash_p_slots_aux(
                                            &mut p_slots_aux,
                                            &mut aux_cap,
                                            &mut aux_mask,
                                            &mut aux_thresh,
                                            &persons,
                                        );
                                    }
                                    break id;
                                }
                            } else {
                                has_gen_p = true;
                                let ph = hash_person_key(pk, ev_arenas, ev_hex);
                                match gen_p_table.entry(
                                    ph,
                                    |&id| {
                                        eq_person_keys(
                                            persons[id as usize],
                                            pk,
                                            ev_arenas,
                                            ev_hex,
                                            ev_arenas,
                                            ev_hex,
                                        )
                                    },
                                    |&id| hash_person_key(persons[id as usize], ev_arenas, ev_hex),
                                ) {
                                    hashbrown::hash_table::Entry::Occupied(occ) => {
                                        let id = *occ.get();
                                        unsafe {
                                            *ev_counts.get_unchecked_mut(id as usize) += 1;
                                        }
                                        id
                                    }
                                    hashbrown::hash_table::Entry::Vacant(vac) => {
                                        let id = persons.len() as u32;
                                        persons.push(pk);
                                        ev_counts.push(1);
                                        vac.insert(id);
                                        id
                                    }
                                }
                            };
                            unsafe {
                                ev_pids_ptr.add(ev_pid_pos).write(pid);
                            }
                            ev_pid_pos += 1;
                        }
                    }
                    debug_assert_eq!(ev_pid_pos, ev_total);
                    unsafe {
                        ev_pids.set_len(ev_total);
                    }

                    if let Some(t) = t_ev {
                        ev_csr_p1_ns += t.elapsed().as_nanos() as u64;
                    }
                    let t_ev2 = if PD { Some(Instant::now()) } else { None };
                    let num_p = persons.len();
                    debug_assert_eq!(ev_counts.len(), num_p);
                    ev_offsets.clear();
                    ev_offsets.resize(num_p + 1, 0);
                    for i in 0..num_p {
                        unsafe {
                            let cur = *ev_offsets.get_unchecked(i);
                            let cnt = *ev_counts.get_unchecked(i);
                            *ev_offsets.get_unchecked_mut(i + 1) = cur + cnt;
                        }
                    }
                    ev_fill.clear();
                    ev_fill.extend_from_slice(&ev_offsets[..num_p]);
                    grouped_events.clear();
                    grouped_events.reserve(ev_total);
                    debug_assert!(grouped_events.capacity() >= ev_total);
                    let ev_ptr = grouped_events.as_mut_ptr();
                    let mut pid_idx = 0usize;
                    for chunk in evs_chunks {
                        for &ev in unsafe { chunk.as_slice() } {
                            let pid = unsafe { *ev_pids.get_unchecked(pid_idx) } as usize;
                            pid_idx += 1;
                            let pos = unsafe { *ev_fill.get_unchecked(pid) } as usize;
                            unsafe {
                                *ev_fill.get_unchecked_mut(pid) = (pos + 1) as u32;
                                std::ptr::write(ev_ptr.add(pos), ev.to_grouped());
                            }
                        }
                    }
                    unsafe {
                        grouped_events.set_len(ev_total);
                    }
                    if let Some(t) = t_ev2 {
                        ev_csr_p2_ns += t.elapsed().as_nanos() as u64;
                    }

                    // 2. Group matching clicks into CSR by pid (skip clicks for event-less persons).
                    let t_cl = if PD { Some(Instant::now()) } else { None };
                    let mut total_matched_cl = 0usize;
                    if cl_total > 0 {
                        cl_counts.clear();
                        cl_counts.resize(num_p, 0);
                        cl_pids.clear();
                        cl_pids.reserve(cl_total);
                        let cl_pids_ptr = cl_pids.as_mut_ptr();
                        let mut cl_pid_pos = 0usize;
                        let has_aux_p = p_aux_count > 0;
                        for chunk in &cls_chunks {
                            let batch = unsafe { chunk.as_slice() };
                            let blen = batch.len();
                            let pre = blen.min(RING);
                            for i in 0..pre {
                                match unsafe { batch.get_unchecked(i).click_person(cl_ext) } {
                                    ClickPerson::Uh42Rem(rem34) => {
                                        let npos = (rem34 as usize) & p_mask;
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                p_slots_b37.as_ptr().add(npos) as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                    }
                                    ClickPerson::Gen(ck)
                                        if has_aux_p && (ck.is_comp() || ck.is_hex()) =>
                                    {
                                        let t34 = aux_tag34(ck);
                                        let npos = aux_pos(t34, aux_mask);
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                p_slots_aux.as_ptr().add(npos) as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                    }
                                    ClickPerson::Gen(_) => {}
                                }
                            }
                            for (ridx, c) in batch.iter().enumerate() {
                                if ridx + RING < blen {
                                    match unsafe {
                                        batch.get_unchecked(ridx + RING).click_person(cl_ext)
                                    } {
                                        ClickPerson::Uh42Rem(nrem) => {
                                            let npos = (nrem as usize) & p_mask;
                                            #[cfg(target_arch = "x86_64")]
                                            unsafe {
                                                std::arch::x86_64::_mm_prefetch(
                                                    p_slots_b37.as_ptr().add(npos) as *const i8,
                                                    std::arch::x86_64::_MM_HINT_T0,
                                                );
                                            }
                                        }
                                        ClickPerson::Gen(ck)
                                            if has_aux_p && (ck.is_comp() || ck.is_hex()) =>
                                        {
                                            let t34 = aux_tag34(ck);
                                            let npos = aux_pos(t34, aux_mask);
                                            #[cfg(target_arch = "x86_64")]
                                            unsafe {
                                                std::arch::x86_64::_mm_prefetch(
                                                    p_slots_aux.as_ptr().add(npos) as *const i8,
                                                    std::arch::x86_64::_MM_HINT_T0,
                                                );
                                            }
                                        }
                                        ClickPerson::Gen(_) => {}
                                    }
                                }
                                let pid = match c.click_person(cl_ext) {
                                    ClickPerson::Uh42Rem(rem34) => {
                                        let mut pos = (rem34 as usize) & p_mask;
                                        loop {
                                            let s = unsafe { *p_slots_b37.get_unchecked(pos) };
                                            if s != 0 {
                                                if (s >> 30) == rem34 {
                                                    break ((s & ((1 << 30) - 1)) - 1) as u32;
                                                }
                                                pos = (pos + 1) & p_mask;
                                                continue;
                                            }
                                            break u32::MAX;
                                        }
                                    }
                                    ClickPerson::Gen(ck) => {
                                        if ck.is_comp() || ck.is_hex() {
                                            if has_aux_p {
                                                let is_hex = ck.is_hex();
                                                let tag34 = aux_tag34(ck);
                                                let mut pos = aux_pos(tag34, aux_mask);
                                                loop {
                                                    let s =
                                                        unsafe { *p_slots_aux.get_unchecked(pos) };
                                                    if s != 0 {
                                                        if (s >> 30) == tag34 {
                                                            let id =
                                                                ((s & ((1 << 30) - 1)) - 1) as u32;
                                                            let matched = if is_hex {
                                                                unsafe {
                                                                    persons
                                                                        .get_unchecked(
                                                                            id as usize,
                                                                        )
                                                                        .resolve_hex(ev_hex)
                                                                        == ck.resolve_hex(cl_hex)
                                                                }
                                                            } else {
                                                                true
                                                            };
                                                            if matched {
                                                                break id;
                                                            }
                                                        }
                                                        pos = (pos + 1) & aux_mask;
                                                        continue;
                                                    }
                                                    break u32::MAX;
                                                }
                                            } else {
                                                u32::MAX
                                            }
                                        } else if has_gen_p {
                                            let ch = hash_person_key(ck, cl_arenas, cl_hex);
                                            gen_p_table
                                                .find(ch, |&id| {
                                                    eq_person_keys(
                                                        persons[id as usize],
                                                        ck,
                                                        ev_arenas,
                                                        ev_hex,
                                                        cl_arenas,
                                                        cl_hex,
                                                    )
                                                })
                                                .copied()
                                                .unwrap_or(u32::MAX)
                                        } else {
                                            u32::MAX
                                        }
                                    }
                                };
                                if pid != u32::MAX {
                                    total_matched_cl += 1;
                                    unsafe {
                                        *cl_counts.get_unchecked_mut(pid as usize) += 1;
                                    }
                                }
                                unsafe {
                                    cl_pids_ptr.add(cl_pid_pos).write(pid);
                                }
                                cl_pid_pos += 1;
                            }
                        }
                        debug_assert_eq!(cl_pid_pos, cl_total);
                        unsafe {
                            cl_pids.set_len(cl_total);
                        }

                        if total_matched_cl > 0 {
                            cl_offsets.clear();
                            cl_offsets.resize(num_p + 1, 0);
                            for i in 0..num_p {
                                unsafe {
                                    let cur = *cl_offsets.get_unchecked(i);
                                    let cnt = *cl_counts.get_unchecked(i);
                                    *cl_offsets.get_unchecked_mut(i + 1) = cur + cnt;
                                }
                            }
                            cl_fill.clear();
                            cl_fill.extend_from_slice(&cl_offsets[..num_p]);
                            grouped_clicks.clear();
                            grouped_clicks.reserve(total_matched_cl);
                            debug_assert!(grouped_clicks.capacity() >= total_matched_cl);
                            let cl_ptr = grouped_clicks.as_mut_ptr();
                            let mut cpid_idx = 0usize;
                            for chunk in cls_chunks {
                                for c in unsafe { chunk.as_slice() } {
                                    let pid = unsafe { *cl_pids.get_unchecked(cpid_idx) };
                                    cpid_idx += 1;
                                    if pid != u32::MAX {
                                        let pos =
                                            unsafe { *cl_fill.get_unchecked(pid as usize) } as usize;
                                        unsafe {
                                            *cl_fill.get_unchecked_mut(pid as usize) =
                                                (pos + 1) as u32;
                                            std::ptr::write(cl_ptr.add(pos), c.to_grouped(cl_ext));
                                        }
                                    }
                                }
                            }
                            unsafe {
                                grouped_clicks.set_len(total_matched_cl);
                            }
                        }
                    }
                    if let Some(t) = t_cl {
                        cl_csr_ns += t.elapsed().as_nanos() as u64;
                    }

                    // 3. Process each person independently.
                    let t_p3 = if PD { Some(Instant::now()) } else { None };
                    let c_p3_0 = if PD { rdtsc_now() } else { 0 };
                    let mut shard_sort_cyc = 0u64;
                    let mut shard_ud_cyc = 0u64;
                    for pid in 0..num_p {
                        let e_lo = ev_offsets[pid] as usize;
                        let e_hi = ev_offsets[pid + 1] as usize;
                        let evs = &mut grouped_events[e_lo..e_hi];
                        let c_s = if PD { rdtsc_now() } else { 0 };
                        E::sort_grouped(evs, &mut radix_scratch);
                        if PD {
                            shard_sort_cyc += rdtsc_now().wrapping_sub(c_s);
                        }

                        let person_bytes = resolve_person_bytes(
                            persons[pid],
                            link_map,
                            ev_arenas,
                            ev_hex,
                            &mut pbuf,
                        );
                        let has_clicks = total_matched_cl > 0 && cl_offsets[pid] < cl_offsets[pid + 1];
                        if has_clicks {
                            sessions.clear();
                        }

                        let (mut sess_start, price0, cat0) = E::unpack_cmp_price_cat(evs[0]);
                        let mut cur_day = E::day_from_cmp(sess_start, ws_day, ws_rem);
                        let mut cur_day_end_cmp = if E::FAST_DAY_BOUND {
                            E::day_end_cmp(cur_day, ws_day, ws_rem)
                        } else {
                            0
                        };
                        let mut sess_has_purch = u32::from(price0 > 0);
                        let mut sess_rev = price0 as i64;
                        let mut prev_ts = sess_start;

                        let mut day_sessions = 1i64;
                        let mut day_purch_sessions = 0u32;
                        let mut day_events = 1i64;
                        let mut day_rev = price0 as i64;
                        if price0 > 0 {
                            cat_rev[cat0 as usize] = price0 as i64;
                            touched_cats.push(cat0);
                        }

                        for &ev_item in &evs[1..] {
                            let (e_ts, e_price, e_cat) = E::unpack_cmp_price_cat(ev_item);
                            if E::gap_exceeds(e_ts, prev_ts) {
                                if has_clicks {
                                    sessions.push(SessionInfo {
                                        start_cmp: sess_start,
                                        day: cur_day,
                                        has_purchase: sess_has_purch,
                                        revenue_cents: sess_rev,
                                    });
                                } else {
                                    day_purch_sessions += sess_has_purch;
                                }
                                sess_start = e_ts;
                                sess_has_purch = 0;
                                sess_rev = 0;

                                let next_day = if E::FAST_DAY_BOUND && e_ts < cur_day_end_cmp {
                                    cur_day
                                } else {
                                    E::day_from_cmp(e_ts, ws_day, ws_rem)
                                };
                                if next_day != cur_day {
                                    let top_cat =
                                        pick_and_reset_top_cat_id(&mut cat_rev, &mut touched_cats);
                                    let c_u = if PD { rdtsc_now() } else { 0 };
                                    let push_res = writer.push(
                                        person_bytes,
                                        cur_day,
                                        day_sessions,
                                        day_events,
                                        day_rev,
                                        top_cat,
                                    );
                                    if PD {
                                        shard_ud_cyc += rdtsc_now().wrapping_sub(c_u);
                                    }
                                    if let Err(err) = push_res {
                                        *err_lock_ref.lock().unwrap() = Some(err);
                                        return;
                                    }
                                    if !has_clicks {
                                        acc.add_credit_batch(
                                            organic_camp,
                                            cur_day,
                                            day_sessions as u32,
                                            day_purch_sessions,
                                            day_rev,
                                        );
                                    }
                                    cur_day = next_day;
                                    if E::FAST_DAY_BOUND {
                                        cur_day_end_cmp = E::day_end_cmp(cur_day, ws_day, ws_rem);
                                    }
                                    day_sessions = 0;
                                    day_purch_sessions = 0;
                                    day_events = 0;
                                    day_rev = 0;
                                }
                                day_sessions += 1;
                            }
                            prev_ts = e_ts;
                            day_events += 1;
                            if e_price > 0 {
                                let p64 = e_price as i64;
                                sess_has_purch = 1;
                                sess_rev += p64;
                                day_rev += p64;
                                let cid = e_cat as usize;
                                if cat_rev[cid] == 0 {
                                    touched_cats.push(e_cat);
                                }
                                cat_rev[cid] += p64;
                            }
                        }

                        let top_cat = pick_and_reset_top_cat_id(&mut cat_rev, &mut touched_cats);
                        let c_u = if PD { rdtsc_now() } else { 0 };
                        let push_res = writer.push(
                            person_bytes,
                            cur_day,
                            day_sessions,
                            day_events,
                            day_rev,
                            top_cat,
                        );
                        if PD {
                            shard_ud_cyc += rdtsc_now().wrapping_sub(c_u);
                        }
                        if let Err(err) = push_res {
                            *err_lock_ref.lock().unwrap() = Some(err);
                            return;
                        }

                        if !has_clicks {
                            day_purch_sessions += sess_has_purch;
                            acc.add_credit_batch(
                                organic_camp,
                                cur_day,
                                day_sessions as u32,
                                day_purch_sessions,
                                day_rev,
                            );
                            continue;
                        }

                        sessions.push(SessionInfo {
                            start_cmp: sess_start,
                            day: cur_day,
                            has_purchase: sess_has_purch,
                            revenue_cents: sess_rev,
                        });

                        // Credit + Assists
                        let c_lo = cl_offsets[pid] as usize;
                        let c_hi = cl_offsets[pid + 1] as usize;
                        let clks = &mut grouped_clicks[c_lo..c_hi];
                        if clks.len() == 1 {
                            let (cts, ccamp, _) = C::unpack_full(&clks[0]);
                            let mut a_day = sessions[0].day;
                            let mut a_cnt = 0i64;
                            for s in &sessions {
                                if cts <= s.start_cmp && C::within_reach(s.start_cmp, cts) {
                                    acc.add_credit(ccamp, s.day, s.has_purchase, s.revenue_cents);
                                    if s.day == a_day {
                                        a_cnt += 1;
                                    } else {
                                        if a_cnt > 0 {
                                            acc.add_assist(ccamp, a_day, a_cnt);
                                        }
                                        a_day = s.day;
                                        a_cnt = 1;
                                    }
                                } else {
                                    acc.add_credit(
                                        organic_camp,
                                        s.day,
                                        s.has_purchase,
                                        s.revenue_cents,
                                    );
                                }
                            }
                            if a_cnt > 0 {
                                acc.add_assist(ccamp, a_day, a_cnt);
                            }
                            continue;
                        }

                        let c_s2 = if PD { rdtsc_now() } else { 0 };
                        C::sort_grouped(clks);
                        if PD {
                            shard_sort_cyc += rdtsc_now().wrapping_sub(c_s2);
                        }

                        if sessions.len() <= 32 && clks.len() <= 64 {
                            let mut left = 0usize;
                            let mut right = 0usize;
                            let mut has_click = false;
                            let mut best_ts = i64::MIN;
                            let mut best_camp = 0u32;
                            let mut best_ckey = CompactKey64::EMPTY;
                            let mut batch_day = sessions[0].day;
                            let mut batch_cnt = 0u32;

                            for s in &sessions {
                                while right < clks.len() {
                                    let (cts, ccamp, ckey) = C::unpack_full(&clks[right]);
                                    if cts > s.start_cmp {
                                        break;
                                    }
                                    if !has_click || cts > best_ts {
                                        has_click = true;
                                        best_ts = cts;
                                        best_camp = ccamp;
                                        best_ckey = ckey;
                                    } else if cts == best_ts
                                        && cmp_raw_keys(
                                            ckey, best_ckey, cl_arenas, cl_hex, cl_arenas, cl_hex,
                                        ) == std::cmp::Ordering::Less
                                    {
                                        best_camp = ccamp;
                                        best_ckey = ckey;
                                    }
                                    let cid = ccamp as usize;
                                    let cnt = active_count[cid];
                                    active_count[cid] = cnt + 1;
                                    if cnt == 0 {
                                        if batch_cnt > 0 {
                                            acc.add_assists_batch(&active_list, batch_day, batch_cnt);
                                            batch_cnt = 0;
                                        }
                                        active_pos[cid] = active_list.len() as u32;
                                        active_list.push(ccamp);
                                    }
                                    right += 1;
                                }
                                while left < right {
                                    let (cts, ccamp, _) = C::unpack_full(&clks[left]);
                                    if C::within_reach(s.start_cmp, cts) {
                                        break;
                                    }
                                    let cid = ccamp as usize;
                                    let cnt = active_count[cid] - 1;
                                    active_count[cid] = cnt;
                                    if cnt == 0 {
                                        if batch_cnt > 0 {
                                            acc.add_assists_batch(&active_list, batch_day, batch_cnt);
                                            batch_cnt = 0;
                                        }
                                        let pos = active_pos[cid] as usize;
                                        let last = *active_list.last().unwrap();
                                        active_list[pos] = last;
                                        active_pos[last as usize] = pos as u32;
                                        active_list.pop();
                                    }
                                    left += 1;
                                }
                                let camp = if has_click && C::within_reach(s.start_cmp, best_ts) {
                                    best_camp
                                } else {
                                    organic_camp
                                };
                                acc.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
                                if !active_list.is_empty() {
                                    if s.day != batch_day {
                                        if batch_cnt > 0 {
                                            acc.add_assists_batch(&active_list, batch_day, batch_cnt);
                                        }
                                        batch_day = s.day;
                                        batch_cnt = 1;
                                    } else {
                                        batch_cnt += 1;
                                    }
                                }
                            }
                            if batch_cnt > 0 {
                                acc.add_assists_batch(&active_list, batch_day, batch_cnt);
                            }
                            for &camp in &active_list {
                                active_count[camp as usize] = 0;
                            }
                            active_list.clear();
                        } else {
                            // Primary credit: two-pointer sweep over sorted sessions and sorted clicks
                            let mut p = 0usize;
                            let mut has_click = false;
                            let mut best_ts = i64::MIN;
                            let mut best_camp = 0u32;
                            let mut best_ckey = CompactKey64::EMPTY;
                            for s in &sessions {
                                while p < clks.len() {
                                    let (cts, ccamp, ckey) = C::unpack_full(&clks[p]);
                                    if cts > s.start_cmp {
                                        break;
                                    }
                                    if !has_click || cts > best_ts {
                                        has_click = true;
                                        best_ts = cts;
                                        best_camp = ccamp;
                                        best_ckey = ckey;
                                    } else if cts == best_ts
                                        && cmp_raw_keys(
                                            ckey, best_ckey, cl_arenas, cl_hex, cl_arenas, cl_hex,
                                        ) == std::cmp::Ordering::Less
                                    {
                                        best_camp = ccamp;
                                        best_ckey = ckey;
                                    }
                                    p += 1;
                                }
                                let camp = if has_click && C::within_reach(s.start_cmp, best_ts) {
                                    best_camp
                                } else {
                                    organic_camp
                                };
                                acc.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
                            }

                            // Assisting campaigns via interval merging
                            day_ranges.clear();
                            let mut d_lo = 0usize;
                            let mut d_cur = sessions[0].day;
                            for (i, s) in sessions.iter().enumerate() {
                                if s.day != d_cur {
                                    day_ranges.push(DayRange {
                                        day: d_cur,
                                        lo_idx: d_lo as u32,
                                        hi_idx: i as u32,
                                    });
                                    d_cur = s.day;
                                    d_lo = i;
                                }
                            }
                            day_ranges.push(DayRange {
                                day: d_cur,
                                lo_idx: d_lo as u32,
                                hi_idx: sessions.len() as u32,
                            });

                            camp_clicks.clear();
                            for c in clks.iter() {
                                let (cts, ccamp, _) = C::unpack_full(c);
                                camp_clicks.push((ccamp, cts));
                            }
                            camp_clicks.sort_unstable();

                            let mut i = 0usize;
                            while i < camp_clicks.len() {
                                let camp = camp_clicks[i].0;
                                let mut iv_start = camp_clicks[i].1;
                                let mut iv_end = iv_start.saturating_add(MS_CLICK_REACH);
                                i += 1;
                                while i < camp_clicks.len() && camp_clicks[i].0 == camp {
                                    let t = camp_clicks[i].1;
                                    if t <= iv_end {
                                        iv_end = t.saturating_add(MS_CLICK_REACH);
                                    } else {
                                        emit_interval_assists(
                                            acc,
                                            camp,
                                            iv_start,
                                            iv_end,
                                            &sessions,
                                            &day_ranges,
                                        );
                                        iv_start = t;
                                        iv_end = t.saturating_add(MS_CLICK_REACH);
                                    }
                                    i += 1;
                                }
                                emit_interval_assists(
                                    acc,
                                    camp,
                                    iv_start,
                                    iv_end,
                                    &sessions,
                                    &day_ranges,
                                );
                            }
                        }
                    }
                    if let Some(t) = t_p3 {
                        let p3_tot = t.elapsed().as_nanos() as u64;
                        let p3_cyc = rdtsc_now().wrapping_sub(c_p3_0).max(1);
                        let shard_sort_ns =
                            ((p3_tot as u128 * shard_sort_cyc as u128) / p3_cyc as u128) as u64;
                        let shard_ud_ns =
                            ((p3_tot as u128 * shard_ud_cyc as u128) / p3_cyc as u128) as u64;
                        sort_ns += shard_sort_ns;
                        ud_ns += shard_ud_ns;
                        sess_attr_ns += p3_tot.saturating_sub(shard_sort_ns + shard_ud_ns);
                    }
                }

                let t_wc = if PD { Some(Instant::now()) } else { None };
                match writer.close() {
                    Ok(rows) => {
                        *ud_rows_out = rows;
                        if rows == 0 {
                            let _ = fs::remove_file(&ud_path);
                        }
                    }
                    Err(e) => {
                        *err_lock_ref.lock().unwrap() = Some(e);
                    }
                }
                if let Some(t) = t_wc {
                    ud_ns += t.elapsed().as_nanos() as u64;
                }
                if PD {
                    detail
                        .s5_ev_csr_ns
                        .fetch_add(ev_csr_p1_ns + ev_csr_p2_ns, Ordering::Relaxed);
                    detail
                        .s5_ev_csr_p1_ns
                        .fetch_add(ev_csr_p1_ns, Ordering::Relaxed);
                    detail
                        .s5_ev_csr_p2_ns
                        .fetch_add(ev_csr_p2_ns, Ordering::Relaxed);
                    detail.s5_cl_csr_ns.fetch_add(cl_csr_ns, Ordering::Relaxed);
                    detail.s5_sort_ns.fetch_add(sort_ns, Ordering::Relaxed);
                    detail
                        .s5_sess_attr_ns
                        .fetch_add(sess_attr_ns, Ordering::Relaxed);
                    detail.s5_ud_ns.fetch_add(ud_ns, Ordering::Relaxed);
                }
            });
        }
    });

    if let Some(e) = err_lock.into_inner().unwrap() {
        return Err(e);
    }

    let total_ud_rows: usize = worker_ud_rows.iter().sum();
    Ok((worker_accs, total_ud_rows))
}

fn read_vm_hwm_kb() -> isize {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return -1;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let tok = rest.trim().split_whitespace().next().unwrap_or("");
            if let Ok(kb) = tok.parse::<isize>() {
                return kb;
            }
        }
    }
    -1
}

#[cfg(test)]
pub fn run_pipeline(data_dir: &Path, out_dir: &Path, ncpu: usize, profile: bool) -> io::Result<()> {
    run_pipeline_with_exit(data_dir, out_dir, ncpu, profile, false)
}

pub fn run_pipeline_with_exit(
    data_dir: &Path,
    out_dir: &Path,
    ncpu: usize,
    profile: bool,
    fast_exit: bool,
) -> io::Result<()> {
    let profile_detail =
        profile && std::env::var("PROFILE_DETAIL").ok().as_deref() == Some("1");
    if profile_detail {
        run_pipeline_inner::<true>(data_dir, out_dir, ncpu, profile, fast_exit)
    } else {
        run_pipeline_inner::<false>(data_dir, out_dir, ncpu, profile, fast_exit)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_typed_stages<
    E: DedupEmit + Stage5Event,
    C: ClickEmit + Stage5Click,
    const PD: bool,
>(
    dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>>,
    hex_dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<HexEvent32>>>>>,
    ev_worker_ext: Vec<Vec<ExtEvent>>,
    ev_worker_arenas: Vec<LongArena>,
    ev_worker_hex: Vec<Vec<Hex128>>,
    ev_slabs: Vec<SlabArena>,
    hex_slabs: Vec<SlabArena>,
    click_src: CsvSource,
    cl_chunks: &[crate::csv::ChunkTask],
    cl_hint_bytes: usize,
    pe_hint_bytes: usize,
    lookups: &Lookups,
    link_map: &mut LinkMap,
    ud_dir: &Path,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    click_window_start_ms: i64,
    min_day: i32,
    max_day: i32,
    ws_day: i32,
    ws_rem: u64,
    ncpu: usize,
    fast_exit: bool,
    detail: &DetailStats,
) -> io::Result<(Instant, Instant, Instant, Vec<CampDailyAcc>, usize)> {
    let out = run_clicks_and_dedup::<E, C, PD>(
        &dedup_slots,
        &hex_dedup_slots,
        &ev_worker_ext,
        &ev_worker_arenas,
        &ev_worker_hex,
        &click_src,
        cl_chunks,
        cl_hint_bytes,
        pe_hint_bytes,
        lookups,
        link_map,
        window_start_ms,
        window_end_ms,
        window_start_sec,
        click_window_start_ms,
        ncpu,
        detail,
    )?;
    let t_drop = if PD { Some(Instant::now()) } else { None };
    drop(click_src);
    drop(dedup_slots);
    drop(hex_dedup_slots);
    drop(ev_worker_ext);
    drop(ev_slabs);
    drop(hex_slabs);
    link_map.drop_lookup_tables();
    if let Some(t) = t_drop {
        detail
            .ev_drop_w_ns
            .store(t.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }
    let t_ed = Instant::now();
    let res = run_stage5::<E, C, PD>(
        out.person_event_chunks,
        out.person_click_chunks,
        &out.person_event_counts,
        &out.person_click_counts,
        &out.cl_worker_ext,
        &ev_worker_arenas,
        &ev_worker_hex,
        &out.cl_worker_arenas,
        &out.cl_worker_hex,
        link_map,
        lookups,
        ud_dir,
        ncpu,
        min_day,
        max_day,
        ws_day,
        ws_rem,
        detail,
    )?;
    if fast_exit {
        std::mem::forget(out.pe_slabs);
        std::mem::forget(out.cl_slabs);
    } else {
        drop(out.pe_slabs);
        drop(out.cl_slabs);
    }
    Ok((t_ed, t_ed, Instant::now(), res.0, res.1))
}

fn run_pipeline_inner<const PD: bool>(
    data_dir: &Path,
    out_dir: &Path,
    ncpu: usize,
    profile: bool,
    fast_exit: bool,
) -> io::Result<()> {
    let t0 = Instant::now();
    let detail = DetailStats::default();

    let manifest_bytes = fs::read(data_dir.join("manifest.json"))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let window_start_ms = parse_ts_ms(manifest.window_start.trim().as_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid window_start"))?;
    let window_end_ms = parse_ts_ms(manifest.window_end.trim().as_bytes())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid window_end"))?;
    let click_window_start_ms = window_start_ms - MS_CLICK_REACH;
    let min_day = window_start_ms.div_euclid(MS_DAY) as i32;
    let max_day = (window_end_ms - 1).div_euclid(MS_DAY) as i32;
    let window_start_sec = window_start_ms.div_euclid(1_000);
    let ws_day = window_start_ms.div_euclid(MS_DAY) as i32;
    let ws_rem = window_start_ms.rem_euclid(MS_DAY) as u64;

    let t_startup = Instant::now();
    let lookups = load_lookups(data_dir)?;
    let t_lookups = Instant::now();

    let window_span_ms = window_end_ms.saturating_sub(window_start_ms);
    let click_span_ms = window_end_ms.saturating_sub(click_window_start_ms);
    let compact_ev_mode = window_start_ms.unsigned_abs() < 1_000_000_000_000_000
        && window_start_ms.rem_euclid(1_000) == 0
        && window_span_ms >= 0
        && window_span_ms <= ((1i64 << 31) - 1)
        && lookups.categories.len() <= 256;
    let compact_click_mode = compact_ev_mode
        && click_span_ms >= 0
        && click_span_ms <= ((1i64 << 31) - 1)
        && lookups.camp_entries.len() < (1 << 19);

    // Parse events while overlapping LinkMap build when multi-threaded.
    let link_paths = list_csv_files(&data_dir.join("links"))?;
    let event_paths = list_csv_files(&data_dir.join("events"))?;
    let event_src = CsvSource::open(&event_paths)?;
    let ev_chunks = event_src.chunks(CHUNK_BYTES);
    let n_ev_workers = ncpu.clamp(1, 63).min(ev_chunks.len().max(1));
    let est_ev_total = event_src.total_bytes() / 68;
    let ev_hint_bytes = (est_ev_total * 16) / n_ev_workers.max(1);

    let (mut link_map, ev_out, links_w_done, overlap_links) = if compact_ev_mode {
        run_parse_events_and_links::<true, PD>(
            &event_src,
            &ev_chunks,
            ev_hint_bytes,
            &link_paths,
            &lookups,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            ncpu,
            &detail,
        )?
    } else {
        run_parse_events_and_links::<false, PD>(
            &event_src,
            &ev_chunks,
            ev_hint_bytes,
            &link_paths,
            &lookups,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            ncpu,
            &detail,
        )?
    };
    drop(event_src);
    let t_events_parse = Instant::now();
    let t_links = if overlap_links {
        t_lookups
    } else {
        links_w_done
    };
    let lm_bytes = if PD { link_map.debug_stats() } else { (0, 0, 0, 0) };

    let ev_slabs = ev_out.ev_slabs;
    let dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>> = ev_out
        .dedup_chunks
        .into_iter()
        .map(|v| Mutex::new(Some(v)))
        .collect();
    let hex_slabs = ev_out.hex_slabs;
    let hex_dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<HexEvent32>>>>> = ev_out
        .hex_dedup_chunks
        .into_iter()
        .map(|v| Mutex::new(Some(v)))
        .collect();
    let ev_worker_arenas = ev_out.ev_worker_arenas;
    let ev_worker_hex = ev_out.ev_worker_hex;
    let ev_worker_ext = ev_out.ev_worker_ext;

    // Unified clicks parse + events dedup (with LinkMap resolution) in one std::thread::scope.
    let click_paths = list_csv_files(&data_dir.join("clicks"))?;
    let click_src = CsvSource::open(&click_paths)?;
    let cl_chunks = click_src.chunks(CHUNK_BYTES);
    let n_pool_workers = ncpu.clamp(1, 63);
    let cl_active = n_pool_workers.min(cl_chunks.len().max(1));
    let cl_hint_bytes = ((click_src.total_bytes() / 42) * 16) / cl_active.max(1);
    let pe_hint_bytes = (est_ev_total * 16) / n_pool_workers.max(1);

    let ud_dir = out_dir.join("user_daily");
    let cd_dir = out_dir.join("campaign_daily");
    clean_parquet_dir(&ud_dir)?;
    clean_parquet_dir(&cd_dir)?;

    let (t_events_dedup, t_clicks, t_stage5, worker_accs, total_ud_rows) = match (
        compact_ev_mode,
        compact_click_mode,
    ) {
        (true, true) => run_typed_stages::<PersonEvent16, PersonClick16, PD>(
            dedup_slots,
            hex_dedup_slots,
            ev_worker_ext,
            ev_worker_arenas,
            ev_worker_hex,
            ev_slabs,
            hex_slabs,
            click_src,
            &cl_chunks,
            cl_hint_bytes,
            pe_hint_bytes,
            &lookups,
            &mut link_map,
            &ud_dir,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            click_window_start_ms,
            min_day,
            max_day,
            ws_day,
            ws_rem,
            ncpu,
            fast_exit,
            &detail,
        )?,
        (true, false) => run_typed_stages::<PersonEvent16, PersonClickWide, PD>(
            dedup_slots,
            hex_dedup_slots,
            ev_worker_ext,
            ev_worker_arenas,
            ev_worker_hex,
            ev_slabs,
            hex_slabs,
            click_src,
            &cl_chunks,
            cl_hint_bytes * 2,
            pe_hint_bytes,
            &lookups,
            &mut link_map,
            &ud_dir,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            click_window_start_ms,
            min_day,
            max_day,
            ws_day,
            ws_rem,
            ncpu,
            fast_exit,
            &detail,
        )?,
        _ => run_typed_stages::<PersonEventWide, PersonClickWide, PD>(
            dedup_slots,
            hex_dedup_slots,
            ev_worker_ext,
            ev_worker_arenas,
            ev_worker_hex,
            ev_slabs,
            hex_slabs,
            click_src,
            &cl_chunks,
            cl_hint_bytes * 2,
            (est_ev_total * 24) / n_pool_workers.max(1),
            &lookups,
            &mut link_map,
            &ud_dir,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            click_window_start_ms,
            min_day,
            max_day,
            ws_day,
            ws_rem,
            ncpu,
            fast_exit,
            &detail,
        )?,
    };

    if total_ud_rows == 0 {
        let empty_ud = UserDailyWriter::create(
            &ud_dir.join("part-0.parquet"),
            1,
            &lookups.categories,
        )?;
        empty_ud.close()?;
    }

    let mut acc_iter = worker_accs.into_iter();
    let mut final_acc = acc_iter.next().unwrap();
    for a in acc_iter {
        final_acc.merge_into(a);
    }

    let mut cd_rows: Vec<CampaignRow<'_>> = Vec::new();
    match &final_acc {
        CampDailyAcc::Dense {
            start_day,
            num_days,
            day_shift,
            num_camps,
            assists,
            credits,
        } => {
            for c in 0..*num_camps {
                let c_name = lookups.camp_name(c);
                let ch_name = lookups.camp_channel(c);
                let row_base = c << *day_shift;
                for d_off in 0..*num_days {
                    let idx = row_base + d_off;
                    let cr = credits[idx];
                    let asst = assists[idx] as i64;
                    if cr.sessions > 0 || asst > 0 {
                        cd_rows.push(CampaignRow {
                            campaign_id: c_name,
                            channel: ch_name,
                            day: *start_day + d_off as i32,
                            sessions: cr.sessions as i64,
                            purchasing_sessions: cr.purchasing_sessions as i64,
                            revenue_cents: cr.revenue_cents,
                            assisted_sessions: asst,
                        });
                    }
                }
            }
        }
        CampDailyAcc::Sparse(map) => {
            for (&(c, day), agg) in map {
                if agg.sessions > 0 || agg.assisted_sessions > 0 {
                    cd_rows.push(CampaignRow {
                        campaign_id: lookups.camp_name(c as usize),
                        channel: lookups.camp_channel(c as usize),
                        day,
                        sessions: agg.sessions,
                        purchasing_sessions: agg.purchasing_sessions,
                        revenue_cents: agg.revenue_cents,
                        assisted_sessions: agg.assisted_sessions,
                    });
                }
            }
        }
    }
    write_campaign_daily(&cd_dir.join("part-0.parquet"), &cd_rows)?;
    let t_done = Instant::now();

    if profile {
        let vm_hwm = read_vm_hwm_kb();
        println!(
            "PROFILE startup={:.4}s lookups={:.4}s links={:.4}s events_parse={:.4}s events_dedup={:.4}s clicks={:.4}s sessionize_attr_ud={:.4}s camp_write={:.4}s total={:.4}s vm_hwm_kb={}",
            (t_startup - t0).as_secs_f64(),
            (t_lookups - t_startup).as_secs_f64(),
            (t_links - t_lookups).as_secs_f64(),
            (t_events_parse - t_links).as_secs_f64(),
            (t_events_dedup - t_events_parse).as_secs_f64(),
            (t_clicks - t_events_dedup).as_secs_f64(),
            (t_stage5 - t_clicks).as_secs_f64(),
            (t_done - t_stage5).as_secs_f64(),
            (t_done - t0).as_secs_f64(),
            vm_hwm
        );
        if PD {
            let to_s = |v: &AtomicU64| (v.load(Ordering::Relaxed) as f64) * 1e-9;
            println!(
                "PROFILE_DETAIL links_w={:.4}s ev_io_scan_cpu={:.4}s ev_dec_cpu={:.4}s cl_cpu={:.4}s dedup_p1_cpu={:.4}s dedup_p2_cpu={:.4}s ev_drop_w={:.4}s s5_ev_csr_cpu={:.4}s s5_cl_csr_cpu={:.4}s s5_sort_cpu={:.4}s s5_sess_attr_cpu={:.4}s s5_ud_cpu={:.4}s",
                to_s(&detail.links_w_ns),
                to_s(&detail.ev_io_scan_ns),
                to_s(&detail.ev_dec_ns),
                to_s(&detail.cl_ns),
                to_s(&detail.dedup_p1_ns),
                to_s(&detail.dedup_p2_ns),
                to_s(&detail.ev_drop_w_ns),
                to_s(&detail.s5_ev_csr_ns),
                to_s(&detail.s5_cl_csr_ns),
                to_s(&detail.s5_sort_ns),
                to_s(&detail.s5_sess_attr_ns),
                to_s(&detail.s5_ud_ns),
            );
            let get_u = |v: &AtomicU64| v.load(Ordering::Relaxed);
            println!(
                "PROFILE_MICRO ev_pread={:.4}s ev_scan={:.4}s ev_classify={:.4}s ev_dec_f1={:.4}s ev_dec_f3={:.4}s ev_dec_oth={:.4}s ev_n=f1:{}/f3:{}/oth:{} ev_kind=fb37:{}/fuhex:{}/eb37:{}/ib37:{}/hex:{}/egen:{}/igen:{}/purch:{} | p2_unpack={:.4}s p2_bloom={:.4}s p2_probe={:.4}s p2_push={:.4}s p2_hex={:.4}s p2_cnt=surv:{}/b_hit:{}/b_slot:{}/b_miss:{}/h_hit:{}/h_slot:{}/h_miss:{} | s5_csr_p1={:.4}s s5_csr_p2={:.4}s | lm_kb=b:{}/sb37:{}/bh:{}/sh:{}",
                to_s(&detail.ev_pread_ns),
                to_s(&detail.ev_scan_ns),
                to_s(&detail.ev_classify_ns),
                to_s(&detail.ev_dec_f1_ns),
                to_s(&detail.ev_dec_f3_ns),
                to_s(&detail.ev_dec_oth_ns),
                get_u(&detail.ev_n_f1),
                get_u(&detail.ev_n_f3),
                get_u(&detail.ev_n_oth),
                get_u(&detail.ev_n_fast_b37),
                get_u(&detail.ev_n_fast_uhex),
                get_u(&detail.ev_n_ext_b37),
                get_u(&detail.ev_n_inv_b37),
                get_u(&detail.ev_n_hex_ev),
                get_u(&detail.ev_n_ext_gen),
                get_u(&detail.ev_n_inv_gen),
                get_u(&detail.ev_n_purch),
                to_s(&detail.p2_unpack_ns),
                to_s(&detail.p2_bloom_ns),
                to_s(&detail.p2_probe_ns),
                to_s(&detail.p2_push_ns),
                to_s(&detail.p2_hex_ns),
                get_u(&detail.p2_surv_total),
                get_u(&detail.p2_b37_bloom_hits),
                get_u(&detail.p2_b37_slot_hits),
                get_u(&detail.p2_b37_misses),
                get_u(&detail.p2_hex_bloom_hits),
                get_u(&detail.p2_hex_slot_hits),
                get_u(&detail.p2_hex_misses),
                to_s(&detail.s5_ev_csr_p1_ns),
                to_s(&detail.s5_ev_csr_p2_ns),
                lm_bytes.0 / 1024,
                lm_bytes.1 / 1024,
                lm_bytes.2 / 1024,
                lm_bytes.3 / 1024,
            );
        }
    }

    if fast_exit {
        use std::io::Write;
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();
        std::process::exit(0);
    }

    Ok(())
}

#[inline(always)]
fn pick_and_reset_top_cat_id(cat_rev: &mut [i64], touched_cats: &mut Vec<u32>) -> Option<u32> {
    if touched_cats.is_empty() {
        return None;
    }
    let mut best_id = touched_cats[0];
    let mut best_rev = cat_rev[best_id as usize];
    cat_rev[best_id as usize] = 0;
    for &cid in &touched_cats[1..] {
        let r = cat_rev[cid as usize];
        cat_rev[cid as usize] = 0;
        if r > best_rev || (r == best_rev && cid < best_id) {
            best_rev = r;
            best_id = cid;
        }
    }
    touched_cats.clear();
    Some(best_id)
}

#[inline(always)]
fn emit_interval_assists(
    acc: &mut CampDailyAcc,
    camp: u32,
    iv_start: i64,
    iv_end: i64,
    sessions: &[SessionInfo],
    day_ranges: &[DayRange],
) {
    let s_lo = sessions.partition_point(|s| s.start_cmp < iv_start);
    if s_lo >= sessions.len() {
        return;
    }
    let s_hi = s_lo + sessions[s_lo..].partition_point(|s| s.start_cmp <= iv_end);
    if s_lo >= s_hi {
        return;
    }
    let mut d_idx = day_ranges.partition_point(|dr| (dr.hi_idx as usize) <= s_lo);
    while d_idx < day_ranges.len() && (day_ranges[d_idx].lo_idx as usize) < s_hi {
        let dr = &day_ranges[d_idx];
        let o_lo = (dr.lo_idx as usize).max(s_lo);
        let o_hi = (dr.hi_idx as usize).min(s_hi);
        if o_lo < o_hi {
            acc.add_assist(camp, dr.day, (o_hi - o_lo) as i64);
        }
        d_idx += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::RowAccessor;

    #[test]
    fn test_sliding_window_vs_merged_intervals_equivalence() {
        let mut seed: u64 = 0x1234_5678_9abc_def0;
        let mut next_u64 = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed
        };

        let num_camps = 12usize;
        let organic_camp = 0u32;
        let base_day = 20_000i32;
        let base_ms = (base_day as i64) * MS_DAY;
        let empty_arenas: [LongArena; 0] = [];
        let empty_hex: [Vec<Hex128>; 0] = [];

        for case in 0..250usize {
            let n_sess = if case < 32 {
                ((next_u64() % 32) + 1) as usize
            } else {
                ((next_u64() % 45) + 1) as usize
            };
            let mut starts = Vec::with_capacity(n_sess);
            let mut t = base_ms;
            for _ in 0..n_sess {
                t += MS_SESSION_GAP + 1 + ((next_u64() % (6 * 3_600_000)) as i64);
                starts.push(t);
            }
            let sessions: Vec<SessionInfo> = starts
                .iter()
                .map(|&st| {
                    let hp = (next_u64() % 2) as u32;
                    let rev = if hp != 0 {
                        ((next_u64() % 10_000) + 1) as i64
                    } else {
                        0
                    };
                    SessionInfo {
                        start_cmp: st,
                        day: st.div_euclid(MS_DAY) as i32,
                        has_purchase: hp,
                        revenue_cents: rev,
                    }
                })
                .collect();

            let n_clks = if case % 5 == 0 {
                1usize
            } else if case % 7 == 0 {
                0usize
            } else {
                (next_u64() % 64) as usize
            };
            let mut clks: Vec<(i64, u32, CompactKey64)> = Vec::with_capacity(n_clks);
            for clk_i in 0..n_clks {
                let camp_id = 1 + (next_u64() % ((num_camps - 1) as u64)) as u32;
                let s_pick = starts[(next_u64() as usize) % starts.len()];
                let offset = match next_u64() % 6 {
                    0 => MS_CLICK_REACH,
                    1 => MS_CLICK_REACH + 1,
                    2 => 0,
                    3 => -1,
                    _ => (next_u64() % (10 * MS_DAY as u64)) as i64,
                };
                let ckey =
                    CompactKey64::from_kb37(1 + (((clk_i as u64) ^ (next_u64() & 0xFF)) & 0xFFFF));
                clks.push((s_pick - offset, camp_id, ckey));
            }
            clks.sort_unstable_by_key(|c| c.0);

            let min_d = sessions.first().unwrap().day;
            let max_d = sessions.last().unwrap().day;
            let mut acc_fused = CampDailyAcc::new(num_camps, min_d, max_d, 1000);
            let mut acc_ref = CampDailyAcc::new(num_camps, min_day_helper(min_d), max_d, 1000);

            // Production fused paths under test (0, 1, or general batched sliding window)
            if clks.is_empty() {
                for s in &sessions {
                    acc_fused.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                }
            } else if clks.len() == 1 {
                let (cts, ccamp, _) = clks[0];
                let mut a_day = sessions[0].day;
                let mut a_cnt = 0i64;
                for s in &sessions {
                    if cts <= s.start_cmp
                        && (s.start_cmp as i128 - cts as i128) <= MS_CLICK_REACH as i128
                    {
                        acc_fused.add_credit(ccamp, s.day, s.has_purchase, s.revenue_cents);
                        if s.day == a_day {
                            a_cnt += 1;
                        } else {
                            if a_cnt > 0 {
                                acc_fused.add_assist(ccamp, a_day, a_cnt);
                            }
                            a_day = s.day;
                            a_cnt = 1;
                        }
                    } else {
                        acc_fused.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                    }
                }
                if a_cnt > 0 {
                    acc_fused.add_assist(ccamp, a_day, a_cnt);
                }
            } else {
                let mut active_count = vec![0u32; num_camps];
                let mut active_pos = vec![0u32; num_camps];
                let mut active_list: Vec<u32> = Vec::new();
                let mut left = 0usize;
                let mut right = 0usize;
                let mut has_click = false;
                let mut best_ts = i64::MIN;
                let mut best_camp = 0u32;
                let mut best_ckey = CompactKey64::EMPTY;
                let mut batch_day = sessions[0].day;
                let mut batch_cnt = 0u32;

                for s in &sessions {
                    while right < clks.len() {
                        let (cts, ccamp, ckey) = clks[right];
                        if cts > s.start_cmp {
                            break;
                        }
                        if !has_click || cts > best_ts {
                            has_click = true;
                            best_ts = cts;
                            best_camp = ccamp;
                            best_ckey = ckey;
                        } else if cts == best_ts
                            && cmp_raw_keys(
                                ckey,
                                best_ckey,
                                &empty_arenas,
                                &empty_hex,
                                &empty_arenas,
                                &empty_hex,
                            ) == std::cmp::Ordering::Less
                        {
                            best_camp = ccamp;
                            best_ckey = ckey;
                        }
                        let cid = ccamp as usize;
                        let cnt = active_count[cid];
                        active_count[cid] = cnt + 1;
                        if cnt == 0 {
                            if batch_cnt > 0 {
                                acc_fused.add_assists_batch(&active_list, batch_day, batch_cnt);
                                batch_cnt = 0;
                            }
                            active_pos[cid] = active_list.len() as u32;
                            active_list.push(ccamp);
                        }
                        right += 1;
                    }
                    while left < right {
                        let (cts, ccamp, _) = clks[left];
                        if (s.start_cmp as i128 - cts as i128) <= MS_CLICK_REACH as i128 {
                            break;
                        }
                        let cid = ccamp as usize;
                        let cnt = active_count[cid] - 1;
                        active_count[cid] = cnt;
                        if cnt == 0 {
                            if batch_cnt > 0 {
                                acc_fused.add_assists_batch(&active_list, batch_day, batch_cnt);
                                batch_cnt = 0;
                            }
                            let pos = active_pos[cid] as usize;
                            let last = *active_list.last().unwrap();
                            active_list[pos] = last;
                            active_pos[last as usize] = pos as u32;
                            active_list.pop();
                        }
                        left += 1;
                    }
                    let camp = if has_click
                        && (s.start_cmp as i128 - best_ts as i128) <= MS_CLICK_REACH as i128
                    {
                        best_camp
                    } else {
                        organic_camp
                    };
                    acc_fused.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
                    if !active_list.is_empty() {
                        if s.day != batch_day {
                            if batch_cnt > 0 {
                                acc_fused.add_assists_batch(&active_list, batch_day, batch_cnt);
                            }
                            batch_day = s.day;
                            batch_cnt = 1;
                        } else {
                            batch_cnt += 1;
                        }
                    }
                }
                if batch_cnt > 0 {
                    acc_fused.add_assists_batch(&active_list, batch_day, batch_cnt);
                }
            }

            // Reference: independent per-session credit + merged-interval assists
            for s in &sessions {
                let mut best: Option<(i64, CompactKey64, u32)> = None;
                for &(cts, ccamp, ckey) in &clks {
                    if cts <= s.start_cmp
                        && (s.start_cmp as i128 - cts as i128) <= MS_CLICK_REACH as i128
                    {
                        best = match best {
                            None => Some((cts, ckey, ccamp)),
                            Some((bts, bkey, _))
                                if cts > bts
                                    || (cts == bts
                                        && cmp_raw_keys(
                                            ckey,
                                            bkey,
                                            &empty_arenas,
                                            &empty_hex,
                                            &empty_arenas,
                                            &empty_hex,
                                        ) == std::cmp::Ordering::Less) =>
                            {
                                Some((cts, ckey, ccamp))
                            }
                            Some(cur) => Some(cur),
                        };
                    }
                }
                let camp = best.map_or(organic_camp, |v| v.2);
                acc_ref.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
            }

            let mut day_ranges = Vec::new();
            let mut d_lo = 0usize;
            let mut d_cur = sessions[0].day;
            for (i, s) in sessions.iter().enumerate() {
                if s.day != d_cur {
                    day_ranges.push(DayRange {
                        day: d_cur,
                        lo_idx: d_lo as u32,
                        hi_idx: i as u32,
                    });
                    d_cur = s.day;
                    d_lo = i;
                }
            }
            day_ranges.push(DayRange {
                day: d_cur,
                lo_idx: d_lo as u32,
                hi_idx: sessions.len() as u32,
            });
            let mut camp_clicks: Vec<(u32, i64)> = clks.iter().map(|&(t, c, _)| (c, t)).collect();
            camp_clicks.sort_unstable();
            let mut i = 0usize;
            while i < camp_clicks.len() {
                let camp = camp_clicks[i].0;
                let mut iv_start = camp_clicks[i].1;
                let mut iv_end = iv_start.saturating_add(MS_CLICK_REACH);
                i += 1;
                while i < camp_clicks.len() && camp_clicks[i].0 == camp {
                    let t = camp_clicks[i].1;
                    if t <= iv_end {
                        iv_end = t.saturating_add(MS_CLICK_REACH);
                    } else {
                        emit_interval_assists(
                            &mut acc_ref,
                            camp,
                            iv_start,
                            iv_end,
                            &sessions,
                            &day_ranges,
                        );
                        iv_start = t;
                        iv_end = t.saturating_add(MS_CLICK_REACH);
                    }
                    i += 1;
                }
                emit_interval_assists(
                    &mut acc_ref,
                    camp,
                    iv_start,
                    iv_end,
                    &sessions,
                    &day_ranges,
                );
            }

            match (&acc_fused, &acc_ref) {
                (
                    CampDailyAcc::Dense {
                        assists: a1,
                        credits: c1,
                        ..
                    },
                    CampDailyAcc::Dense {
                        assists: a2,
                        credits: c2,
                        ..
                    },
                ) => {
                    assert_eq!(a1, a2, "assists mismatch on case {case}");
                    assert_eq!(c1.len(), c2.len());
                    for (x, y) in c1.iter().zip(c2.iter()) {
                        assert_eq!(
                            (x.sessions, x.purchasing_sessions, x.revenue_cents),
                            (y.sessions, y.purchasing_sessions, y.revenue_cents),
                            "credits mismatch on case {case}"
                        );
                    }
                }
                _ => panic!("expected dense accumulators in test"),
            }
        }
    }

    #[test]
    fn test_radix_sort_u64_matches_std() {
        let mut seed: u64 = 0xCAFE_BABE_1234_5678;
        let mut next_u64 = || {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            seed
        };
        let max_rel = i32::MAX as u64;
        let mut scratch = Vec::new();
        for &n in &[0usize, 1, 2, 3, 4, 5, 16, 24, 25, 128, 159, 256, 384, 500, 1536, 2047] {
            for mode in [0u8, 1, 2, 3, 4] {
                let mut v = Vec::with_capacity(n);
                for idx in 0..n {
                    let ts_rel = match mode {
                        0 => 123_456_789,
                        1 => next_u64() % 200_000,
                        2 => next_u64() % 1_209_600_000,
                        3 => match idx {
                            0 => 0,
                            1 => max_rel,
                            2 => (1u64 << 22) - 1,
                            3 => 1u64 << 22,
                            _ => next_u64() & max_rel,
                        },
                        _ => (((n - idx) as u64).wrapping_mul(17_000_003)) & max_rel,
                    };
                    let low = next_u64() & 0xFFFF_FFFF;
                    v.push((ts_rel << 32) | low);
                }
                let mut expected: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                expected.sort_unstable();

                let mut v_b = v.clone();
                sort_u64_bucket256(&mut v_b, &mut scratch);
                let got_b: Vec<u32> = v_b.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got_b, expected, "bucket256 mismatch n={n} mode={mode}");

                let mut v_g = v;
                <PersonEvent16 as Stage5Event>::sort_grouped(&mut v_g, &mut scratch);
                let got_g: Vec<u32> = v_g.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got_g, expected, "sort_grouped mismatch n={n} mode={mode}");
            }
        }

        for &n in &[256usize, 384, 500, 1536, 2047, 2048, 2500, 5000] {
            for mode in [0u8, 1, 2, 3, 4, 5] {
                let mut v = Vec::with_capacity(n);
                for idx in 0..n {
                    let ts_rel = match mode {
                        0 => 123_456_789,
                        1 => (0x0012_3400u64) | (next_u64() & 0x3FF),
                        2 => next_u64() % 1_209_600_000,
                        3 => match idx {
                            0 => 0,
                            1 => max_rel,
                            2 => (1u64 << 10) - 1,
                            3 => 1u64 << 10,
                            4 => (1u64 << 22) - 1,
                            5 => 1u64 << 22,
                            _ => next_u64() & max_rel,
                        },
                        4 => {
                            // Adversarial >64 reverse-sorted elements inside the same 1.024s (10-bit) bucket
                            if idx < 220 {
                                0x0040_0000 + ((220 - idx) as u64 * 4)
                            } else if idx < 420 {
                                0x0080_0400 + ((idx * 37) as u64 & 0x3FF)
                            } else {
                                next_u64() % 1_209_600_000
                            }
                        }
                        _ => (next_u64() % 7) * 200_000_000,
                    };
                    let low = idx as u64;
                    v.push((ts_rel << 32) | low);
                }
                let mut expected_hi: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                expected_hi.sort_unstable();
                let mut v_g = v.clone();

                sort_u64_radix21_fixup(&mut v, &mut scratch);
                let got_r: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got_r, expected_hi, "radix21_fixup mismatch n={n} mode={mode}");

                <PersonEvent16 as Stage5Event>::sort_grouped(&mut v_g, &mut scratch);
                let got_g: Vec<u32> = v_g.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got_g, expected_hi, "sort_grouped radix21 mismatch n={n} mode={mode}");
            }
        }
    }

    fn min_day_helper(d: i32) -> i32 {
        d
    }

    #[test]
    fn test_wide_mode_and_long_ids_end_to_end() {
        let base = std::env::temp_dir().join("ss_test_wide_mode_e2e");
        let _ = fs::remove_dir_all(&base);
        let data = base.join("data");
        let out = base.join("out");
        fs::create_dir_all(data.join("events")).unwrap();
        fs::create_dir_all(data.join("clicks")).unwrap();
        fs::create_dir_all(data.join("links")).unwrap();

        // 60-day window -> forces !compact_mode
        fs::write(
            data.join("manifest.json"),
            r#"{"window_start":"2026-10-01T00:00:00Z","window_end":"2026-11-30T00:00:00Z"}"#,
        )
        .unwrap();

        // 300 categories -> also forces !compact_mode
        let mut prods = String::from("product_id,category\n");
        for i in 0..300 {
            prods.push_str(&format!("prod_long_{i:04},cat_{i:04}\n"));
        }
        fs::write(data.join("products.csv"), prods).unwrap();

        fs::write(
            data.join("campaigns.csv"),
            "campaign_id,channel\ncamp_long_0001,search\ncamp_long_0002,social\n",
        )
        .unwrap();

        // Long Tag 11 IDs + linked long IDs
        fs::write(
            data.join("links/part-0.csv"),
            "user_id_a,user_id_b\nuser_long_0002,!user_long_0001\n",
        )
        .unwrap();

        // Duplicate event where earliest copy is invalid; plus late >24h; plus long unlinked user
        let events = concat!(
            "event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents\n",
            "ev_long_dup_bad,!user_long_0001,bad_ts,2026-10-03T10:01:00Z,view,prod_long_0001,\n",
            "ev_long_dup_bad,!user_long_0001,2026-10-03T10:00:00Z,2026-10-03T10:05:00Z,view,prod_long_0001,\n",
            "ev_long_valid_1,user_long_0002,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,purchase,prod_long_0299,500\n",
            "ev_long_valid_2,unlinked_long_user_99,2026-11-20T12:00:00Z,2026-11-20T12:01:00Z,purchase,prod_long_0005,700\n",
            "ev_long_late,unlinked_long_user_99,2026-11-20T12:05:00Z,2026-11-21T12:05:01Z,view,prod_long_0005,\n",
        );
        fs::write(data.join("events/part-0.csv"), events).unwrap();

        let clicks = concat!(
            "click_id,user_id,campaign_id,ts\n",
            "click_long_0001,!user_long_0001,camp_long_0001,2026-10-03T09:00:00Z\n",
            "click_long_0002,unlinked_long_user_99,camp_long_0002,2026-11-20T11:00:00Z\n",
        );
        fs::write(data.join("clicks/part-0.csv"), clicks).unwrap();

        run_pipeline(&data, &out, 4, false).unwrap();

        let mut ud_rows = Vec::new();
        for entry in fs::read_dir(out.join("user_daily")).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("parquet") {
                let rdr = SerializedFileReader::new(fs::File::open(&p).unwrap()).unwrap();
                for row in rdr.get_row_iter(None).unwrap() {
                    let row = row.unwrap();
                    ud_rows.push((
                        row.get_string(0).unwrap().clone(),
                        row.get_long(4).unwrap(),
                        row.get_string(5).unwrap().clone(),
                    ));
                }
            }
        }
        ud_rows.sort();
        assert_eq!(
            ud_rows,
            vec![
                ("!user_long_0001".to_string(), 500, "cat_0299".to_string()),
                (
                    "unlinked_long_user_99".to_string(),
                    700,
                    "cat_0005".to_string()
                ),
            ]
        );

        let cd_rdr =
            SerializedFileReader::new(fs::File::open(out.join("campaign_daily/part-0.parquet")).unwrap())
                .unwrap();
        let mut cd_rows = Vec::new();
        for row in cd_rdr.get_row_iter(None).unwrap() {
            let row = row.unwrap();
            cd_rows.push((
                row.get_string(0).unwrap().clone(),
                row.get_long(3).unwrap(),
                row.get_long(5).unwrap(),
                row.get_long(6).unwrap(),
            ));
        }
        cd_rows.sort();
        assert_eq!(
            cd_rows,
            vec![
                ("camp_long_0001".to_string(), 1, 500, 1),
                ("camp_long_0002".to_string(), 1, 700, 1),
            ]
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_v5_hex32_links_dedup_clicks_end_to_end() {
        let base = std::env::temp_dir().join("ss_test_v5_hex32_e2e");
        let _ = fs::remove_dir_all(&base);
        let data = base.join("data");
        let out = base.join("out");
        fs::create_dir_all(data.join("events")).unwrap();
        fs::create_dir_all(data.join("clicks")).unwrap();
        fs::create_dir_all(data.join("links")).unwrap();

        // 14-day window -> compact PersonEvent16 + PersonClick16 mode
        fs::write(
            data.join("manifest.json"),
            r#"{"window_start":"2026-10-01T00:00:00Z","window_end":"2026-10-15T00:00:00Z"}"#,
        )
        .unwrap();
        fs::write(
            data.join("products.csv"),
            "product_id,category\np1,books\np2,games\n",
        )
        .unwrap();
        fs::write(
            data.join("campaigns.csv"),
            "campaign_id,channel\ncamp_a,search\ncamp_b,social\n",
        )
        .unwrap();
        fs::write(
            data.join("links/part-0.csv"),
            concat!(
                "user_id_a,user_id_b\n",
                // hex32 root < b37 & < hex32
                "u100,u00000000000000000000000000000001\n",
                "uffffffffffffffffffffffffffffffff,u100\n",
                // b37 root < hex32 ('1' < '2')
                "u22222222222222222222222222222222,u10\n",
                // mixed inline root < hex32 ('!' < 'u')
                "u33333333333333333333333333333333,!aaa_mix\n",
            ),
        )
        .unwrap();

        let events = concat!(
            "event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents\n",
            // Unlinked all-zero hex32 user
            "ea0000000000000000000000000000001,u00000000000000000000000000000000,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,purchase,p1,400\n",
            // Duplicate hex32 event_id where earliest copy is invalid -> dropped
            "e0123456789abcdef0123456789abcdef,u100,bad_ts,2026-10-03T10:01:00Z,view,p1,\n",
            "e0123456789abcdef0123456789abcdef,u100,2026-10-03T10:00:00Z,2026-10-03T10:05:00Z,purchase,p2,777\n",
            // Duplicate hex32 event_id where earliest valid copy (p2, 500) wins over (p1, 900)
            "efedcba9876543210fedcba9876543210,uffffffffffffffffffffffffffffffff,2026-10-03T10:00:00Z,2026-10-03T10:05:00Z,purchase,p1,900\n",
            "efedcba9876543210fedcba9876543210,u00000000000000000000000000000001,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,purchase,p2,500\n",
            // B37-root + hex32 member
            "eb0000000000000000000000000000001,u22222222222222222222222222222222,2026-10-04T12:00:00Z,2026-10-04T12:01:00Z,purchase,p1,300\n",
            // Inline-root + hex32 member (organic)
            "ec0000000000000000000000000000001,u33333333333333333333333333333333,2026-10-05T15:00:00Z,2026-10-05T15:01:00Z,purchase,p1,200\n",
        );
        fs::write(data.join("events/part-0.csv"), events).unwrap();

        let clicks = concat!(
            "click_id,user_id,campaign_id,ts\n",
            "k00000000000000000000000000000000,u00000000000000000000000000000000,camp_a,2026-10-03T09:00:00Z\n",
            // Equal-ts tie-break on hex32 click_ids: k0000..0001 < kffff..ffff -> camp_a wins credit, both assist
            "kffffffffffffffffffffffffffffffff,u100,camp_b,2026-10-03T09:00:00Z\n",
            "k00000000000000000000000000000001,uffffffffffffffffffffffffffffffff,camp_a,2026-10-03T09:00:00Z\n",
            "k22222222222222222222222222222222,u22222222222222222222222222222222,camp_b,2026-10-04T11:30:00Z\n",
        );
        fs::write(data.join("clicks/part-0.csv"), clicks).unwrap();

        run_pipeline(&data, &out, 4, false).unwrap();

        let mut ud_rows = Vec::new();
        for entry in fs::read_dir(out.join("user_daily")).unwrap() {
            let p = entry.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) == Some("parquet") {
                let rdr = SerializedFileReader::new(fs::File::open(&p).unwrap()).unwrap();
                for row in rdr.get_row_iter(None).unwrap() {
                    let row = row.unwrap();
                    ud_rows.push((
                        row.get_string(0).unwrap().clone(),
                        row.get_long(4).unwrap(),
                        row.get_string(5).unwrap().clone(),
                    ));
                }
            }
        }
        ud_rows.sort();
        assert_eq!(
            ud_rows,
            vec![
                ("!aaa_mix".to_string(), 200, "books".to_string()),
                (
                    "u00000000000000000000000000000000".to_string(),
                    400,
                    "books".to_string()
                ),
                (
                    "u00000000000000000000000000000001".to_string(),
                    500,
                    "games".to_string()
                ),
                ("u10".to_string(), 300, "books".to_string()),
            ]
        );

        let cd_rdr = SerializedFileReader::new(
            fs::File::open(out.join("campaign_daily/part-0.parquet")).unwrap(),
        )
        .unwrap();
        let mut cd_rows = Vec::new();
        for row in cd_rdr.get_row_iter(None).unwrap() {
            let row = row.unwrap();
            cd_rows.push((
                row.get_string(0).unwrap().clone(),
                row.get_long(3).unwrap(),
                row.get_long(4).unwrap(),
                row.get_long(5).unwrap(),
                row.get_long(6).unwrap(),
            ));
        }
        cd_rows.sort();
        assert_eq!(
            cd_rows,
            vec![
                ("camp_a".to_string(), 2, 2, 900, 2),
                ("camp_b".to_string(), 0, 0, 0, 1),
                ("camp_b".to_string(), 1, 1, 300, 1),
                ("organic".to_string(), 1, 1, 200, 0),
            ]
        );

        let _ = fs::remove_dir_all(&base);
    }
}
