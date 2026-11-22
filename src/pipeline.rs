use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Default)]
struct DetailStats {
    links_w_ns: AtomicU64,
    ev_io_scan_ns: AtomicU64,
    ev_dec_ns: AtomicU64,
    cl_ns: AtomicU64,
    dedup_p1_ns: AtomicU64,
    dedup_p2_ns: AtomicU64,
    ev_drop_w_ns: AtomicU64,
    s5_ev_csr_ns: AtomicU64,
    s5_cl_csr_ns: AtomicU64,
    s5_sort_ns: AtomicU64,
    s5_sess_attr_ns: AtomicU64,
    s5_ud_ns: AtomicU64,
}

use hashbrown::{HashMap, HashTable};

use crate::csv::{
    biject42, cmp_raw_keys, decode_b37, encode_b37_padded, encode_b37_pair_padded, eq_raw_keys,
    field_span, for_each_line_fields_slice, hash_bytes_fast, hash_raw_key, inv_biject42,
    list_csv_files, mix64, CompactKey64, CsvSource, DirectLine, LongArena, B37_MASK42, CHUNK_BYTES,
};
use crate::links::{build_link_map, LinkMap};
use crate::parse::{
    parse_price_cents, parse_ts_ms, DateCache, Manifest, MS_CLICK_REACH, MS_DAY, MS_SECOND,
    MS_SESSION_GAP,
};
use crate::parquet_out::{clean_parquet_dir, write_campaign_daily, CampaignRow, UserDailyWriter};
use crate::slab::{MutChunkRef, SlabArena, SlabBuckets};

const P_DEDUP: usize = 256;
const P_PERSON: usize = 256;
const EV_CHUNK_LEN: usize = 1024;
const EV_CHUNK_SHIFT: u32 = 10;
const EV_CHUNK_MASK: u32 = (EV_CHUNK_LEN as u32) - 1;
const MAX_DEDUP_U32_CHUNKS: usize = 1023;
const PE_CHUNK_LEN: usize = 2048;
const CL_CHUNK_LEN: usize = 1024;
const USER_DAILY_BATCH_ROWS: usize = 131_072;

const PE_TAG_SHIFT: u32 = 61;
const PE_FAST: u64 = 0u64 << PE_TAG_SHIFT;
const PE_EXT_B37: u64 = 1u64 << PE_TAG_SHIFT;
const PE_INV_B37: u64 = 2u64 << PE_TAG_SHIFT;
const PE_DEAD: u64 = 3u64 << PE_TAG_SHIFT;
const PE_EXT_GEN: u64 = 4u64 << PE_TAG_SHIFT;
const PE_INV_GEN: u64 = 5u64 << PE_TAG_SHIFT;
const PE_TAG_MASK: u64 = 7u64 << PE_TAG_SHIFT;
const PE_EV_REM_MASK: u64 = (1u64 << 34) - 1;
const PE_EXT_IDX_MASK: u64 = (1u64 << 40) - 1;
const PE_ING_BIAS: i64 = 1i64 << 17;

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
    cat_id: u32,
}

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
struct ExtClick {
    person_key: CompactKey64,
    click_id_key: CompactKey64,
    ts_rel_ms: u32,
    camp_id: u32,
}

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
    has_purchase: i64,
    revenue_cents: i64,
}

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
        num_camps: usize,
        assists: Vec<u32>,
        credits: Vec<CampCredit>,
    },
    Sparse(HashMap<(u32, i32), CampDayAgg>),
}

impl CampDailyAcc {
    fn new(num_camps: usize, min_day: i32, max_day: i32, total_events: usize) -> Self {
        let span = (max_day as i64 - min_day as i64 + 1).max(1) as usize;
        if span <= 4096
            && num_camps <= 16_384
            && span.saturating_mul(num_camps) <= 1_048_576
            && total_events < (u32::MAX as usize)
        {
            let total_cells = span * num_camps;
            Self::Dense {
                start_day: min_day,
                num_days: span,
                num_camps,
                assists: vec![0u32; total_cells],
                credits: vec![CampCredit::default(); total_cells],
            }
        } else {
            Self::Sparse(HashMap::with_capacity(4096))
        }
    }

    #[inline(always)]
    fn add_credit(&mut self, camp_id: u32, day: i32, has_purchase: i64, rev: i64) {
        match self {
            Self::Dense {
                start_day,
                num_days,
                num_camps,
                credits,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days && (camp_id as usize) < *num_camps);
                let idx = d_off * (*num_camps) + (camp_id as usize);
                let c = unsafe { credits.get_unchecked_mut(idx) };
                c.sessions += 1;
                c.purchasing_sessions += has_purchase as u32;
                c.revenue_cents += rev;
            }
            Self::Sparse(map) => {
                let c = map.entry((camp_id, day)).or_default();
                c.sessions += 1;
                c.purchasing_sessions += has_purchase;
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
                num_camps,
                assists,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days && (camp_id as usize) < *num_camps);
                let idx = d_off * (*num_camps) + (camp_id as usize);
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
                num_camps,
                assists,
                ..
            } => {
                let d_off = (day.wrapping_sub(*start_day) as u32) as usize;
                debug_assert!(d_off < *num_days);
                let n_c = *num_camps;
                let row_base = d_off * n_c;
                for &camp_id in camps {
                    let c = camp_id as usize;
                    debug_assert!(c < n_c);
                    unsafe {
                        *assists.get_unchecked_mut(row_base + c) += cnt;
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
    stack_buf: &'a mut [u8; 10],
) -> &'a [u8] {
    if key.is_uh42() {
        let len = decode_b37(inv_biject42(key.uh42_val()), b'u', stack_buf);
        &stack_buf[..len]
    } else if key.is_comp() {
        link_map.resolve_long_canon_bytes(key.comp_id())
    } else if key.is_ref() {
        LongArena::resolve_in(ev_arenas, key)
    } else {
        let len = key.decode_inline(stack_buf);
        &stack_buf[..len]
    }
}

#[inline(always)]
fn ev16_ingest_ts(
    ev: &ParsedEvent16,
    window_start_sec: i64,
    ext_by_worker: &[Vec<ExtEvent>],
) -> i64 {
    let tag = ev.w0 & PE_TAG_MASK;
    if tag == PE_FAST {
        let ing_off = (((ev.w0 >> 43) & 0x3_FFFF) as i64) - PE_ING_BIAS;
        let ts_rel = (((ev.w0 >> 34) & 0x1FF) << 22) | ((ev.w1 >> 42) & 0x3F_FFFF);
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
    type Grouped: Copy + Send;
    fn person_key(&self) -> CompactKey64;
    fn to_grouped(&self) -> Self::Grouped;
    fn sort_grouped(slice: &mut [Self::Grouped], scratch: &mut Vec<u64>);
    fn unpack_cmp_price_cat(g: Self::Grouped) -> (i64, u32, u32);
    fn day_from_cmp(cmp_ts: i64, ws_day: i32, ws_rem: u64) -> i32;
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
    fn from_fast_b37(person_key: CompactKey64, ts_rel_ms: u32) -> Self;
    fn from_ext(person_key: CompactKey64, ex: &ExtEvent, window_start_ms: i64) -> Self;
    fn set_person_key(&mut self, pk: CompactKey64);
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
    fn from_fast_b37(person_key: CompactKey64, ts_rel_ms: u32) -> Self {
        Self {
            person_key,
            ts_rel_ms,
            price_cat: 0,
        }
    }

    #[inline(always)]
    fn from_ext(person_key: CompactKey64, ex: &ExtEvent, window_start_ms: i64) -> Self {
        Self {
            person_key,
            ts_rel_ms: (ex.ts_ms - window_start_ms) as u32,
            price_cat: (ex.cat_id << 24) | ex.price_cents,
        }
    }

    #[inline(always)]
    fn set_person_key(&mut self, pk: CompactKey64) {
        self.person_key = pk;
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
    fn from_fast_b37(_person_key: CompactKey64, _ts_rel_ms: u32) -> Self {
        unreachable!("PE_FAST is only emitted in compact mode")
    }

    #[inline(always)]
    fn from_ext(person_key: CompactKey64, ex: &ExtEvent, _window_start_ms: i64) -> Self {
        Self {
            person_key,
            ts_ms: ex.ts_ms,
            price_cents: ex.price_cents,
            cat_id: ex.cat_id,
        }
    }

    #[inline(always)]
    fn set_person_key(&mut self, pk: CompactKey64) {
        self.person_key = pk;
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
    } else if !pk.is_ref() {
        ((mix64(pk.0) >> 52) as usize) & (P_PERSON - 1)
    } else {
        ((hash_bytes_fast(LongArena::resolve_in(arenas, pk)) >> 52) as usize) & (P_PERSON - 1)
    }
}

#[inline(always)]
fn hash_person_key(k: CompactKey64, arenas: &[LongArena]) -> u64 {
    if !k.is_ref() {
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
    arenas_b: &[LongArena],
) -> bool {
    if !a.is_ref() && !b.is_ref() {
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
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN>,
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

#[inline(always)]
fn flush_dedup_pending<E: DedupEmit>(
    n: usize,
    pending_ev: &mut [E; LINK_PENDING],
    pending_h42: &[u64; LINK_PENDING],
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
    link_map: &LinkMap,
    person_out: &mut SlabBuckets<E, P_PERSON, PE_CHUNK_LEN>,
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
        person_out.push(pshard, unsafe { *pending_ev.get_unchecked(j) });
    }
    for k in 0..nh {
        let j = unsafe { *hit_idxs.get_unchecked(k) } as usize;
        let h42 = unsafe { *pending_h42.get_unchecked(j) };
        let mut item = unsafe { *pending_ev.get_unchecked(j) };
        let pshard = if let Some(canon) = link_map.probe_b37(h42) {
            item.set_person_key(canon);
            pshard_for_person_key(canon, &[])
        } else {
            ((h42 >> 34) as usize) & (P_PERSON - 1)
        };
        person_out.push(pshard, item);
    }
}

#[inline(always)]
fn resolve_user_for_other_or_ext(
    padded: &[u8],
    u_s: usize,
    u_len: usize,
    u_e: usize,
    link_map: &LinkMap,
    lm_empty: bool,
    wid: usize,
    cl_arena_out: &mut LongArena,
) -> (CompactKey64, usize) {
    if let Some(u_b37) = encode_b37_padded(padded, u_s, u_len, b'u') {
        let h42 = biject42(u_b37);
        if !lm_empty {
            if let Some(canon) = link_map.probe_b37(h42) {
                return (canon, pshard_for_person_key(canon, &[]));
            }
        }
        return (
            CompactKey64::from_uh42(h42),
            ((h42 >> 34) as usize) & (P_PERSON - 1),
        );
    }
    if let Some(uk) = CompactKey64::encode_raw_inline_padded(padded, u_s, u_len) {
        if !lm_empty {
            if let Some(canon) = link_map.resolve_other_inline(uk) {
                return (canon, pshard_for_person_key(canon, &[]));
            }
        }
        return (uk, ((mix64(uk.0) >> 52) as usize) & (P_PERSON - 1));
    }
    let uid = unsafe { padded.get_unchecked(u_s..u_e) };
    if !lm_empty {
        if let Some(canon) = link_map.resolve_long(uid) {
            return (canon, pshard_for_person_key(canon, &[]));
        }
    }
    let pk = cl_arena_out.push_ref(wid, uid);
    let pshard = ((hash_bytes_fast(uid) >> 52) as usize) & (P_PERSON - 1);
    (pk, pshard)
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn process_cl_batch_direct<C: ClickEmit>(
    padded: &[u8],
    lines: &[DirectLine<4>],
    dcache: &mut DateCache,
    lookups: &Lookups,
    link_map: &LinkMap,
    lm_empty: bool,
    wid: usize,
    click_window_start_ms: i64,
    window_end_ms: i64,
    cl_arena_out: &mut LongArena,
    cl_ext_out: &mut Vec<ExtClick>,
    cl_buckets: &mut SlabBuckets<C, P_PERSON, CL_CHUNK_LEN>,
    pending_cl: &mut [C; LINK_PENDING],
    pending_h42: &mut [u64; LINK_PENDING],
    n_pending: &mut usize,
    hit_idxs: &mut [u8; LINK_PENDING],
    miss_idxs: &mut [u8; LINK_PENDING],
) {
    let base = padded.as_ptr();
    for dl in lines {
        let ls = dl.ls as usize;
        let c0 = dl.commas_end[0] as usize;
        let c1 = dl.commas_end[1] as usize;
        let c2 = dl.commas_end[2] as usize;
        let le = dl.commas_end[3] as usize;

        let (cl_s, cl_e) = unsafe { field_span(base, ls, c0) };
        let cl_len = cl_e - cl_s;
        let (u_s, u_e) = unsafe { field_span(base, c0 + 1, c1) };
        let u_len = u_e - u_s;
        if cl_len == 0 || u_len == 0 {
            continue;
        }
        let (c_s, c_e) = unsafe { field_span(base, c1 + 1, c2) };
        let Some(cid) = lookups.get_campaign_padded(padded, c_s, c_e - c_s) else {
            continue;
        };
        let (ts_s, ts_e) = unsafe { field_span(base, c2 + 1, le) };
        let Some(ts_ms) = dcache.parse_ts_ms_padded_dc(padded, ts_s, ts_e - ts_s) else {
            continue;
        };
        if ts_ms < click_window_start_ms || ts_ms >= window_end_ms {
            continue;
        }

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
            continue;
        }

        let click_id_key = if let Some(k_b37) = encode_b37_padded(padded, cl_s, cl_len, b'k') {
            CompactKey64::from_kb37(k_b37)
        } else if let Some(k) = CompactKey64::encode_raw_inline_padded(padded, cl_s, cl_len) {
            k
        } else {
            let click_id = unsafe { padded.get_unchecked(cl_s..cl_e) };
            cl_arena_out.push_ref(wid, click_id)
        };
        let (person_key, pshard) = resolve_user_for_other_or_ext(
            padded,
            u_s,
            u_len,
            u_e,
            link_map,
            lm_empty,
            wid,
            cl_arena_out,
        );
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
}

#[allow(clippy::too_many_arguments)]
fn run_clicks_and_dedup<E: DedupEmit, C: ClickEmit, const PD: bool>(
    dedup_slots: &[Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>],
    ev_worker_ext: &[Vec<ExtEvent>],
    ev_worker_arenas: &[LongArena],
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

    let mut cl_worker_slabs: Vec<Option<SlabArena>> = (0..n_workers).map(|_| None).collect();
    let mut cl_worker_chunks: Vec<Vec<Vec<MutChunkRef<C>>>> =
        (0..n_workers).map(|_| Vec::new()).collect();
    let mut cl_worker_arenas: Vec<LongArena> = (0..n_workers).map(|_| LongArena::default()).collect();
    let mut cl_worker_ext: Vec<Vec<ExtClick>> = (0..n_workers).map(|_| Vec::new()).collect();

    let mut pe_worker_slabs: Vec<Option<SlabArena>> = (0..n_workers).map(|_| None).collect();
    let mut dedup_worker_chunks: Vec<Vec<Vec<MutChunkRef<E>>>> =
        (0..n_workers).map(|_| Vec::new()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..n_workers).map(|_| None).collect();

    std::thread::scope(|scope| {
        for (
            wid,
            (
                (((cl_slab_slot, cl_chunks_slot), (cl_arena_out, cl_ext_out)),
                (pe_slab_slot, ev_out_slot)),
                err_out,
            ),
        ) in cl_worker_slabs
            .iter_mut()
            .zip(cl_worker_chunks.iter_mut())
            .zip(cl_worker_arenas.iter_mut().zip(cl_worker_ext.iter_mut()))
            .zip(pe_worker_slabs.iter_mut().zip(dedup_worker_chunks.iter_mut()))
            .zip(worker_errs.iter_mut())
            .enumerate()
        {
            let next_cl_ref = &next_cl;
            let next_d_ref = &next_d_shard;
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
                            SlabBuckets::<C, P_PERSON, CL_CHUNK_LEN>::new(cl_hint_bytes);
                        let tmpl =
                            C::make_b37_pending(0, 0, click_window_start_ms, click_window_start_ms, 0);
                        let mut pending_cl = [tmpl; LINK_PENDING];
                        let mut pending_h42 = [0u64; LINK_PENDING];
                        let mut n_pending = 0usize;

                        let mut cidx = first;
                        while let Some(&task) = cl_chunks.get(cidx) {
                            if let Err(e) = click_src.for_each_chunk_direct_batched::<4>(
                                task,
                                &mut buf,
                                |padded, lines| {
                                    process_cl_batch_direct::<C>(
                                        padded,
                                        lines,
                                        &mut dcache,
                                        lookups,
                                        link_map,
                                        lm_empty,
                                        wid,
                                        click_window_start_ms,
                                        window_end_ms,
                                        cl_arena_out,
                                        cl_ext_out,
                                        &mut cl_buckets,
                                        &mut pending_cl,
                                        &mut pending_h42,
                                        &mut n_pending,
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

                // Phase B (ZERO barrier): pull P_DEDUP shards & emit into SlabBuckets<E, P_PERSON, PE_CHUNK_LEN>.
                let mut person_out: Option<SlabBuckets<E, P_PERSON, PE_CHUNK_LEN>> = None;
                let mut dedup_u32: Vec<u32> = Vec::new();
                let mut dedup_keys: Vec<u64> = Vec::new();
                let mut dedup_idxs: Vec<u32> = Vec::new();
                let mut gen_table: Option<HashTable<u32>> = None;
                let mut ring_u32 = [DedupProbeU32 { tag12: 0, slot: 0 }; RING];
                let mut ring_wide = [0usize; RING];

                let mut pending_ev = [E::empty_tmpl(); LINK_PENDING];
                let mut pending_h42 = [0u64; LINK_PENDING];
                let mut p1_ns = 0u64;
                let mut p2_ns = 0u64;

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

                        for cidx in 0..n_chunks {
                            let c_len = shard_chunks[cidx].len;
                            let c_ptr = shard_chunks[cidx].ptr;
                            let cbase = (cidx as u32) << EV_CHUNK_SHIFT;
                            let pre = c_len.min(RING);
                            for i in 0..pre {
                                let w0 = unsafe { (*c_ptr.add(i)).w0 };
                                ring_u32[i] = if w0 < PE_DEAD {
                                    let ev_rem = w0 & PE_EV_REM_MASK;
                                    let slot = fast_range32(ev_rem, cap);
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            dedup_u32.as_ptr().add(slot) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                    DedupProbeU32 {
                                        tag12: ((ev_rem as u32) & 0xFFF) << 20,
                                        slot: slot as u32,
                                    }
                                } else {
                                    DedupProbeU32 {
                                        tag12: u32::MAX,
                                        slot: 0,
                                    }
                                };
                            }

                            for ridx in 0..c_len {
                                let prb = ring_u32[ridx & (RING - 1)];
                                if ridx + RING < c_len {
                                    let w0_a = unsafe { (*c_ptr.add(ridx + RING)).w0 };
                                    ring_u32[ridx & (RING - 1)] = if w0_a < PE_DEAD {
                                        let ev_rem = w0_a & PE_EV_REM_MASK;
                                        let slot = fast_range32(ev_rem, cap);
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                dedup_u32.as_ptr().add(slot) as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                        DedupProbeU32 {
                                            tag12: ((ev_rem as u32) & 0xFFF) << 20,
                                            slot: slot as u32,
                                        }
                                    } else {
                                        DedupProbeU32 {
                                            tag12: u32::MAX,
                                            slot: 0,
                                        }
                                    };
                                }

                                let ev = unsafe { *c_ptr.add(ridx) };
                                if prb.tag12 != u32::MAX {
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
                                            if (unsafe { (*prev_ptr).w0 } & PE_EV_REM_MASK) == ev_rem
                                            {
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
                                        }
                                        slot += 1;
                                        if slot == cap {
                                            slot = 0;
                                        }
                                    }
                                } else {
                                    let gt = gen_table.get_or_insert_with(HashTable::new);
                                    let ev_key = CompactKey64(ev.w1);
                                    let eh = hash_raw_key(ev_key, ev_worker_arenas);
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
                                                ev_worker_arenas,
                                            )
                                        },
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_k = CompactKey64(unsafe {
                                                (*shard_chunks[pc].ptr.add(pr)).w1
                                            });
                                            hash_raw_key(prev_k, ev_worker_arenas)
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
                                    let ev_key = CompactKey64(ev.w1);
                                    let eh = hash_raw_key(ev_key, ev_worker_arenas);
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
                                                ev_worker_arenas,
                                            )
                                        },
                                        |&packed| {
                                            let pc = (packed >> EV_CHUNK_SHIFT) as usize;
                                            let pr = (packed & EV_CHUNK_MASK) as usize;
                                            let prev_k = CompactKey64(unsafe {
                                                (*shard_chunks[pc].ptr.add(pr)).w1
                                            });
                                            hash_raw_key(prev_k, ev_worker_arenas)
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

                    // Pass 2: stream survivors through 2-stage batch-32 Bloom+Slot prefetch -> SlabBuckets<E>.
                    let mut n_p2_pending = 0usize;
                    for chunk in shard_chunks {
                        let slice = unsafe { chunk.as_slice() };
                        let blen = slice.len();
                        for ridx in 0..blen {
                            let ev = unsafe { *slice.get_unchecked(ridx) };
                            let tag = (ev.w0 >> PE_TAG_SHIFT) as u32;
                            if ((0b10011u32 >> tag) & 1) == 0 {
                                continue;
                            }
                            let (item, h42) = if tag == 0 {
                                let ts_rel_u = ((((ev.w0 >> 34) & 0x1FF) << 22)
                                    | ((ev.w1 >> 42) & 0x3F_FFFF))
                                    as u32;
                                let h42 = biject42(ev.w1 & B37_MASK42);
                                (E::from_fast_b37(CompactKey64::from_uh42(h42), ts_rel_u), h42)
                            } else {
                                let (e_wid, e_idx) = if tag == 1 {
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
                                    ev_worker_ext.get_unchecked(e_wid).get_unchecked(e_idx)
                                };
                                if ex.person_key.is_ub37() {
                                    let h42 = biject42(ex.person_key.ub37_val());
                                    (
                                        E::from_ext(
                                            CompactKey64::from_uh42(h42),
                                            ex,
                                            window_start_ms,
                                        ),
                                        h42,
                                    )
                                } else {
                                    let pk0 = ex.person_key;
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
                                    buckets_out.push(pshard, E::from_ext(pk, ex, window_start_ms));
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
                                    flush_dedup_pending(
                                        LINK_PENDING,
                                        &mut pending_ev,
                                        &pending_h42,
                                        &mut hit_idxs,
                                        &mut miss_idxs,
                                        link_map,
                                        buckets_out,
                                    );
                                    n_p2_pending = 0;
                                }
                            }
                        }
                    }
                    if n_p2_pending > 0 {
                        flush_dedup_pending(
                            n_p2_pending,
                            &mut pending_ev,
                            &pending_h42,
                            &mut hit_idxs,
                            &mut miss_idxs,
                            link_map,
                            buckets_out,
                        );
                    }
                    if let Some(t) = t_p2 {
                        p2_ns += t.elapsed().as_nanos() as u64;
                    }
                }

                if let Some(buckets_out) = person_out {
                    let t_fin = if PD { Some(Instant::now()) } else { None };
                    let (pe_slab, pe_done) = buckets_out.finish();
                    *pe_slab_slot = Some(pe_slab);
                    *ev_out_slot = pe_done;
                    if let Some(t) = t_fin {
                        p2_ns += t.elapsed().as_nanos() as u64;
                    }
                }
                if PD {
                    detail.dedup_p1_ns.fetch_add(p1_ns, Ordering::Relaxed);
                    detail.dedup_p2_ns.fetch_add(p2_ns, Ordering::Relaxed);
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
        if canon.is_uh42() {
            self.w0 = CL_UB37 | (self.w0 & !CL_REM34_MASK) | (canon.uh42_val() & CL_REM34_MASK);
        } else {
            let ts_rel_ms =
                ((((self.w0 >> 34) & 0x1FF) << 22) | ((self.w1 >> 42) & 0x3F_FFFF)) as u32;
            let camp_id = ((self.w0 >> 43) & 0x7_FFFF) as u32;
            let click_id_key = CompactKey64::from_kb37(self.w1 & B37_MASK42);
            let idx = cl_ext.len() as u64;
            cl_ext.push(ExtClick {
                person_key: canon,
                click_id_key,
                ts_rel_ms,
                camp_id,
            });
            self.w0 = CL_EXT | ((wid as u64) << 40) | idx;
            self.w1 = 0;
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
            person_key,
            click_id_key,
            ts_rel_ms: (ts_ms - click_window_start_ms) as u32,
            camp_id,
        });
        Self {
            w0: CL_EXT | ((wid as u64) << 40) | idx,
            w1: 0,
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
    ev_worker_arenas: Vec<LongArena>,
    ev_worker_ext: Vec<Vec<ExtEvent>>,
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn process_ev_batch_direct<const COMPACT: bool>(
    padded: &[u8],
    lines: &[DirectLine<7>],
    dcache: &mut DateCache,
    lookups: &Lookups,
    wid: usize,
    window_start_ms: i64,
    window_end_ms: i64,
    _window_start_sec: i64,
    ev_arena_out: &mut LongArena,
    ext_out: &mut Vec<ExtEvent>,
    ev_buckets: &mut SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN>,
) {
    const VIEW_U32: u32 = u32::from_ne_bytes(*b"view");
    const CART_U32: u32 = u32::from_ne_bytes(*b"cart");
    const PURCHASE_U64: u64 = u64::from_ne_bytes(*b"purchase");

    let base = padded.as_ptr();
    let window_span_u64 = (window_end_ms - window_start_ms).max(0) as u64;
    for dl in lines {
        let ls = dl.ls as usize;
        let c0 = dl.commas_end[0] as usize;
        let c1 = dl.commas_end[1] as usize;
        let c2 = dl.commas_end[2] as usize;
        let c3 = dl.commas_end[3] as usize;
        let c4 = dl.commas_end[4] as usize;
        let c5 = dl.commas_end[5] as usize;
        let le = dl.commas_end[6] as usize;

        let (ev_s, ev_e) = unsafe { field_span(base, ls, c0) };
        let ev_len = ev_e - ev_s;
        if ev_len == 0 {
            continue;
        }
        let (ing_s, ing_e) = unsafe { field_span(base, c2 + 1, c3) };
        let Some((ingest_sec, hint_hi, hint_lo, hint_day_sec)) =
            dcache.parse_f1_sec_padded_with_hint(padded, ing_s, ing_e - ing_s)
        else {
            continue;
        };
        let ingest_ms = ingest_sec * MS_SECOND;

        let (u_s, u_e) = unsafe { field_span(base, c0 + 1, c1) };
        let u_len = u_e - u_s;
        let (ts_s, ts_e) = unsafe { field_span(base, c1 + 1, c2) };
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
                if let Some((t, t_sec)) = dcache.parse_ts_ms_sec_padded_hint(
                    padded,
                    ts_s,
                    ts_e - ts_s,
                    hint_hi,
                    hint_lo,
                    hint_day_sec,
                ) {
                    let in_win = if COMPACT {
                        let ts_rel = t.wrapping_sub(window_start_ms) as u64;
                        ts_rel < window_span_u64 && (ingest_ms - t) <= MS_DAY
                    } else {
                        t >= window_start_ms
                            && t < window_end_ms
                            && (ingest_ms as i128 - t as i128) <= MS_DAY as i128
                    };
                    if in_win {
                        ts_ms = t;
                        ts_sec_val = t_sec;
                        if is_purchase {
                            cat_id = lookups.get_product_cat_padded(padded, p_s, p_len);
                        }
                        valid = true;
                    }
                }
            }
        }

        if COMPACT && valid && !is_purchase {
            let ts_rel_u = (ts_ms - window_start_ms) as u64;
            let ing_off = ingest_sec - ts_sec_val;
            if (-PE_ING_BIAS..PE_ING_BIAS).contains(&ing_off) {
                if let Some((ev_b37, u_b37)) =
                    encode_b37_pair_padded(padded, ev_s, ev_len, b'e', u_s, u_len, b'u')
                {
                    let h42 = biject42(ev_b37);
                    let d_shard = (h42 >> 34) as usize;
                    let ev_rem = h42 & PE_EV_REM_MASK;
                    let biased = (ing_off + PE_ING_BIAS) as u64;
                    ev_buckets.push(
                        d_shard,
                        ParsedEvent16 {
                            w0: PE_FAST | (biased << 43) | ((ts_rel_u >> 22) << 34) | ev_rem,
                            w1: ((ts_rel_u & 0x3F_FFFF) << 42) | u_b37,
                        },
                    );
                    continue;
                }
            }
        }

        if let Some(ev_b37) = encode_b37_padded(padded, ev_s, ev_len, b'e') {
            let h42 = biject42(ev_b37);
            let d_shard = (h42 >> 34) as usize;
            let ev_rem = h42 & PE_EV_REM_MASK;
            if !valid {
                ev_buckets.push(
                    d_shard,
                    ParsedEvent16 {
                        w0: PE_INV_B37 | ev_rem,
                        w1: ingest_ms as u64,
                    },
                );
                continue;
            }
            let person_key =
                CompactKey64::encode_user_inline_padded(padded, u_s, u_len).unwrap_or_else(|| {
                    let uid = unsafe { padded.get_unchecked(u_s..u_e) };
                    ev_arena_out.push_ref(wid, uid)
                });
            let ext_idx = ext_out.len() as u64;
            ext_out.push(ExtEvent {
                person_key,
                ts_ms,
                ingest_ts_ms: ingest_ms,
                price_cents: price_val,
                cat_id,
            });
            ev_buckets.push(
                d_shard,
                ParsedEvent16 {
                    w0: PE_EXT_B37 | ev_rem,
                    w1: ((wid as u64) << 40) | ext_idx,
                },
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
                    cat_id: 0,
                });
                ev_buckets.push(
                    d_shard,
                    ParsedEvent16 {
                        w0: PE_INV_GEN | ((wid as u64) << 40) | ext_idx,
                        w1: ev_key.0,
                    },
                );
                continue;
            }
            let person_key =
                CompactKey64::encode_user_inline_padded(padded, u_s, u_len).unwrap_or_else(|| {
                    let uid = unsafe { padded.get_unchecked(u_s..u_e) };
                    ev_arena_out.push_ref(wid, uid)
                });
            ext_out.push(ExtEvent {
                person_key,
                ts_ms,
                ingest_ts_ms: ingest_ms,
                price_cents: price_val,
                cat_id,
            });
            ev_buckets.push(
                d_shard,
                ParsedEvent16 {
                    w0: PE_EXT_GEN | ((wid as u64) << 40) | ext_idx,
                    w1: ev_key.0,
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_parse_events_par<const COMPACT: bool, const PD: bool>(
    event_src: &CsvSource,
    ev_chunks: &[crate::csv::ChunkTask],
    ev_hint_bytes: usize,
    lookups: &Lookups,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    ncpu: usize,
    detail: &DetailStats,
) -> io::Result<EvParseOutput> {
    if ev_chunks.is_empty() {
        return Ok(EvParseOutput {
            ev_slabs: Vec::new(),
            dedup_chunks: (0..P_DEDUP).map(|_| Vec::new()).collect(),
            ev_worker_arenas: Vec::new(),
            ev_worker_ext: Vec::new(),
        });
    }

    let n_slots = ncpu.clamp(1, 63).min(ev_chunks.len());
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
    let mut ev_worker_arenas: Vec<LongArena> = (0..n_slots).map(|_| LongArena::default()).collect();
    let mut ev_worker_ext: Vec<Vec<ExtEvent>> = (0..n_slots).map(|_| Vec::new()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..n_slots).map(|_| None).collect();

    std::thread::scope(|scope| {
        let order_ref = &order;
        let next_ref = &next_ord;
        for (wid, ((((slab_slot, dedup_slot), arena_out), ext_out), err_out)) in worker_slabs
            .iter_mut()
            .zip(worker_dedup.iter_mut())
            .zip(ev_worker_arenas.iter_mut())
            .zip(ev_worker_ext.iter_mut())
            .zip(worker_errs.iter_mut())
            .enumerate()
        {
            scope.spawn(move || {
                let mut buf = Vec::new();
                let mut dcache = DateCache::new_for_window(window_start_ms, window_end_ms);
                let mut ev_buckets: Option<SlabBuckets<ParsedEvent16, P_DEDUP, EV_CHUNK_LEN>> =
                    None;
                let mut io_scan_ns = 0u64;
                let mut ev_dec_ns = 0u64;

                loop {
                    let o = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(&cidx) = order_ref.get(o) else {
                        break;
                    };
                    let task = ev_chunks[cidx];
                    let t_c = if PD { Some(Instant::now()) } else { None };
                    let mut dec_ns = 0u64;
                    let res = {
                        let buckets =
                            ev_buckets.get_or_insert_with(|| SlabBuckets::new(ev_hint_bytes));
                        event_src.for_each_chunk_direct_batched::<7>(
                            task,
                            &mut buf,
                            |padded, lines| {
                                let t_d = if PD { Some(Instant::now()) } else { None };
                                process_ev_batch_direct::<COMPACT>(
                                    padded,
                                    lines,
                                    &mut dcache,
                                    lookups,
                                    wid,
                                    window_start_ms,
                                    window_end_ms,
                                    window_start_sec,
                                    arena_out,
                                    ext_out,
                                    buckets,
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
                if PD {
                    detail.ev_io_scan_ns.fetch_add(io_scan_ns, Ordering::Relaxed);
                    detail.ev_dec_ns.fetch_add(ev_dec_ns, Ordering::Relaxed);
                }
            });
        }
    });

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

    Ok(EvParseOutput {
        ev_slabs,
        dedup_chunks,
        ev_worker_arenas,
        ev_worker_ext,
    })
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

fn sort_u64_radix8(slice: &mut [u64], scratch: &mut Vec<u64>) {
    let n = slice.len();
    if n <= 1 {
        return;
    }
    if scratch.len() < n {
        scratch.resize(n, 0);
    }
    let tmp = &mut scratch[..n];

    let mut c0 = [0u32; 256];
    let mut c1 = [0u32; 256];
    let mut c2 = [0u32; 256];
    let mut c3 = [0u32; 256];
    for &x in slice.iter() {
        let k = (x >> 32) as usize;
        c0[k & 0xFF] += 1;
        c1[(k >> 8) & 0xFF] += 1;
        c2[(k >> 16) & 0xFF] += 1;
        c3[(k >> 24) & 0xFF] += 1;
    }

    let k0 = (slice[0] >> 32) as usize;
    let skip0 = c0[k0 & 0xFF] as usize == n;
    let skip1 = c1[(k0 >> 8) & 0xFF] as usize == n;
    let skip2 = c2[(k0 >> 16) & 0xFF] as usize == n;
    let skip3 = c3[(k0 >> 24) & 0xFF] as usize == n;

    let mut in_tmp = false;
    if !skip0 {
        radix_pass_u64(slice, tmp, &mut c0, 32, 0xFF);
        in_tmp = true;
    }
    if !skip1 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c1, 40, 0xFF);
        } else {
            radix_pass_u64(slice, tmp, &mut c1, 40, 0xFF);
        }
        in_tmp = !in_tmp;
    }
    if !skip2 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c2, 48, 0xFF);
        } else {
            radix_pass_u64(slice, tmp, &mut c2, 48, 0xFF);
        }
        in_tmp = !in_tmp;
    }
    if !skip3 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c3, 56, 0xFF);
        } else {
            radix_pass_u64(slice, tmp, &mut c3, 56, 0xFF);
        }
        in_tmp = !in_tmp;
    }

    if in_tmp {
        slice.copy_from_slice(tmp);
    }
}

fn sort_u64_radix(slice: &mut [u64], scratch: &mut Vec<u64>) {
    let n = slice.len();
    if scratch.len() < n {
        scratch.resize(n, 0);
    }
    let tmp = &mut scratch[..n];

    let mut c0 = [0u32; 2048];
    let mut c1 = [0u32; 2048];
    let mut c2 = [0u32; 1024];
    for &x in slice.iter() {
        let k = (x >> 32) as usize;
        c0[k & 0x7FF] += 1;
        c1[(k >> 11) & 0x7FF] += 1;
        c2[(k >> 22) & 0x3FF] += 1;
    }

    let k0 = (slice[0] >> 32) as usize;
    let skip0 = c0[k0 & 0x7FF] as usize == n;
    let skip1 = c1[(k0 >> 11) & 0x7FF] as usize == n;
    let skip2 = c2[(k0 >> 22) & 0x3FF] as usize == n;

    let mut in_tmp = false;
    if !skip0 {
        radix_pass_u64(slice, tmp, &mut c0, 32, 0x7FF);
        in_tmp = true;
    }
    if !skip1 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c1, 43, 0x7FF);
        } else {
            radix_pass_u64(slice, tmp, &mut c1, 43, 0x7FF);
        }
        in_tmp = !in_tmp;
    }
    if !skip2 {
        if in_tmp {
            radix_pass_u64(tmp, slice, &mut c2, 54, 0x3FF);
        } else {
            radix_pass_u64(slice, tmp, &mut c2, 54, 0x3FF);
        }
        in_tmp = !in_tmp;
    }

    if in_tmp {
        slice.copy_from_slice(tmp);
    }
}

impl Stage5Event for PersonEvent16 {
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
            if slice[0] > slice[1] {
                slice.swap(0, 1);
            }
            return;
        }
        if n <= 20 {
            for i in 1..n {
                let key = unsafe { *slice.get_unchecked(i) };
                let mut j = i;
                while j > 0 {
                    let prev = unsafe { *slice.get_unchecked(j - 1) };
                    if prev <= key {
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
        if n < 160 {
            slice.sort_unstable();
        } else if n < 1536 {
            sort_u64_radix8(slice, scratch);
        } else {
            sort_u64_radix(slice, scratch);
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
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool {
        (cur_cmp - prev_cmp) > MS_SESSION_GAP
    }
}

impl Stage5Event for PersonEventWide {
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
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool {
        (cur_cmp as i128 - prev_cmp as i128) > MS_SESSION_GAP as i128
    }
}

impl Stage5Click for PersonClick16 {
    type Grouped = CompactClick16;

    #[inline(always)]
    fn click_person(&self, cl_ext: &[Vec<ExtClick>]) -> ClickPerson {
        if (self.w0 & CL_TAG_MASK) == CL_UB37 {
            ClickPerson::Uh42Rem(self.w0 & CL_REM34_MASK)
        } else {
            let payload = self.w0 & !CL_TAG_MASK;
            let wid = (payload >> 40) as usize;
            let idx = (payload & PE_EXT_IDX_MASK) as usize;
            let pk = unsafe { cl_ext.get_unchecked(wid).get_unchecked(idx).person_key };
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

#[allow(clippy::too_many_arguments)]
fn run_stage5<E: Stage5Event, C: Stage5Click, const PD: bool>(
    person_event_chunks: Vec<Vec<MutChunkRef<E>>>,
    person_click_chunks: Vec<Vec<MutChunkRef<C>>>,
    person_event_counts: &[usize],
    person_click_counts: &[usize],
    cl_ext: &[Vec<ExtClick>],
    ev_arenas: &[LongArena],
    cl_arenas: &[LongArena],
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
                let mut ev_csr_ns = 0u64;
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
                let mut pbuf = [0u8; 10];
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

                    // 1. Unified branchless L1/L2 intern via 8B p_slots_b37 + rare gen_p_table.
                    let t_ev = if PD { Some(Instant::now()) } else { None };
                    let mut p_cap = (ev_total / 16).max(256).next_power_of_two();
                    let mut p_mask = p_cap - 1;
                    let mut p_thresh = p_cap * 6 / 10;
                    p_slots_b37.clear();
                    p_slots_b37.resize(p_cap, 0u64);
                    let mut p_b37_count = 0usize;
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
                                }
                            }
                            let pk = ev.person_key();
                            let pid = if pk.is_uh42() {
                                if p_b37_count >= p_thresh {
                                    p_cap *= 2;
                                    p_mask = p_cap - 1;
                                    p_thresh = p_cap * 6 / 10;
                                    p_slots_b37.clear();
                                    p_slots_b37.resize(p_cap, 0u64);
                                    for (existing_pid, &existing_key) in persons.iter().enumerate() {
                                        if existing_key.is_uh42() {
                                            let r34 = existing_key.uh42_val() & CL_REM34_MASK;
                                            let mut pos = (r34 as usize) & p_mask;
                                            while p_slots_b37[pos] != 0 {
                                                pos = (pos + 1) & p_mask;
                                            }
                                            p_slots_b37[pos] =
                                                (r34 << 30) | ((existing_pid as u64) + 1);
                                        }
                                    }
                                }
                                let rem34 = pk.uh42_val() & CL_REM34_MASK;
                                let mut pos = (rem34 as usize) & p_mask;
                                loop {
                                    let s = unsafe { *p_slots_b37.get_unchecked(pos) };
                                    if s == 0 {
                                        let id = persons.len() as u32;
                                        persons.push(pk);
                                        ev_counts.push(1);
                                        p_b37_count += 1;
                                        unsafe {
                                            *p_slots_b37.get_unchecked_mut(pos) =
                                                (rem34 << 30) | ((id as u64) + 1);
                                        }
                                        break id;
                                    }
                                    if (s >> 30) == rem34 {
                                        let id = ((s & ((1 << 30) - 1)) - 1) as u32;
                                        unsafe {
                                            *ev_counts.get_unchecked_mut(id as usize) += 1;
                                        }
                                        break id;
                                    }
                                    pos = (pos + 1) & p_mask;
                                }
                            } else {
                                has_gen_p = true;
                                let ph = hash_person_key(pk, ev_arenas);
                                match gen_p_table.entry(
                                    ph,
                                    |&id| {
                                        eq_person_keys(persons[id as usize], pk, ev_arenas, ev_arenas)
                                    },
                                    |&id| hash_person_key(persons[id as usize], ev_arenas),
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
                    if let Some(t) = t_ev {
                        ev_csr_ns += t.elapsed().as_nanos() as u64;
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
                        for chunk in &cls_chunks {
                            let batch = unsafe { chunk.as_slice() };
                            let blen = batch.len();
                            let pre = blen.min(RING);
                            for i in 0..pre {
                                if let ClickPerson::Uh42Rem(rem34) =
                                    unsafe { batch.get_unchecked(i).click_person(cl_ext) }
                                {
                                    let npos = (rem34 as usize) & p_mask;
                                    #[cfg(target_arch = "x86_64")]
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            p_slots_b37.as_ptr().add(npos) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                }
                            }
                            for (ridx, c) in batch.iter().enumerate() {
                                if ridx + RING < blen {
                                    if let ClickPerson::Uh42Rem(nrem) =
                                        unsafe { batch.get_unchecked(ridx + RING).click_person(cl_ext) }
                                    {
                                        let npos = (nrem as usize) & p_mask;
                                        #[cfg(target_arch = "x86_64")]
                                        unsafe {
                                            std::arch::x86_64::_mm_prefetch(
                                                p_slots_b37.as_ptr().add(npos) as *const i8,
                                                std::arch::x86_64::_MM_HINT_T0,
                                            );
                                        }
                                    }
                                }
                                let pid = match c.click_person(cl_ext) {
                                    ClickPerson::Uh42Rem(rem34) => {
                                        let mut pos = (rem34 as usize) & p_mask;
                                        loop {
                                            let s = unsafe { *p_slots_b37.get_unchecked(pos) };
                                            if s == 0 {
                                                break u32::MAX;
                                            }
                                            if (s >> 30) == rem34 {
                                                break ((s & ((1 << 30) - 1)) - 1) as u32;
                                            }
                                            pos = (pos + 1) & p_mask;
                                        }
                                    }
                                    ClickPerson::Gen(ck) => {
                                        if has_gen_p {
                                            let ch = hash_person_key(ck, cl_arenas);
                                            gen_p_table
                                                .find(ch, |&id| {
                                                    eq_person_keys(
                                                        persons[id as usize],
                                                        ck,
                                                        ev_arenas,
                                                        cl_arenas,
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
                    let mut shard_sort_ns = 0u64;
                    let mut shard_ud_ns = 0u64;
                    for pid in 0..num_p {
                        let e_lo = ev_offsets[pid] as usize;
                        let e_hi = ev_offsets[pid + 1] as usize;
                        let evs = &mut grouped_events[e_lo..e_hi];
                        let t_s = if PD { Some(Instant::now()) } else { None };
                        E::sort_grouped(evs, &mut radix_scratch);
                        if let Some(t) = t_s {
                            shard_sort_ns += t.elapsed().as_nanos() as u64;
                        }

                        let person_bytes =
                            resolve_person_bytes(persons[pid], link_map, ev_arenas, &mut pbuf);

                        sessions.clear();
                        let (mut sess_start, price0, cat0) = E::unpack_cmp_price_cat(evs[0]);
                        let mut sess_day = E::day_from_cmp(sess_start, ws_day, ws_rem);
                        let mut sess_has_purch = if price0 > 0 { 1i64 } else { 0i64 };
                        let mut sess_rev = price0 as i64;
                        let mut prev_ts = sess_start;

                        let mut cur_day = sess_day;
                        let mut day_sessions = 1i64;
                        let mut day_events = 1i64;
                        let mut day_rev = price0 as i64;
                        if price0 > 0 {
                            cat_rev[cat0 as usize] = price0 as i64;
                            touched_cats.push(cat0);
                        }

                        for &ev_item in &evs[1..] {
                            let (e_ts, e_price, e_cat) = E::unpack_cmp_price_cat(ev_item);
                            if E::gap_exceeds(e_ts, prev_ts) {
                                sessions.push(SessionInfo {
                                    start_cmp: sess_start,
                                    day: sess_day,
                                    has_purchase: sess_has_purch,
                                    revenue_cents: sess_rev,
                                });
                                sess_start = e_ts;
                                sess_day = E::day_from_cmp(e_ts, ws_day, ws_rem);
                                sess_has_purch = 0;
                                sess_rev = 0;

                                if sess_day != cur_day {
                                    let top_cat =
                                        pick_and_reset_top_cat_id(&mut cat_rev, &mut touched_cats);
                                    let t_u = if PD { Some(Instant::now()) } else { None };
                                    let push_res = writer.push(
                                        person_bytes,
                                        cur_day,
                                        day_sessions,
                                        day_events,
                                        day_rev,
                                        top_cat,
                                    );
                                    if let Some(t) = t_u {
                                        shard_ud_ns += t.elapsed().as_nanos() as u64;
                                    }
                                    if let Err(err) = push_res {
                                        *err_lock_ref.lock().unwrap() = Some(err);
                                        return;
                                    }
                                    cur_day = sess_day;
                                    day_sessions = 0;
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

                        sessions.push(SessionInfo {
                            start_cmp: sess_start,
                            day: sess_day,
                            has_purchase: sess_has_purch,
                            revenue_cents: sess_rev,
                        });
                        let top_cat = pick_and_reset_top_cat_id(&mut cat_rev, &mut touched_cats);
                        let t_u = if PD { Some(Instant::now()) } else { None };
                        let push_res = writer.push(
                            person_bytes,
                            cur_day,
                            day_sessions,
                            day_events,
                            day_rev,
                            top_cat,
                        );
                        if let Some(t) = t_u {
                            shard_ud_ns += t.elapsed().as_nanos() as u64;
                        }
                        if let Err(err) = push_res {
                            *err_lock_ref.lock().unwrap() = Some(err);
                            return;
                        }

                        // Credit + Assists
                        if total_matched_cl == 0 {
                            for s in &sessions {
                                acc.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                            }
                            continue;
                        }
                        let c_lo = cl_offsets[pid] as usize;
                        let c_hi = cl_offsets[pid + 1] as usize;
                        if c_lo == c_hi {
                            for s in &sessions {
                                acc.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                            }
                            continue;
                        }

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

                        let t_s2 = if PD { Some(Instant::now()) } else { None };
                        C::sort_grouped(clks);
                        if let Some(t) = t_s2 {
                            shard_sort_ns += t.elapsed().as_nanos() as u64;
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
                                        && cmp_raw_keys(ckey, best_ckey, cl_arenas, cl_arenas)
                                            == std::cmp::Ordering::Less
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
                                        && cmp_raw_keys(ckey, best_ckey, cl_arenas, cl_arenas)
                                            == std::cmp::Ordering::Less
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
                    detail.s5_ev_csr_ns.fetch_add(ev_csr_ns, Ordering::Relaxed);
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
fn run_typed_stages<E: DedupEmit + Stage5Event, C: ClickEmit + Stage5Click, const PD: bool>(
    dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>>,
    ev_worker_ext: Vec<Vec<ExtEvent>>,
    ev_worker_arenas: Vec<LongArena>,
    ev_slabs: Vec<SlabArena>,
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
        &ev_worker_ext,
        &ev_worker_arenas,
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
    drop(ev_worker_ext);
    drop(ev_slabs);
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
        &out.cl_worker_arenas,
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

    // Build LinkMap first with uncontended parallelism, then run work-stealing events parse.
    let link_paths = list_csv_files(&data_dir.join("links"))?;
    let t_links_start = Instant::now();
    let mut link_map = build_link_map(&link_paths, ncpu)?;
    let t_links = Instant::now();
    if PD {
        detail
            .links_w_ns
            .store((t_links - t_links_start).as_nanos() as u64, Ordering::Relaxed);
    }

    let event_paths = list_csv_files(&data_dir.join("events"))?;
    let event_src = CsvSource::open(&event_paths)?;
    let ev_chunks = event_src.chunks(CHUNK_BYTES);
    let n_ev_workers = ncpu.clamp(1, 63).min(ev_chunks.len().max(1));
    let est_ev_total = event_src.total_bytes() / 68;
    let ev_hint_bytes = (est_ev_total * 16) / n_ev_workers.max(1);

    let ev_out = if compact_ev_mode {
        run_parse_events_par::<true, PD>(
            &event_src,
            &ev_chunks,
            ev_hint_bytes,
            &lookups,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            ncpu,
            &detail,
        )?
    } else {
        run_parse_events_par::<false, PD>(
            &event_src,
            &ev_chunks,
            ev_hint_bytes,
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

    let ev_slabs = ev_out.ev_slabs;
    let dedup_slots: Vec<Mutex<Option<Vec<MutChunkRef<ParsedEvent16>>>>> = ev_out
        .dedup_chunks
        .into_iter()
        .map(|v| Mutex::new(Some(v)))
        .collect();
    let ev_worker_arenas = ev_out.ev_worker_arenas;
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
            ev_worker_ext,
            ev_worker_arenas,
            ev_slabs,
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
            ev_worker_ext,
            ev_worker_arenas,
            ev_slabs,
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
            ev_worker_ext,
            ev_worker_arenas,
            ev_slabs,
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
            num_camps,
            assists,
            credits,
        } => {
            for c in 0..*num_camps {
                let c_name = lookups.camp_name(c);
                let ch_name = lookups.camp_channel(c);
                for d_off in 0..*num_days {
                    let idx = d_off * (*num_camps) + c;
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
                    let hp = (next_u64() % 2) as i64;
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
                let ckey = CompactKey64::from_comp((clk_i as u32) ^ ((next_u64() & 0xFF) as u32));
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
                            && cmp_raw_keys(ckey, best_ckey, &empty_arenas, &empty_arenas)
                                == std::cmp::Ordering::Less
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
                                        && cmp_raw_keys(ckey, bkey, &empty_arenas, &empty_arenas)
                                            == std::cmp::Ordering::Less) =>
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
        let mut scratch = Vec::new();
        for &n in &[256usize, 384, 500, 1536, 2048, 5000] {
            for mode in [0u8, 1, 2, 3] {
                let mut v = Vec::with_capacity(n);
                for idx in 0..n {
                    let ts_rel = match mode {
                        0 => 123_456_789,
                        1 => next_u64() % 200_000,
                        2 => next_u64() % 1_209_600_000,
                        _ => match idx {
                            0 => 0,
                            1 => u32::MAX as u64,
                            2 => (1u64 << 22) - 1,
                            3 => 1u64 << 22,
                            _ => next_u64() & (u32::MAX as u64),
                        },
                    };
                    let low = next_u64() & 0xFFFF_FFFF;
                    v.push((ts_rel << 32) | low);
                }
                let mut expected: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                expected.sort_unstable();
                let mut v2 = v.clone();
                sort_u64_radix(&mut v, &mut scratch);
                let got: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got, expected, "radix mismatch n={n} mode={mode}");

                <PersonEvent16 as Stage5Event>::sort_grouped(&mut v2, &mut scratch);
                let got2: Vec<u32> = v2.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got2, expected, "sort_grouped mismatch n={n} mode={mode}");
            }
        }
        for &n in &[128usize, 159, 160, 255, 256, 512, 1024, 1535] {
            for mode in [0u8, 1, 2, 3, 4, 5] {
                let mut v = Vec::with_capacity(n);
                for idx in 0..n {
                    let ts_rel = match mode {
                        0 => 123_456_789,
                        1 => (0x00AB_CD12u64 << 8) | (next_u64() & 0xFF),
                        2 => next_u64() % 1_209_600_000,
                        3 => match idx {
                            0 => 0,
                            1 => u32::MAX as u64,
                            2 => (1u64 << 22) - 1,
                            3 => 1u64 << 22,
                            _ => next_u64() & (u32::MAX as u64),
                        },
                        4 => ((n - idx) as u64).wrapping_mul(17_000_003) & (u32::MAX as u64),
                        _ => (next_u64() % 7) * 500_000_000,
                    };
                    let low = idx as u64;
                    v.push((ts_rel << 32) | low);
                }
                let mut expected_hi: Vec<u32> = v.iter().map(|x| (x >> 32) as u32).collect();
                expected_hi.sort_unstable();
                let mut v_std_stable = v.clone();
                v_std_stable.sort_by_key(|x| (x >> 32) as u32);
                let mut v_grouped = v.clone();

                sort_u64_radix8(&mut v, &mut scratch);
                assert_eq!(
                    v, v_std_stable,
                    "radix8 mismatch n={n} mode={mode}"
                );

                <PersonEvent16 as Stage5Event>::sort_grouped(&mut v_grouped, &mut scratch);
                let got_hi: Vec<u32> = v_grouped.iter().map(|x| (x >> 32) as u32).collect();
                assert_eq!(got_hi, expected_hi, "sort_grouped radix8 mismatch n={n} mode={mode}");
            }
        }
        for &n in &[0usize, 1, 2, 3, 5, 16, 20, 21, 24, 25, 100, 159] {
            for mode in [0u8, 2, 3] {
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let ts_rel = match mode {
                        0 => 42,
                        2 => next_u64() % 1_209_600_000,
                        _ => next_u64() & (u32::MAX as u64),
                    };
                    let low = next_u64() & 0xFFFF_FFFF;
                    v.push((ts_rel << 32) | low);
                }
                let mut expected = v.clone();
                expected.sort_unstable();
                <PersonEvent16 as Stage5Event>::sort_grouped(&mut v, &mut scratch);
                assert_eq!(v, expected, "small sort_grouped mismatch n={n} mode={mode}");
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
}
