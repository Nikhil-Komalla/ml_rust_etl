use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use hashbrown::{HashMap, HashTable};
use parquet::basic::Compression;

use crate::csv::{
    cmp_raw_keys, for_each_line_fields_slice, hash_bytes_fast, hash_raw_key, list_csv_files,
    mix64, CompactKey64, CsvSource, LongArena, CHUNK_BYTES,
};
use crate::links::{build_link_map, LinkMap};
use crate::parse::{
    parse_price_cents, parse_ts_ms, DateCache, Manifest, MS_CLICK_REACH, MS_DAY, MS_SECOND,
    MS_SESSION_GAP,
};
use crate::parquet_out::{clean_parquet_dir, write_campaign_daily, CampaignRow, UserDailyWriter};

const P_DEDUP: usize = 256;
const P_PERSON: usize = 128;
const USER_DAILY_BATCH_ROWS: usize = 131_072;

const META_TAG_SHIFT: u32 = 62;
const META_VALID_FAST: u64 = 0u64 << META_TAG_SHIFT;
const META_VALID_EXT: u64 = 1u64 << META_TAG_SHIFT;
const META_INVALID: u64 = 2u64 << META_TAG_SHIFT;
const META_DEAD: u64 = 3u64 << META_TAG_SHIFT;
const META_FAST_TS_MASK: u64 = (1u64 << 31) - 1;
const META_FAST_ING_BIAS: i64 = 1i64 << 30;
const META_EXT_IDX_MASK: u64 = (1u64 << 40) - 1;

#[derive(Clone, Copy)]
#[repr(C)]
struct ParsedEvent {
    ev_key: CompactKey64,
    person_key: CompactKey64,
    meta: u64,
}

const _: () = assert!(std::mem::size_of::<ParsedEvent>() == 24);

#[derive(Clone, Copy)]
struct ExtEvent {
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

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonClick16 {
    person_key: CompactKey64,
    click_id_key: CompactKey64,
    ts_rel_ms: u32,
    camp_id: u32,
}

const _: () = assert!(std::mem::size_of::<PersonClick16>() == 24);

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
        cells: Vec<CampDayAgg>,
    },
    Sparse(HashMap<(u32, i32), CampDayAgg>),
}

impl CampDailyAcc {
    fn new(num_camps: usize, min_day: i32, max_day: i32) -> Self {
        let span = (max_day as i64 - min_day as i64 + 1).max(1) as usize;
        if span <= 4096 && num_camps <= 16_384 && span.saturating_mul(num_camps) <= 1_048_576 {
            Self::Dense {
                start_day: min_day,
                num_days: span,
                num_camps,
                cells: vec![CampDayAgg::default(); span * num_camps],
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
                cells,
            } => {
                let d_off = day - *start_day;
                if d_off >= 0 && (d_off as usize) < *num_days && (camp_id as usize) < *num_camps {
                    let c = &mut cells[(camp_id as usize) * (*num_days) + (d_off as usize)];
                    c.sessions += 1;
                    c.purchasing_sessions += has_purchase;
                    c.revenue_cents += rev;
                    return;
                }
                unreachable!("credit day {day} or camp {camp_id} outside dense range");
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
                cells,
            } => {
                let d_off = day - *start_day;
                if d_off >= 0 && (d_off as usize) < *num_days && (camp_id as usize) < *num_camps {
                    cells[(camp_id as usize) * (*num_days) + (d_off as usize)].assisted_sessions +=
                        cnt;
                    return;
                }
                unreachable!("assist day {day} or camp {camp_id} outside dense range");
            }
            Self::Sparse(map) => {
                map.entry((camp_id, day)).or_default().assisted_sessions += cnt;
            }
        }
    }

    fn merge_into(&mut self, other: CampDailyAcc) {
        match (self, other) {
            (Self::Dense { cells: dst, .. }, Self::Dense { cells: src, .. }) => {
                for (d, s) in dst.iter_mut().zip(src.iter()) {
                    d.add_assign(s);
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

struct CampEntry {
    cid_off: usize,
    cid_len: usize,
    ch_off: usize,
    ch_len: usize,
}

struct Lookups {
    prod_slots: Vec<FlatKvSlot>,
    prod_mask: usize,
    long_prod_map: HashMap<Box<[u8]>, u32>,
    has_long_prod: bool,
    categories: Vec<Box<[u8]>>,
    unknown_cat_id: u32,
    camp_buf: Vec<u8>,
    camp_entries: Vec<CampEntry>,
    camp_slots: Vec<FlatKvSlot>,
    camp_mask: usize,
    long_camp_map: HashMap<Box<[u8]>, u32>,
    has_long_camp: bool,
    organic_camp_id: u32,
}

impl Lookups {
    #[inline(always)]
    fn get_product_cat(&self, pid: &[u8]) -> u32 {
        if let Some(k) = CompactKey64::encode_raw_inline(pid) {
            let mut pos = (mix64(k.0) as usize) & self.prod_mask;
            loop {
                let s = self.prod_slots[pos];
                if s.key == k.0 {
                    return s.val;
                }
                if s.key == 0 {
                    return self.unknown_cat_id;
                }
                pos = (pos + 1) & self.prod_mask;
            }
        } else if self.has_long_prod {
            self.long_prod_map
                .get(pid)
                .copied()
                .unwrap_or(self.unknown_cat_id)
        } else {
            self.unknown_cat_id
        }
    }

    #[inline(always)]
    fn get_campaign(&self, cid: &[u8]) -> Option<u32> {
        if let Some(k) = CompactKey64::encode_raw_inline(cid) {
            let mut pos = (mix64(k.0) as usize) & self.camp_mask;
            loop {
                let s = self.camp_slots[pos];
                if s.key == k.0 {
                    return Some(s.val);
                }
                if s.key == 0 {
                    return None;
                }
                pos = (pos + 1) & self.camp_mask;
            }
        } else if self.has_long_camp {
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
    let est_prods = (prod_buf.len() / 10).max(16);
    let p_cap = (est_prods * 2).next_power_of_two();
    let mut prod_slots = vec![FlatKvSlot::EMPTY; p_cap];
    let mut prod_mask = p_cap - 1;
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
            insert_flat_kv(&mut prod_slots, &mut prod_mask, &mut prod_count, k.0, tmp_cat);
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
    for s in &mut prod_slots {
        if s.key != 0 {
            s.val = remap[s.val as usize];
        }
    }
    for v in long_prod_map.values_mut() {
        *v = remap[*v as usize];
    }

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
    let mut camp_slots = vec![FlatKvSlot::EMPTY; c_cap];
    let mut camp_mask = c_cap - 1;
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
            insert_flat_kv(&mut camp_slots, &mut camp_mask, &mut camp_count, k.0, idx);
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

    let has_long_prod = !long_prod_map.is_empty();
    let has_long_camp = !long_camp_map.is_empty();

    Ok(Lookups {
        prod_slots,
        prod_mask,
        long_prod_map,
        has_long_prod,
        categories,
        unknown_cat_id,
        camp_buf,
        camp_entries,
        camp_slots,
        camp_mask,
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
    if key.is_comp() {
        link_map.canon_bytes(key.comp_id())
    } else if key.is_ref() {
        LongArena::resolve_in(ev_arenas, key)
    } else {
        let len = key.decode_inline(stack_buf);
        &stack_buf[..len]
    }
}

#[inline(always)]
fn ev_ingest_ts(ev: &ParsedEvent, window_start_sec: i64, ext_by_worker: &[Vec<ExtEvent>]) -> i64 {
    let tag = ev.meta & (3u64 << META_TAG_SHIFT);
    if tag == META_VALID_FAST {
        let biased = ((ev.meta >> 31) & META_FAST_TS_MASK) as i64;
        (window_start_sec + (biased - META_FAST_ING_BIAS)) * 1_000
    } else if tag == META_VALID_EXT {
        let payload = ev.meta & !(3u64 << META_TAG_SHIFT);
        let wid = (payload >> 40) as usize;
        let idx = (payload & META_EXT_IDX_MASK) as usize;
        ext_by_worker[wid][idx].ingest_ts_ms
    } else {
        ev.person_key.0 as i64
    }
}

#[inline(always)]
fn ev_payload_compact(
    ev: &ParsedEvent,
    window_start_ms: i64,
    ext_by_worker: &[Vec<ExtEvent>],
) -> (u32, u32) {
    let tag = ev.meta & (3u64 << META_TAG_SHIFT);
    if tag == META_VALID_FAST {
        ((ev.meta & META_FAST_TS_MASK) as u32, 0)
    } else {
        let payload = ev.meta & !(3u64 << META_TAG_SHIFT);
        let wid = (payload >> 40) as usize;
        let idx = (payload & META_EXT_IDX_MASK) as usize;
        let ex = ext_by_worker[wid][idx];
        let ts_rel = (ex.ts_ms - window_start_ms) as u32;
        let price_cat = (ex.cat_id << 24) | ex.price_cents;
        (ts_rel, price_cat)
    }
}

#[inline(always)]
fn ev_payload_wide(ev: &ParsedEvent, ext_by_worker: &[Vec<ExtEvent>]) -> (i64, u32, u32) {
    let payload = ev.meta & !(3u64 << META_TAG_SHIFT);
    let wid = (payload >> 40) as usize;
    let idx = (payload & META_EXT_IDX_MASK) as usize;
    let ex = ext_by_worker[wid][idx];
    (ex.ts_ms, ex.price_cents, ex.cat_id)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct PersonSlot {
    key: u64,
    pid: u32,
}

impl PersonSlot {
    const EMPTY: Self = Self { key: 0, pid: 0 };
}

trait Stage5Event: Copy + Send + Sync {
    type Grouped: Copy + Send;
    fn person_key(&self) -> CompactKey64;
    fn to_grouped(&self) -> Self::Grouped;
    fn sort_grouped(slice: &mut [Self::Grouped]);
    fn unpack(g: Self::Grouped, ws_day: i32, ws_rem: u64) -> (i64, i32, u32, u32);
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool;
}

trait Stage5Click: Copy + Send + Sync {
    type Grouped: Copy + Send;
    fn person_key(&self) -> CompactKey64;
    fn to_grouped(&self) -> Self::Grouped;
    fn sort_grouped(slice: &mut [Self::Grouped]);
    fn unpack_full(g: &Self::Grouped) -> (i64, u32, CompactKey64);
}

trait ClickEmit: Stage5Click {
    fn set_person_key(&mut self, pk: CompactKey64);
    fn from_parsed(
        person_key: CompactKey64,
        click_id_key: CompactKey64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self;
}

impl ClickEmit for PersonClick16 {
    #[inline(always)]
    fn set_person_key(&mut self, pk: CompactKey64) {
        self.person_key = pk;
    }

    #[inline(always)]
    fn from_parsed(
        person_key: CompactKey64,
        click_id_key: CompactKey64,
        ts_ms: i64,
        click_window_start_ms: i64,
        camp_id: u32,
    ) -> Self {
        Self {
            person_key,
            click_id_key,
            ts_rel_ms: (ts_ms - click_window_start_ms) as u32,
            camp_id,
        }
    }
}

impl ClickEmit for PersonClickWide {
    #[inline(always)]
    fn set_person_key(&mut self, pk: CompactKey64) {
        self.person_key = pk;
    }

    #[inline(always)]
    fn from_parsed(
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

#[inline(always)]
fn swcb_push<T: Copy, const W: usize>(
    swcb: &mut [T],
    cnts: &mut [u8],
    buckets: &mut [Vec<T>],
    shard: usize,
    val: T,
) {
    let base = shard * W;
    let c = unsafe { *cnts.get_unchecked(shard) } as usize;
    unsafe {
        *swcb.get_unchecked_mut(base + c) = val;
    }
    let c = c + 1;
    if c < W {
        unsafe {
            *cnts.get_unchecked_mut(shard) = c as u8;
        }
    } else {
        unsafe {
            buckets
                .get_unchecked_mut(shard)
                .extend_from_slice(swcb.get_unchecked(base..base + W));
            *cnts.get_unchecked_mut(shard) = 0;
        }
    }
}

struct ParsedPoolOutput<C> {
    dedup_inputs: Vec<Vec<Vec<ParsedEvent>>>,
    ev_worker_arenas: Vec<LongArena>,
    ev_worker_ext: Vec<Vec<ExtEvent>>,
    person_click_batches: Vec<Vec<Vec<C>>>,
    person_click_counts: Vec<usize>,
    cl_worker_arenas: Vec<LongArena>,
}

fn run_parse_events_and_clicks<C: ClickEmit>(
    event_src: &CsvSource,
    ev_chunks: &[crate::csv::ChunkTask],
    est_ev_cap: usize,
    click_src: &CsvSource,
    cl_chunks: &[crate::csv::ChunkTask],
    est_cl_cap: usize,
    lookups: &Lookups,
    link_map: &LinkMap,
    window_start_ms: i64,
    window_end_ms: i64,
    window_start_sec: i64,
    click_window_start_ms: i64,
    compact_mode: bool,
    n_workers: usize,
) -> io::Result<ParsedPoolOutput<C>> {
    const SWCB_EV: usize = 8;
    const SWCB_CL: usize = 8;

    let mut ev_worker_shards: Vec<Vec<Vec<ParsedEvent>>> =
        (0..n_workers).map(|_| Vec::new()).collect();
    let mut ev_worker_arenas: Vec<LongArena> = (0..n_workers).map(|_| LongArena::default()).collect();
    let mut ev_worker_ext: Vec<Vec<ExtEvent>> = (0..n_workers).map(|_| Vec::new()).collect();
    let mut cl_worker_shards: Vec<Vec<Vec<C>>> = (0..n_workers).map(|_| Vec::new()).collect();
    let mut cl_worker_arenas: Vec<LongArena> = (0..n_workers).map(|_| LongArena::default()).collect();
    let mut worker_errs: Vec<Option<io::Error>> = (0..n_workers).map(|_| None).collect();

    if !ev_chunks.is_empty() || !cl_chunks.is_empty() {
        let next_ev = AtomicUsize::new(0);
        let next_cl = AtomicUsize::new(0);
        let lm_empty = link_map.is_empty();

        std::thread::scope(|scope| {
            for (
                wid,
                (((((ev_buckets_slot, ev_arena_out), ext_out), cl_buckets_slot), cl_arena_out), err_out),
            ) in ev_worker_shards
                .iter_mut()
                .zip(ev_worker_arenas.iter_mut())
                .zip(ev_worker_ext.iter_mut())
                .zip(cl_worker_shards.iter_mut())
                .zip(cl_worker_arenas.iter_mut())
                .zip(worker_errs.iter_mut())
                .enumerate()
            {
                let next_ev_ref = &next_ev;
                let next_cl_ref = &next_cl;
                scope.spawn(move || {
                    let mut dcache = DateCache::new();
                    let mut buf = Vec::new();
                    let mut hit_idxs = [0u8; 64];
                    let mut pending_uh = [0u64; 64];

                    // Events phase
                    if !ev_chunks.is_empty() {
                        let first = next_ev_ref.fetch_add(1, Ordering::Relaxed);
                        if first < ev_chunks.len() {
                            let mut ev_buckets: Vec<Vec<ParsedEvent>> =
                                (0..P_DEDUP).map(|_| Vec::with_capacity(est_ev_cap)).collect();
                            let mut swcb = vec![
                                ParsedEvent {
                                    ev_key: CompactKey64::EMPTY,
                                    person_key: CompactKey64::EMPTY,
                                    meta: 0,
                                };
                                P_DEDUP * SWCB_EV
                            ];
                            let mut swcb_cnt = [0u8; P_DEDUP];
                            let mut pending_ev = [ParsedEvent {
                                ev_key: CompactKey64::EMPTY,
                                person_key: CompactKey64::EMPTY,
                                meta: 0,
                            }; 64];
                            let mut pending_ds = [0u8; 64];

                            let mut cidx = first;
                            while let Some(&task) = ev_chunks.get(cidx) {
                                if let Err(e) =
                                    event_src.for_each_chunk_batch::<7>(task, &mut buf, |data, spans| {
                                        let mut n_pending = 0usize;

                                        for sp in spans {
                                            let ev_id = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[0] as usize..sp.ends[0] as usize,
                                                )
                                            };
                                            if ev_id.is_empty() {
                                                continue;
                                            }
                                            let ingest_ts = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[3] as usize..sp.ends[3] as usize,
                                                )
                                            };
                                            let Some((ingest_sec, hint_hi, hint_lo, hint_dd)) =
                                                dcache.parse_f1_sec_with_date(ingest_ts)
                                            else {
                                                continue;
                                            };
                                            let ingest_ms = ingest_sec * MS_SECOND;
                                            let (ev_key, ev_hash) =
                                                if let Some(k) = CompactKey64::encode_raw_inline(ev_id)
                                                {
                                                    (k, mix64(k.0))
                                                } else {
                                                    (
                                                        ev_arena_out.push_ref(wid, ev_id),
                                                        hash_bytes_fast(ev_id),
                                                    )
                                                };
                                            let d_shard =
                                                ((ev_hash >> 52) as usize) & (P_DEDUP - 1);

                                            let uid = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[1] as usize..sp.ends[1] as usize,
                                                )
                                            };
                                            let ts = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[2] as usize..sp.ends[2] as usize,
                                                )
                                            };
                                            let etype = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[4] as usize..sp.ends[4] as usize,
                                                )
                                            };
                                            let pid = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[5] as usize..sp.ends[5] as usize,
                                                )
                                            };
                                            let price = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[6] as usize..sp.ends[6] as usize,
                                                )
                                            };

                                            let mut valid = false;
                                            let mut ts_ms = 0i64;
                                            let mut price_val = 0u32;
                                            let mut cat_id = 0u32;
                                            let mut is_purchase = false;

                                            if !uid.is_empty() && !pid.is_empty() {
                                                if etype.len() == 4 {
                                                    const VIEW_U32: u32 =
                                                        u32::from_ne_bytes(*b"view");
                                                    const CART_U32: u32 =
                                                        u32::from_ne_bytes(*b"cart");
                                                    let w = unsafe {
                                                        u32::from_ne_bytes(
                                                            *(etype.as_ptr() as *const [u8; 4]),
                                                        )
                                                    };
                                                    if (w == VIEW_U32) | (w == CART_U32) {
                                                        if let Some(t) = dcache
                                                            .parse_ts_ms_with_hint(
                                                                ts, hint_hi, hint_lo, hint_dd,
                                                            )
                                                        {
                                                            if t >= window_start_ms
                                                                && t < window_end_ms
                                                                && (ingest_ms as i128 - t as i128)
                                                                    <= MS_DAY as i128
                                                            {
                                                                ts_ms = t;
                                                                valid = true;
                                                            }
                                                        }
                                                    }
                                                } else if etype == b"purchase" {
                                                    if let Some(p) = parse_price_cents(price) {
                                                        if let Some(t) = dcache
                                                            .parse_ts_ms_with_hint(
                                                                ts, hint_hi, hint_lo, hint_dd,
                                                            )
                                                        {
                                                            if t >= window_start_ms
                                                                && t < window_end_ms
                                                                && (ingest_ms as i128 - t as i128)
                                                                    <= MS_DAY as i128
                                                            {
                                                                ts_ms = t;
                                                                price_val = p;
                                                                cat_id =
                                                                    lookups.get_product_cat(pid);
                                                                is_purchase = true;
                                                                valid = true;
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            if !valid {
                                                swcb_push::<ParsedEvent, SWCB_EV>(
                                                    &mut swcb,
                                                    &mut swcb_cnt,
                                                    &mut ev_buckets,
                                                    d_shard,
                                                    ParsedEvent {
                                                        ev_key,
                                                        person_key: CompactKey64(ingest_ms as u64),
                                                        meta: META_INVALID,
                                                    },
                                                );
                                                continue;
                                            }

                                            let meta = if compact_mode && !is_purchase {
                                                let ingest_sec_rel = ingest_sec - window_start_sec;
                                                if (-META_FAST_ING_BIAS..META_FAST_ING_BIAS)
                                                    .contains(&ingest_sec_rel)
                                                {
                                                    let ts_rel = (ts_ms - window_start_ms) as u64;
                                                    let biased =
                                                        (ingest_sec_rel + META_FAST_ING_BIAS) as u64;
                                                    META_VALID_FAST | (biased << 31) | ts_rel
                                                } else {
                                                    let ext_idx = ext_out.len() as u64;
                                                    ext_out.push(ExtEvent {
                                                        ts_ms,
                                                        ingest_ts_ms: ingest_ms,
                                                        price_cents: price_val,
                                                        cat_id,
                                                    });
                                                    META_VALID_EXT | ((wid as u64) << 40) | ext_idx
                                                }
                                            } else {
                                                let ext_idx = ext_out.len() as u64;
                                                ext_out.push(ExtEvent {
                                                    ts_ms,
                                                    ingest_ts_ms: ingest_ms,
                                                    price_cents: price_val,
                                                    cat_id,
                                                });
                                                META_VALID_EXT | ((wid as u64) << 40) | ext_idx
                                            };

                                            if let Some(uk) = CompactKey64::encode_raw_inline(uid) {
                                                if lm_empty {
                                                    swcb_push::<ParsedEvent, SWCB_EV>(
                                                        &mut swcb,
                                                        &mut swcb_cnt,
                                                        &mut ev_buckets,
                                                        d_shard,
                                                        ParsedEvent {
                                                            ev_key,
                                                            person_key: uk,
                                                            meta,
                                                        },
                                                    );
                                                } else {
                                                    let uh = mix64(uk.0);
                                                    link_map.prefetch_bloom(uh);
                                                    pending_ev[n_pending] = ParsedEvent {
                                                        ev_key,
                                                        person_key: uk,
                                                        meta,
                                                    };
                                                    pending_uh[n_pending] = uh;
                                                    pending_ds[n_pending] = d_shard as u8;
                                                    n_pending += 1;
                                                }
                                            } else {
                                                let person_key = link_map
                                                    .resolve_long(uid)
                                                    .unwrap_or_else(|| {
                                                        ev_arena_out.push_ref(wid, uid)
                                                    });
                                                swcb_push::<ParsedEvent, SWCB_EV>(
                                                    &mut swcb,
                                                    &mut swcb_cnt,
                                                    &mut ev_buckets,
                                                    d_shard,
                                                    ParsedEvent {
                                                        ev_key,
                                                        person_key,
                                                        meta,
                                                    },
                                                );
                                            }
                                        }

                                        let mut n_hits = 0usize;
                                        for j in 0..n_pending {
                                            let uh = pending_uh[j];
                                            if link_map.bloom_may_contain(uh) {
                                                link_map.prefetch_slot(uh);
                                                hit_idxs[n_hits] = j as u8;
                                                n_hits += 1;
                                            } else {
                                                swcb_push::<ParsedEvent, SWCB_EV>(
                                                    &mut swcb,
                                                    &mut swcb_cnt,
                                                    &mut ev_buckets,
                                                    pending_ds[j] as usize,
                                                    pending_ev[j],
                                                );
                                            }
                                        }

                                        for k in 0..n_hits {
                                            let j = hit_idxs[k] as usize;
                                            let mut ev = pending_ev[j];
                                            ev.person_key = link_map
                                                .probe_inline_with_hash(ev.person_key, pending_uh[j]);
                                            swcb_push::<ParsedEvent, SWCB_EV>(
                                                &mut swcb,
                                                &mut swcb_cnt,
                                                &mut ev_buckets,
                                                pending_ds[j] as usize,
                                                ev,
                                            );
                                        }
                                    })
                                {
                                    *err_out = Some(e);
                                    return;
                                }
                                cidx = next_ev_ref.fetch_add(1, Ordering::Relaxed);
                            }

                            for ds in 0..P_DEDUP {
                                let cnt = swcb_cnt[ds] as usize;
                                if cnt > 0 {
                                    let base = ds * SWCB_EV;
                                    ev_buckets[ds].extend_from_slice(&swcb[base..base + cnt]);
                                }
                            }
                            *ev_buckets_slot = ev_buckets;
                        }
                    }

                    // Clicks phase immediately in same worker pool (no barrier)
                    if !cl_chunks.is_empty() {
                        let first = next_cl_ref.fetch_add(1, Ordering::Relaxed);
                        if first < cl_chunks.len() {
                            let mut cl_buckets: Vec<Vec<C>> =
                                (0..P_PERSON).map(|_| Vec::with_capacity(est_cl_cap)).collect();
                            let tmpl = C::from_parsed(
                                CompactKey64::EMPTY,
                                CompactKey64::EMPTY,
                                0,
                                0,
                                0,
                            );
                            let mut swcb = vec![tmpl; P_PERSON * SWCB_CL];
                            let mut swcb_cnt = [0u8; P_PERSON];
                            let mut pending_cl = [tmpl; 64];

                            let mut cidx = first;
                            while let Some(&task) = cl_chunks.get(cidx) {
                                if let Err(e) =
                                    click_src.for_each_chunk_batch::<4>(task, &mut buf, |data, spans| {
                                        let mut n_pending = 0usize;

                                        for sp in spans {
                                            let click_id = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[0] as usize..sp.ends[0] as usize,
                                                )
                                            };
                                            let uid = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[1] as usize..sp.ends[1] as usize,
                                                )
                                            };
                                            if click_id.is_empty() || uid.is_empty() {
                                                continue;
                                            }
                                            let camp_id = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[2] as usize..sp.ends[2] as usize,
                                                )
                                            };
                                            let Some(cid) = lookups.get_campaign(camp_id) else {
                                                continue;
                                            };
                                            let ts = unsafe {
                                                data.get_unchecked(
                                                    sp.starts[3] as usize..sp.ends[3] as usize,
                                                )
                                            };
                                            let Some(ts_ms) = dcache.parse_ts_ms(ts) else {
                                                continue;
                                            };
                                            if ts_ms < click_window_start_ms
                                                || ts_ms >= window_end_ms
                                            {
                                                continue;
                                            }
                                            let click_id_key =
                                                CompactKey64::encode_raw(click_id, wid, cl_arena_out);

                                            if let Some(uk) = CompactKey64::encode_raw_inline(uid) {
                                                let uh = mix64(uk.0);
                                                if lm_empty {
                                                    let pshard =
                                                        ((uh >> 52) as usize) & (P_PERSON - 1);
                                                    swcb_push::<C, SWCB_CL>(
                                                        &mut swcb,
                                                        &mut swcb_cnt,
                                                        &mut cl_buckets,
                                                        pshard,
                                                        C::from_parsed(
                                                            uk,
                                                            click_id_key,
                                                            ts_ms,
                                                            click_window_start_ms,
                                                            cid,
                                                        ),
                                                    );
                                                } else {
                                                    link_map.prefetch_bloom(uh);
                                                    pending_cl[n_pending] = C::from_parsed(
                                                        uk,
                                                        click_id_key,
                                                        ts_ms,
                                                        click_window_start_ms,
                                                        cid,
                                                    );
                                                    pending_uh[n_pending] = uh;
                                                    n_pending += 1;
                                                }
                                            } else {
                                                let (pk, ph) =
                                                    if let Some(pk) = link_map.resolve_long(uid) {
                                                        (pk, mix64(pk.0))
                                                    } else {
                                                        (
                                                            cl_arena_out.push_ref(wid, uid),
                                                            hash_bytes_fast(uid),
                                                        )
                                                    };
                                                let pshard =
                                                    ((ph >> 52) as usize) & (P_PERSON - 1);
                                                swcb_push::<C, SWCB_CL>(
                                                    &mut swcb,
                                                    &mut swcb_cnt,
                                                    &mut cl_buckets,
                                                    pshard,
                                                    C::from_parsed(
                                                        pk,
                                                        click_id_key,
                                                        ts_ms,
                                                        click_window_start_ms,
                                                        cid,
                                                    ),
                                                );
                                            }
                                        }

                                        let mut n_hits = 0usize;
                                        for j in 0..n_pending {
                                            let uh = pending_uh[j];
                                            if link_map.bloom_may_contain(uh) {
                                                link_map.prefetch_slot(uh);
                                                hit_idxs[n_hits] = j as u8;
                                                n_hits += 1;
                                            } else {
                                                let pshard =
                                                    ((uh >> 52) as usize) & (P_PERSON - 1);
                                                swcb_push::<C, SWCB_CL>(
                                                    &mut swcb,
                                                    &mut swcb_cnt,
                                                    &mut cl_buckets,
                                                    pshard,
                                                    pending_cl[j],
                                                );
                                            }
                                        }

                                        for k in 0..n_hits {
                                            let j = hit_idxs[k] as usize;
                                            let mut pc = pending_cl[j];
                                            let uk = pc.person_key();
                                            let uh = pending_uh[j];
                                            let pk = link_map.probe_inline_with_hash(uk, uh);
                                            let ph = if pk.0 == uk.0 { uh } else { mix64(pk.0) };
                                            pc.set_person_key(pk);
                                            let pshard = ((ph >> 52) as usize) & (P_PERSON - 1);
                                            swcb_push::<C, SWCB_CL>(
                                                &mut swcb,
                                                &mut swcb_cnt,
                                                &mut cl_buckets,
                                                pshard,
                                                pc,
                                            );
                                        }
                                    })
                                {
                                    *err_out = Some(e);
                                    return;
                                }
                                cidx = next_cl_ref.fetch_add(1, Ordering::Relaxed);
                            }

                            for ps in 0..P_PERSON {
                                let cnt = swcb_cnt[ps] as usize;
                                if cnt > 0 {
                                    let base = ps * SWCB_CL;
                                    cl_buckets[ps].extend_from_slice(&swcb[base..base + cnt]);
                                }
                            }
                            *cl_buckets_slot = cl_buckets;
                        }
                    }
                });
            }
        });
    }

    for e in worker_errs.into_iter().flatten() {
        return Err(e);
    }

    let mut dedup_inputs: Vec<Vec<Vec<ParsedEvent>>> =
        (0..P_DEDUP).map(|_| Vec::with_capacity(n_workers)).collect();
    for mut worker_vecs in ev_worker_shards {
        for (d_shard, v) in worker_vecs.drain(..).enumerate() {
            if !v.is_empty() {
                dedup_inputs[d_shard].push(v);
            }
        }
    }

    let mut person_click_batches: Vec<Vec<Vec<C>>> = (0..P_PERSON)
        .map(|_| Vec::with_capacity(n_workers))
        .collect();
    let mut person_click_counts = vec![0usize; P_PERSON];
    for mut worker_vecs in cl_worker_shards {
        for (ps, v) in worker_vecs.drain(..).enumerate() {
            if !v.is_empty() {
                person_click_counts[ps] += v.len();
                person_click_batches[ps].push(v);
            }
        }
    }

    Ok(ParsedPoolOutput {
        dedup_inputs,
        ev_worker_arenas,
        ev_worker_ext,
        person_click_batches,
        person_click_counts,
        cl_worker_arenas,
    })
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
    fn sort_grouped(slice: &mut [u64]) {
        if slice.len() > 1 {
            slice.sort_unstable();
        }
    }

    #[inline(always)]
    fn unpack(g: u64, ws_day: i32, ws_rem: u64) -> (i64, i32, u32, u32) {
        let ts_rel = (g >> 32) as u64;
        let price_cat = g as u32;
        let price = price_cat & 0x00FF_FFFF;
        let cat_id = price_cat >> 24;
        let day = ws_day + ((ws_rem + ts_rel) / (MS_DAY as u64)) as i32;
        ((ts_rel as i64) + MS_CLICK_REACH, day, price, cat_id)
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
    fn sort_grouped(slice: &mut [CompactEventWide]) {
        if slice.len() > 1 {
            slice.sort_unstable_by_key(|e| e.ts_ms);
        }
    }

    #[inline(always)]
    fn unpack(g: CompactEventWide, _ws_day: i32, _ws_rem: u64) -> (i64, i32, u32, u32) {
        let day = g.ts_ms.div_euclid(MS_DAY) as i32;
        (g.ts_ms, day, g.price_cents, g.cat_id)
    }

    #[inline(always)]
    fn gap_exceeds(cur_cmp: i64, prev_cmp: i64) -> bool {
        (cur_cmp as i128 - prev_cmp as i128) > MS_SESSION_GAP as i128
    }
}

impl Stage5Click for PersonClick16 {
    type Grouped = CompactClick16;

    #[inline(always)]
    fn person_key(&self) -> CompactKey64 {
        self.person_key
    }

    #[inline(always)]
    fn to_grouped(&self) -> CompactClick16 {
        CompactClick16 {
            ts_rel_ms: self.ts_rel_ms,
            camp_id: self.camp_id,
            click_id_key: self.click_id_key,
        }
    }

    #[inline(always)]
    fn sort_grouped(slice: &mut [CompactClick16]) {
        if slice.len() > 1 {
            slice.sort_unstable_by_key(|c| c.ts_rel_ms);
        }
    }

    #[inline(always)]
    fn unpack_full(g: &CompactClick16) -> (i64, u32, CompactKey64) {
        (g.ts_rel_ms as i64, g.camp_id, g.click_id_key)
    }
}

impl Stage5Click for PersonClickWide {
    type Grouped = CompactClickWide;

    #[inline(always)]
    fn person_key(&self) -> CompactKey64 {
        self.person_key
    }

    #[inline(always)]
    fn to_grouped(&self) -> CompactClickWide {
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
}

fn run_stage5<E: Stage5Event, C: Stage5Click>(
    person_event_batches: Vec<Vec<Vec<E>>>,
    person_click_batches: Vec<Vec<Vec<C>>>,
    person_event_counts: &[usize],
    person_click_counts: &[usize],
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
) -> io::Result<(Vec<CampDailyAcc>, usize)> {
    let mut shard_order: Vec<usize> = (0..P_PERSON).collect();
    shard_order.sort_unstable_by(|&a, &b| {
        let wa = person_event_counts[a] + person_click_counts[a];
        let wb = person_event_counts[b] + person_click_counts[b];
        wb.cmp(&wa)
    });

    let mut shard_data: Vec<(Vec<Vec<E>>, Vec<Vec<C>>, usize, usize)> = person_event_batches
        .into_iter()
        .zip(person_click_batches.into_iter())
        .zip(
            person_event_counts
                .iter()
                .copied()
                .zip(person_click_counts.iter().copied()),
        )
        .map(|((eb, cb), (ec, cc))| (eb, cb, ec, cc))
        .collect();
    let shard_slots: Vec<Mutex<Option<(Vec<Vec<E>>, Vec<Vec<C>>, usize, usize)>>> =
        shard_data.drain(..).map(|item| Mutex::new(Some(item))).collect();

    let n_out_workers = ncpu.max(1).min(P_PERSON);
    let next_order = AtomicUsize::new(0);
    let num_camps = lookups.camp_entries.len();
    let num_cats = lookups.categories.len();
    let organic_camp = lookups.organic_camp_id;

    let mut worker_accs: Vec<CampDailyAcc> = (0..n_out_workers)
        .map(|_| CampDailyAcc::new(num_camps, min_day, max_day))
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
                let mut writer = match UserDailyWriter::create(
                    &ud_path,
                    USER_DAILY_BATCH_ROWS,
                    &lookups.categories,
                    Compression::UNCOMPRESSED,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        *err_lock_ref.lock().unwrap() = Some(e);
                        return;
                    }
                };

                // Hoisted per-worker reusable buffers (zero per-shard malloc/free).
                let mut p_slots: Vec<PersonSlot> = Vec::new();
                let mut persons: Vec<CompactKey64> = Vec::new();
                let mut long_p_table: HashTable<u32> = HashTable::new();
                let mut ev_pids: Vec<u32> = Vec::new();
                let mut ev_offsets: Vec<u32> = Vec::new();
                let mut ev_fill: Vec<u32> = Vec::new();
                let mut grouped_events: Vec<E::Grouped> = Vec::new();
                let mut cl_counts: Vec<u32> = Vec::new();
                let mut cl_pids: Vec<u32> = Vec::new();
                let mut cl_offsets: Vec<u32> = Vec::new();
                let mut cl_fill: Vec<u32> = Vec::new();
                let mut grouped_clicks: Vec<C::Grouped> = Vec::new();

                let mut cat_rev = vec![0i64; num_cats];
                let mut touched_cats: Vec<u32> = Vec::with_capacity(32);
                let mut active_count = vec![0u32; num_camps];
                let mut active_pos = vec![0u32; num_camps];
                let mut active_list: Vec<u32> = Vec::with_capacity(64);
                let mut sessions: Vec<SessionInfo> = Vec::with_capacity(256);
                let mut day_ranges: Vec<DayRange> = Vec::with_capacity(32);
                let mut camp_clicks: Vec<(u32, i64)> = Vec::with_capacity(256);
                let mut pbuf = [0u8; 10];

                loop {
                    let ord_idx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(&shard_idx) = order_ref.get(ord_idx) else {
                        break;
                    };
                    let Some((evs_batches, cls_batches, ev_total, cl_total)) =
                        slots_ref[shard_idx].lock().unwrap().take()
                    else {
                        break;
                    };
                    if ev_total == 0 {
                        continue;
                    }

                    // 1. Intern unique person_keys in flat L2-resident table (lazy long_p_table for Tag 11).
                    let mut p_cap = (ev_total / 12).max(256).next_power_of_two();
                    let mut p_mask = p_cap - 1;
                    let mut p_thresh = p_cap * 6 / 10;
                    p_slots.clear();
                    p_slots.resize(p_cap, PersonSlot::EMPTY);
                    persons.clear();
                    long_p_table.clear();
                    let mut has_long_p = false;
                    ev_pids.clear();
                    ev_pids.reserve(ev_total);

                    for batch in &evs_batches {
                        for ev in batch {
                            let pk = ev.person_key();
                            let pid = if !pk.is_ref() {
                                if persons.len() >= p_thresh {
                                    p_cap *= 2;
                                    p_mask = p_cap - 1;
                                    p_thresh = p_cap * 6 / 10;
                                    p_slots.clear();
                                    p_slots.resize(p_cap, PersonSlot::EMPTY);
                                    for (existing_pid, &existing_key) in persons.iter().enumerate() {
                                        if !existing_key.is_ref() {
                                            let mut pos = (mix64(existing_key.0) as usize) & p_mask;
                                            while p_slots[pos].key != 0 {
                                                pos = (pos + 1) & p_mask;
                                            }
                                            p_slots[pos] = PersonSlot {
                                                key: existing_key.0,
                                                pid: existing_pid as u32,
                                            };
                                        }
                                    }
                                }
                                let mut pos = (mix64(pk.0) as usize) & p_mask;
                                loop {
                                    let s = p_slots[pos];
                                    if s.key == pk.0 {
                                        break s.pid;
                                    }
                                    if s.key == 0 {
                                        let id = persons.len() as u32;
                                        persons.push(pk);
                                        p_slots[pos] = PersonSlot { key: pk.0, pid: id };
                                        break id;
                                    }
                                    pos = (pos + 1) & p_mask;
                                }
                            } else {
                                has_long_p = true;
                                let pb = LongArena::resolve_in(ev_arenas, pk);
                                let ph = hash_bytes_fast(pb);
                                match long_p_table.entry(
                                    ph,
                                    |&id| LongArena::resolve_in(ev_arenas, persons[id as usize]) == pb,
                                    |&id| hash_bytes_fast(LongArena::resolve_in(ev_arenas, persons[id as usize])),
                                ) {
                                    hashbrown::hash_table::Entry::Occupied(occ) => *occ.get(),
                                    hashbrown::hash_table::Entry::Vacant(vac) => {
                                        let id = persons.len() as u32;
                                        persons.push(pk);
                                        vac.insert(id);
                                        id
                                    }
                                }
                            };
                            ev_pids.push(pid);
                        }
                    }

                    let num_p = persons.len();
                    ev_offsets.clear();
                    ev_offsets.resize(num_p + 1, 0);
                    for &pid in &ev_pids {
                        ev_offsets[pid as usize + 1] += 1;
                    }
                    for i in 1..=num_p {
                        ev_offsets[i] += ev_offsets[i - 1];
                    }
                    ev_fill.clear();
                    ev_fill.extend_from_slice(&ev_offsets[..num_p]);
                    grouped_events.clear();
                    if grouped_events.capacity() < ev_total {
                        grouped_events.reserve(ev_total - grouped_events.capacity());
                    }
                    // Resize with first element template (safe, Copy)
                    let ev_zero = evs_batches[0][0].to_grouped();
                    grouped_events.resize(ev_total, ev_zero);

                    let mut pid_idx = 0usize;
                    for batch in evs_batches {
                        for ev in batch {
                            let pid = ev_pids[pid_idx] as usize;
                            pid_idx += 1;
                            let pos = ev_fill[pid] as usize;
                            ev_fill[pid] += 1;
                            grouped_events[pos] = ev.to_grouped();
                        }
                    }

                    // 2. Group matching clicks into CSR by pid (skip clicks for event-less persons).
                    cl_counts.clear();
                    cl_counts.resize(num_p, 0);
                    cl_pids.clear();
                    cl_pids.reserve(cl_total);
                    for batch in &cls_batches {
                        for c in batch {
                            let ck = c.person_key();
                            let pid = if !ck.is_ref() {
                                let mut pos = (mix64(ck.0) as usize) & p_mask;
                                loop {
                                    let s = p_slots[pos];
                                    if s.key == ck.0 {
                                        break s.pid;
                                    }
                                    if s.key == 0 {
                                        break u32::MAX;
                                    }
                                    pos = (pos + 1) & p_mask;
                                }
                            } else if has_long_p {
                                let cb = LongArena::resolve_in(cl_arenas, ck);
                                let ch = hash_bytes_fast(cb);
                                long_p_table
                                    .find(ch, |&id| {
                                        LongArena::resolve_in(ev_arenas, persons[id as usize]) == cb
                                    })
                                    .copied()
                                    .unwrap_or(u32::MAX)
                            } else {
                                u32::MAX
                            };
                            if pid != u32::MAX {
                                cl_counts[pid as usize] += 1;
                            }
                            cl_pids.push(pid);
                        }
                    }

                    cl_offsets.clear();
                    cl_offsets.resize(num_p + 1, 0);
                    for i in 0..num_p {
                        cl_offsets[i + 1] = cl_offsets[i] + cl_counts[i];
                    }
                    let total_matched_cl = cl_offsets[num_p] as usize;
                    if total_matched_cl > 0 {
                        cl_fill.clear();
                        cl_fill.extend_from_slice(&cl_offsets[..num_p]);
                        let mut first_cl_tmpl = None;
                        for b in &cls_batches {
                            if let Some(first) = b.first() {
                                first_cl_tmpl = Some(first.to_grouped());
                                break;
                            }
                        }
                        grouped_clicks.clear();
                        grouped_clicks.resize(total_matched_cl, first_cl_tmpl.unwrap());
                        let mut cpid_idx = 0usize;
                        for batch in cls_batches {
                            for c in batch {
                                let pid = cl_pids[cpid_idx];
                                cpid_idx += 1;
                                if pid != u32::MAX {
                                    let pos = cl_fill[pid as usize] as usize;
                                    cl_fill[pid as usize] += 1;
                                    grouped_clicks[pos] = c.to_grouped();
                                }
                            }
                        }
                    }

                    // 3. Process each person independently.
                    for pid in 0..num_p {
                        let e_lo = ev_offsets[pid] as usize;
                        let e_hi = ev_offsets[pid + 1] as usize;
                        let evs = &mut grouped_events[e_lo..e_hi];
                        E::sort_grouped(evs);

                        let person_bytes =
                            resolve_person_bytes(persons[pid], link_map, ev_arenas, &mut pbuf);

                        sessions.clear();
                        let (mut sess_start, mut sess_day, price0, cat0) =
                            E::unpack(evs[0], ws_day, ws_rem);
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
                            let (e_ts, e_day, e_price, e_cat) =
                                E::unpack(ev_item, ws_day, ws_rem);
                            if E::gap_exceeds(e_ts, prev_ts) {
                                sessions.push(SessionInfo {
                                    start_cmp: sess_start,
                                    day: sess_day,
                                    has_purchase: sess_has_purch,
                                    revenue_cents: sess_rev,
                                });
                                sess_start = e_ts;
                                sess_day = e_day;
                                sess_has_purch = 0;
                                sess_rev = 0;

                                if sess_day != cur_day {
                                    let top_cat =
                                        pick_and_reset_top_cat_id(&mut cat_rev, &mut touched_cats);
                                    if let Err(err) = writer.push(
                                        person_bytes,
                                        cur_day,
                                        day_sessions,
                                        day_events,
                                        day_rev,
                                        top_cat,
                                    ) {
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
                        if let Err(err) = writer.push(
                            person_bytes,
                            cur_day,
                            day_sessions,
                            day_events,
                            day_rev,
                            top_cat,
                        ) {
                            *err_lock_ref.lock().unwrap() = Some(err);
                            return;
                        }

                        // Credit + Assists
                        let c_lo = cl_offsets[pid] as usize;
                        let c_hi = cl_offsets[pid + 1] as usize;
                        if c_lo == c_hi {
                            for s in &sessions {
                                acc.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                            }
                            continue;
                        }

                        let clks = &mut grouped_clicks[c_lo..c_hi];
                        C::sort_grouped(clks);

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
                            let camp = if has_click
                                && (s.start_cmp as i128 - best_ts as i128) <= MS_CLICK_REACH as i128
                            {
                                best_camp
                            } else {
                                organic_camp
                            };
                            acc.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
                        }

                        // Assisting campaigns
                        if sessions.len() <= 32 && clks.len() <= 64 {
                            let mut left = 0usize;
                            let mut right = 0usize;
                            for s in &sessions {
                                while right < clks.len() {
                                    let (cts, ccamp, _) = C::unpack_full(&clks[right]);
                                    if cts > s.start_cmp {
                                        break;
                                    }
                                    let cid = ccamp as usize;
                                    let cnt = active_count[cid];
                                    active_count[cid] = cnt + 1;
                                    if cnt == 0 {
                                        active_pos[cid] = active_list.len() as u32;
                                        active_list.push(ccamp);
                                    }
                                    right += 1;
                                }
                                while left < right {
                                    let (cts, ccamp, _) = C::unpack_full(&clks[left]);
                                    if (s.start_cmp as i128 - cts as i128)
                                        <= MS_CLICK_REACH as i128
                                    {
                                        break;
                                    }
                                    let cid = ccamp as usize;
                                    let cnt = active_count[cid] - 1;
                                    active_count[cid] = cnt;
                                    if cnt == 0 {
                                        let pos = active_pos[cid] as usize;
                                        let last = *active_list.last().unwrap();
                                        active_list[pos] = last;
                                        active_pos[last as usize] = pos as u32;
                                        active_list.pop();
                                    }
                                    left += 1;
                                }
                                for &camp in &active_list {
                                    acc.add_assist(camp, s.day, 1);
                                }
                            }
                            for &camp in &active_list {
                                active_count[camp as usize] = 0;
                            }
                            active_list.clear();
                        } else {
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
                }

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

pub fn run_pipeline(data_dir: &Path, out_dir: &Path, ncpu: usize, profile: bool) -> io::Result<()> {
    let t0 = Instant::now();

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
    let link_paths = list_csv_files(&data_dir.join("links"))?;
    let (lookups_res, links_res) =
        rayon::join(|| load_lookups(data_dir), || build_link_map(&link_paths, ncpu));
    let lookups = lookups_res?;
    let mut link_map = links_res?;
    let t_links = Instant::now();
    let t_lookups = t_startup;

    let window_span_ms = window_end_ms.saturating_sub(window_start_ms);
    let click_span_ms = window_end_ms.saturating_sub(click_window_start_ms);
    let compact_mode = window_span_ms >= 0
        && window_span_ms <= ((1i64 << 31) - 1)
        && click_span_ms >= 0
        && click_span_ms <= (u32::MAX as i64)
        && lookups.categories.len() <= 256;

    // Unified Stage 3a + Stage 4: parse events & clicks in one work-stealing pool
    let event_paths = list_csv_files(&data_dir.join("events"))?;
    let click_paths = list_csv_files(&data_dir.join("clicks"))?;
    let event_src = CsvSource::open(&event_paths)?;
    let click_src = CsvSource::open(&click_paths)?;
    let ev_chunks = event_src.chunks(CHUNK_BYTES);
    let cl_chunks = click_src.chunks(CHUNK_BYTES);
    let total_chunks = ev_chunks.len() + cl_chunks.len();
    let n_ev_workers = ncpu.clamp(1, 63).min(total_chunks.max(1));
    let est_ev_total = event_src.total_bytes() / 68;
    let ev_active_workers = n_ev_workers.min(ev_chunks.len().max(1));
    let raw_ev_cap = est_ev_total / (ev_active_workers * P_DEDUP);
    let est_ev_cap = if raw_ev_cap >= 64 { raw_ev_cap + 16 } else { 0 };
    let cl_active_workers = n_ev_workers.min(cl_chunks.len().max(1));
    let raw_cl_cap = (click_src.total_bytes() / 42) / (cl_active_workers * P_PERSON);
    let est_cl_cap = if raw_cl_cap >= 64 { raw_cl_cap + 16 } else { 0 };

    let (
        dedup_inputs,
        ev_worker_arenas,
        ev_worker_ext,
        person_click_batches_16,
        person_click_batches_wide,
        person_click_counts,
        cl_worker_arenas,
    ) = if compact_mode {
        let out = run_parse_events_and_clicks::<PersonClick16>(
            &event_src,
            &ev_chunks,
            est_ev_cap,
            &click_src,
            &cl_chunks,
            est_cl_cap,
            &lookups,
            &link_map,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            click_window_start_ms,
            compact_mode,
            n_ev_workers,
        )?;
        (
            out.dedup_inputs,
            out.ev_worker_arenas,
            out.ev_worker_ext,
            out.person_click_batches,
            Vec::new(),
            out.person_click_counts,
            out.cl_worker_arenas,
        )
    } else {
        let out = run_parse_events_and_clicks::<PersonClickWide>(
            &event_src,
            &ev_chunks,
            est_ev_cap,
            &click_src,
            &cl_chunks,
            est_cl_cap,
            &lookups,
            &link_map,
            window_start_ms,
            window_end_ms,
            window_start_sec,
            click_window_start_ms,
            compact_mode,
            n_ev_workers,
        )?;
        (
            out.dedup_inputs,
            out.ev_worker_arenas,
            out.ev_worker_ext,
            Vec::new(),
            out.person_click_batches,
            out.person_click_counts,
            out.cl_worker_arenas,
        )
    };
    drop(event_src);
    drop(click_src);
    link_map.drop_lookup_tables();
    let t_events_parse = Instant::now();

    let dedup_slots: Vec<Mutex<Option<Vec<Vec<ParsedEvent>>>>> =
        dedup_inputs.into_iter().map(|v| Mutex::new(Some(v))).collect();

    // Stage 3b: L2-resident prefetched in-place dedup -> persistent worker P_PERSON scatter.
    let n_dedup_workers = ncpu.clamp(1, 63).min(P_DEDUP);
    let raw_p_cap = est_ev_total / (n_dedup_workers * P_PERSON);
    let est_p_cap = if raw_p_cap >= 64 { raw_p_cap + 16 } else { 0 };
    let next_d_shard = AtomicUsize::new(0);

    let mut person_event_batches_16: Vec<Vec<Vec<PersonEvent16>>> = Vec::new();
    let mut person_event_batches_wide: Vec<Vec<Vec<PersonEventWide>>> = Vec::new();
    let mut person_event_counts = vec![0usize; P_PERSON];

    if compact_mode {
        let mut dedup_worker_outs: Vec<Vec<Vec<PersonEvent16>>> = (0..n_dedup_workers)
            .map(|_| (0..P_PERSON).map(|_| Vec::with_capacity(est_p_cap)).collect())
            .collect();
        std::thread::scope(|scope| {
            for person_out in &mut dedup_worker_outs {
                let slots_ref = &dedup_slots;
                let next_ref = &next_d_shard;
                let ext_ref = &ev_worker_ext;
                let arenas_ref = &ev_worker_arenas;
                scope.spawn(move || {
                    let mut dedup_keys: Vec<u64> = Vec::new();
                    let mut dedup_idxs: Vec<u32> = Vec::new();
                    let mut long_table: Option<HashTable<u32>> = None;

                    loop {
                        let ds = next_ref.fetch_add(1, Ordering::Relaxed);
                        if ds >= P_DEDUP {
                            break;
                        }
                        let Some(mut shard_vecs) = slots_ref[ds].lock().unwrap().take() else {
                            continue;
                        };
                        let total: usize = shard_vecs.iter().map(Vec::len).sum();
                        if total == 0 {
                            continue;
                        }
                        let cap = (total * 10 / 6).max(16).next_power_of_two();
                        let mask = cap - 1;
                        dedup_keys.clear();
                        dedup_keys.resize(cap, 0u64);
                        dedup_idxs.resize(cap, 0u32);
                        if let Some(lt) = &mut long_table {
                            lt.clear();
                        }

                        for widx in 0..shard_vecs.len() {
                            let batch_len = shard_vecs[widx].len();
                            let wbase = (widx as u32) << 26;
                            for ridx in 0..batch_len {
                                #[cfg(target_arch = "x86_64")]
                                if ridx + 16 < batch_len {
                                    let k_ahead = unsafe { shard_vecs[widx].get_unchecked(ridx + 16).ev_key };
                                    let nslot = (mix64(k_ahead.0) as usize) & mask;
                                    unsafe {
                                        std::arch::x86_64::_mm_prefetch(
                                            dedup_keys.as_ptr().add(nslot) as *const i8,
                                            std::arch::x86_64::_MM_HINT_T0,
                                        );
                                    }
                                }
                                let ev = shard_vecs[widx][ridx];
                                if !ev.ev_key.is_ref() {
                                    let mut slot = (mix64(ev.ev_key.0) as usize) & mask;
                                    loop {
                                        let cur = dedup_keys[slot];
                                        if cur == ev.ev_key.0 {
                                            let packed = dedup_idxs[slot];
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            let ev_ing = ev_ingest_ts(&ev, window_start_sec, ext_ref);
                                            let cur_ing = ev_ingest_ts(
                                                &shard_vecs[pw][pr],
                                                window_start_sec,
                                                ext_ref,
                                            );
                                            if ev_ing < cur_ing {
                                                shard_vecs[pw][pr] = ev;
                                            }
                                            shard_vecs[widx][ridx].meta = META_DEAD;
                                            break;
                                        }
                                        if cur == 0 {
                                            dedup_keys[slot] = ev.ev_key.0;
                                            dedup_idxs[slot] = wbase | (ridx as u32);
                                            break;
                                        }
                                        slot = (slot + 1) & mask;
                                    }
                                } else {
                                    let lt = long_table.get_or_insert_with(HashTable::new);
                                    let ev_bytes = LongArena::resolve_in(arenas_ref, ev.ev_key);
                                    let eh = hash_bytes_fast(ev_bytes);
                                    match lt.entry(
                                        eh,
                                        |&packed| {
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            LongArena::resolve_in(arenas_ref, shard_vecs[pw][pr].ev_key)
                                                == ev_bytes
                                        },
                                        |&packed| {
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            hash_bytes_fast(LongArena::resolve_in(
                                                arenas_ref,
                                                shard_vecs[pw][pr].ev_key,
                                            ))
                                        },
                                    ) {
                                        hashbrown::hash_table::Entry::Occupied(occ) => {
                                            let packed = *occ.get();
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            let ev_ing = ev_ingest_ts(&ev, window_start_sec, ext_ref);
                                            let cur_ing = ev_ingest_ts(
                                                &shard_vecs[pw][pr],
                                                window_start_sec,
                                                ext_ref,
                                            );
                                            if ev_ing < cur_ing {
                                                shard_vecs[pw][pr] = ev;
                                            }
                                            shard_vecs[widx][ridx].meta = META_DEAD;
                                        }
                                        hashbrown::hash_table::Entry::Vacant(vac) => {
                                            vac.insert(wbase | (ridx as u32));
                                        }
                                    }
                                }
                            }
                        }

                        for batch in shard_vecs {
                            for ev in batch {
                                let tag = ev.meta & (3u64 << META_TAG_SHIFT);
                                if tag < META_INVALID {
                                    let ph = hash_raw_key(ev.person_key, arenas_ref);
                                    let pshard = ((ph >> 52) as usize) & (P_PERSON - 1);
                                    let (ts_rel_ms, price_cat) =
                                        ev_payload_compact(&ev, window_start_ms, ext_ref);
                                    person_out[pshard].push(PersonEvent16 {
                                        person_key: ev.person_key,
                                        ts_rel_ms,
                                        price_cat,
                                    });
                                }
                            }
                        }
                    }
                });
            }
        });
        person_event_batches_16 = (0..P_PERSON)
            .map(|_| Vec::with_capacity(n_dedup_workers))
            .collect();
        for mut wouts in dedup_worker_outs {
            for (ps, v) in wouts.drain(..).enumerate() {
                if !v.is_empty() {
                    person_event_counts[ps] += v.len();
                    person_event_batches_16[ps].push(v);
                }
            }
        }
    } else {
        let mut dedup_worker_outs: Vec<Vec<Vec<PersonEventWide>>> = (0..n_dedup_workers)
            .map(|_| (0..P_PERSON).map(|_| Vec::with_capacity(est_p_cap)).collect())
            .collect();
        std::thread::scope(|scope| {
            for person_out in &mut dedup_worker_outs {
                let slots_ref = &dedup_slots;
                let next_ref = &next_d_shard;
                let ext_ref = &ev_worker_ext;
                let arenas_ref = &ev_worker_arenas;
                scope.spawn(move || {
                    let mut dedup_keys: Vec<u64> = Vec::new();
                    let mut dedup_idxs: Vec<u32> = Vec::new();
                    let mut long_table: Option<HashTable<u32>> = None;

                    loop {
                        let ds = next_ref.fetch_add(1, Ordering::Relaxed);
                        if ds >= P_DEDUP {
                            break;
                        }
                        let Some(mut shard_vecs) = slots_ref[ds].lock().unwrap().take() else {
                            continue;
                        };
                        let total: usize = shard_vecs.iter().map(Vec::len).sum();
                        if total == 0 {
                            continue;
                        }
                        let cap = (total * 10 / 6).max(16).next_power_of_two();
                        let mask = cap - 1;
                        dedup_keys.clear();
                        dedup_keys.resize(cap, 0u64);
                        dedup_idxs.resize(cap, 0u32);
                        if let Some(lt) = &mut long_table {
                            lt.clear();
                        }

                        for widx in 0..shard_vecs.len() {
                            let batch_len = shard_vecs[widx].len();
                            let wbase = (widx as u32) << 26;
                            for ridx in 0..batch_len {
                                let ev = shard_vecs[widx][ridx];
                                if !ev.ev_key.is_ref() {
                                    let mut slot = (mix64(ev.ev_key.0) as usize) & mask;
                                    loop {
                                        let cur = dedup_keys[slot];
                                        if cur == ev.ev_key.0 {
                                            let packed = dedup_idxs[slot];
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            let ev_ing = ev_ingest_ts(&ev, window_start_sec, ext_ref);
                                            let cur_ing = ev_ingest_ts(
                                                &shard_vecs[pw][pr],
                                                window_start_sec,
                                                ext_ref,
                                            );
                                            if ev_ing < cur_ing {
                                                shard_vecs[pw][pr] = ev;
                                            }
                                            shard_vecs[widx][ridx].meta = META_DEAD;
                                            break;
                                        }
                                        if cur == 0 {
                                            dedup_keys[slot] = ev.ev_key.0;
                                            dedup_idxs[slot] = wbase | (ridx as u32);
                                            break;
                                        }
                                        slot = (slot + 1) & mask;
                                    }
                                } else {
                                    let lt = long_table.get_or_insert_with(HashTable::new);
                                    let ev_bytes = LongArena::resolve_in(arenas_ref, ev.ev_key);
                                    let eh = hash_bytes_fast(ev_bytes);
                                    match lt.entry(
                                        eh,
                                        |&packed| {
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            LongArena::resolve_in(arenas_ref, shard_vecs[pw][pr].ev_key)
                                                == ev_bytes
                                        },
                                        |&packed| {
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            hash_bytes_fast(LongArena::resolve_in(
                                                arenas_ref,
                                                shard_vecs[pw][pr].ev_key,
                                            ))
                                        },
                                    ) {
                                        hashbrown::hash_table::Entry::Occupied(occ) => {
                                            let packed = *occ.get();
                                            let pw = (packed >> 26) as usize;
                                            let pr = (packed & ((1 << 26) - 1)) as usize;
                                            let ev_ing = ev_ingest_ts(&ev, window_start_sec, ext_ref);
                                            let cur_ing = ev_ingest_ts(
                                                &shard_vecs[pw][pr],
                                                window_start_sec,
                                                ext_ref,
                                            );
                                            if ev_ing < cur_ing {
                                                shard_vecs[pw][pr] = ev;
                                            }
                                            shard_vecs[widx][ridx].meta = META_DEAD;
                                        }
                                        hashbrown::hash_table::Entry::Vacant(vac) => {
                                            vac.insert(wbase | (ridx as u32));
                                        }
                                    }
                                }
                            }
                        }

                        for batch in shard_vecs {
                            for ev in batch {
                                let tag = ev.meta & (3u64 << META_TAG_SHIFT);
                                if tag < META_INVALID {
                                    let ph = hash_raw_key(ev.person_key, arenas_ref);
                                    let pshard = ((ph >> 52) as usize) & (P_PERSON - 1);
                                    let (ts_ms, price_cents, cat_id) =
                                        ev_payload_wide(&ev, ext_ref);
                                    person_out[pshard].push(PersonEventWide {
                                        person_key: ev.person_key,
                                        ts_ms,
                                        price_cents,
                                        cat_id,
                                    });
                                }
                            }
                        }
                    }
                });
            }
        });
        person_event_batches_wide = (0..P_PERSON)
            .map(|_| Vec::with_capacity(n_dedup_workers))
            .collect();
        for mut wouts in dedup_worker_outs {
            for (ps, v) in wouts.drain(..).enumerate() {
                if !v.is_empty() {
                    person_event_counts[ps] += v.len();
                    person_event_batches_wide[ps].push(v);
                }
            }
        }
    }
    drop(dedup_slots);
    drop(ev_worker_ext);
    let t_events_dedup = Instant::now();
    let t_clicks = t_events_dedup;

    let ud_dir = out_dir.join("user_daily");
    let cd_dir = out_dir.join("campaign_daily");
    clean_parquet_dir(&ud_dir)?;
    clean_parquet_dir(&cd_dir)?;

    let (worker_accs, total_ud_rows) = if compact_mode {
        run_stage5(
            person_event_batches_16,
            person_click_batches_16,
            &person_event_counts,
            &person_click_counts,
            &ev_worker_arenas,
            &cl_worker_arenas,
            &link_map,
            &lookups,
            &ud_dir,
            ncpu,
            min_day,
            max_day,
            ws_day,
            ws_rem,
        )?
    } else {
        run_stage5(
            person_event_batches_wide,
            person_click_batches_wide,
            &person_event_counts,
            &person_click_counts,
            &ev_worker_arenas,
            &cl_worker_arenas,
            &link_map,
            &lookups,
            &ud_dir,
            ncpu,
            min_day,
            max_day,
            ws_day,
            ws_rem,
        )?
    };

    if total_ud_rows == 0 {
        let empty_ud = UserDailyWriter::create(
            &ud_dir.join("part-0.parquet"),
            1,
            &lookups.categories,
            Compression::UNCOMPRESSED,
        )?;
        empty_ud.close()?;
    }
    let t_stage5 = Instant::now();

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
            cells,
        } => {
            for c in 0..*num_camps {
                let c_name = lookups.camp_name(c);
                let ch_name = lookups.camp_channel(c);
                let base = c * (*num_days);
                for d_off in 0..*num_days {
                    let agg = &cells[base + d_off];
                    if agg.sessions > 0 || agg.assisted_sessions > 0 {
                        cd_rows.push(CampaignRow {
                            campaign_id: c_name,
                            channel: ch_name,
                            day: *start_day + d_off as i32,
                            sessions: agg.sessions,
                            purchasing_sessions: agg.purchasing_sessions,
                            revenue_cents: agg.revenue_cents,
                            assisted_sessions: agg.assisted_sessions,
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
    write_campaign_daily(&cd_dir.join("part-0.parquet"), &cd_rows, Compression::UNCOMPRESSED)?;
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
        let base_day = 20_000i32;
        let base_ms = (base_day as i64) * MS_DAY;

        for _case in 0..200 {
            let n_sess = ((next_u64() % 45) + 1) as usize;
            let mut starts = Vec::with_capacity(n_sess);
            let mut t = base_ms;
            for _ in 0..n_sess {
                t += MS_SESSION_GAP + 1 + ((next_u64() % (6 * 3_600_000)) as i64);
                starts.push(t);
            }
            let sessions: Vec<SessionInfo> = starts
                .iter()
                .map(|&st| SessionInfo {
                    start_cmp: st,
                    day: st.div_euclid(MS_DAY) as i32,
                    has_purchase: 0,
                    revenue_cents: 0,
                })
                .collect();

            let n_clks = (next_u64() % 70) as usize;
            let mut clks = Vec::with_capacity(n_clks);
            for _ in 0..n_clks {
                let camp_id = (next_u64() % (num_camps as u64)) as u32;
                let s_pick = starts[(next_u64() as usize) % starts.len()];
                let offset = match next_u64() % 6 {
                    0 => MS_CLICK_REACH,
                    1 => MS_CLICK_REACH + 1,
                    2 => 0,
                    3 => -1,
                    _ => (next_u64() % (10 * MS_DAY as u64)) as i64,
                };
                clks.push((s_pick - offset, camp_id));
            }
            clks.sort_unstable();

            let min_d = sessions.first().unwrap().day;
            let max_d = sessions.last().unwrap().day;
            let mut acc_slide = CampDailyAcc::new(num_camps, min_d, max_d);
            let mut acc_iv = CampDailyAcc::new(num_camps, min_day_helper(min_d), max_d);

            let mut active_count = vec![0u32; num_camps];
            let mut active_pos = vec![0u32; num_camps];
            let mut active_list: Vec<u32> = Vec::new();
            let mut left = 0usize;
            let mut right = 0usize;
            for s in &sessions {
                while right < clks.len() && clks[right].0 <= s.start_cmp {
                    let cid = clks[right].1 as usize;
                    let cnt = active_count[cid];
                    active_count[cid] = cnt + 1;
                    if cnt == 0 {
                        active_pos[cid] = active_list.len() as u32;
                        active_list.push(clks[right].1);
                    }
                    right += 1;
                }
                while left < right
                    && (s.start_cmp as i128 - clks[left].0 as i128) > MS_CLICK_REACH as i128
                {
                    let cid = clks[left].1 as usize;
                    let cnt = active_count[cid] - 1;
                    active_count[cid] = cnt;
                    if cnt == 0 {
                        let pos = active_pos[cid] as usize;
                        let last = *active_list.last().unwrap();
                        active_list[pos] = last;
                        active_pos[last as usize] = pos as u32;
                        active_list.pop();
                    }
                    left += 1;
                }
                for &camp in &active_list {
                    acc_slide.add_assist(camp, s.day, 1);
                }
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
            let mut camp_clicks: Vec<(u32, i64)> = clks.iter().map(|&(t, c)| (c, t)).collect();
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
                            &mut acc_iv,
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
                    &mut acc_iv,
                    camp,
                    iv_start,
                    iv_end,
                    &sessions,
                    &day_ranges,
                );
            }

            match (&acc_slide, &acc_iv) {
                (CampDailyAcc::Dense { cells: a, .. }, CampDailyAcc::Dense { cells: b, .. }) => {
                    assert_eq!(a.len(), b.len());
                    for (ca, cb) in a.iter().zip(b.iter()) {
                        assert_eq!(ca.assisted_sessions, cb.assisted_sessions);
                    }
                }
                _ => panic!("expected dense accumulators in test"),
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
