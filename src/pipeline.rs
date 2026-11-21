use std::fs;
use std::hash::BuildHasher;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use hashbrown::{DefaultHashBuilder, HashMap, HashTable};
use parquet::basic::Compression;
use rayon::prelude::*;

use crate::csv::{
    fast_hash_bytes, for_each_line_fields, is_valid_utf8, list_csv_files, parse_csv_line,
    FileSet, InlineKey16, OverflowSpan, SliceRef, CHUNK_BYTES, FILE_IDX_ARENA, FILE_IDX_OVERFLOW,
};
use crate::links::{build_link_map, LinkMap};
use crate::parse::{
    parse_price_cents, parse_ts_ms, DateCache, Manifest, MS_CLICK_REACH, MS_DAY, MS_SESSION_GAP,
};
use crate::parquet_out::{clean_parquet_dir, write_campaign_daily, CampaignRow, UserDailyWriter};

const P_DEDUP: usize = 64;
const P_PERSON: usize = 64;
const DUPLICATE_DEAD: u32 = u32::MAX - 1;
const INVALID_EVENT: u32 = u32::MAX;
const USER_DAILY_BATCH_ROWS: usize = 131_072;

#[derive(Clone, Copy)]
struct ParsedEvent {
    ev_key: InlineKey16,
    ingest_ts_ms: i64,
    ts_ms: i64,
    uid_key: InlineKey16,
    price_or_invalid: u32,
    cat_id: u32,
}

const _: () = assert!(std::mem::size_of::<ParsedEvent>() == 56);

#[derive(Clone, Copy)]
struct PersonEvent {
    person_key: InlineKey16,
    ts_ms: i64,
    price_cents: u32,
    cat_id: u32,
}

const _: () = assert!(std::mem::size_of::<PersonEvent>() == 32);

#[derive(Clone, Copy)]
struct PersonClick {
    person_key: InlineKey16,
    click_id_ref: SliceRef,
    ts_ms: i64,
    camp_id: u32,
    _pad: u32,
}

const _: () = assert!(std::mem::size_of::<PersonClick>() == 40);

#[derive(Clone, Copy)]
struct CompactEvent {
    ts_ms: i64,
    price_cents: u32,
    cat_id: u32,
}

#[derive(Clone, Copy)]
struct CompactClick {
    ts_ms: i64,
    click_id_ref: SliceRef,
    camp_id: u32,
    _pad: u32,
}

#[derive(Clone, Copy)]
struct SessionInfo {
    start_ts: i64,
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
            (
                Self::Dense { cells: dst, .. },
                Self::Dense { cells: src, .. },
            ) => {
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

struct ProdEntry {
    off: usize,
    len: usize,
    cat_id: u32,
    hash: u64,
}

struct CampEntry {
    cid_off: usize,
    cid_len: usize,
    ch_off: usize,
    ch_len: usize,
    camp_id: u32,
    hash: u64,
}

struct Lookups {
    prod_buf: Vec<u8>,
    prod_entries: Vec<ProdEntry>,
    prod_table: HashTable<u32>,
    categories: Vec<Box<[u8]>>,
    unknown_cat_id: u32,
    camp_buf: Vec<u8>,
    camp_entries: Vec<CampEntry>,
    camp_table: HashTable<u32>,
    organic_camp_id: u32,
}

impl Lookups {
    #[inline(always)]
    fn get_product_cat(&self, pid: &[u8], hash_builder: &DefaultHashBuilder) -> u32 {
        let h = hash_builder.hash_one(pid);
        match self.prod_table.find(h, |&idx| {
            let e = &self.prod_entries[idx as usize];
            e.hash == h && &self.prod_buf[e.off..e.off + e.len] == pid
        }) {
            Some(&idx) => self.prod_entries[idx as usize].cat_id,
            None => self.unknown_cat_id,
        }
    }

    #[inline(always)]
    fn get_campaign(&self, cid: &[u8], hash_builder: &DefaultHashBuilder) -> Option<u32> {
        let h = hash_builder.hash_one(cid);
        self.camp_table
            .find(h, |&idx| {
                let e = &self.camp_entries[idx as usize];
                e.hash == h && &self.camp_buf[e.cid_off..e.cid_off + e.cid_len] == cid
            })
            .map(|&idx| self.camp_entries[idx as usize].camp_id)
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
fn scan_buf_skip_header<const K: usize>(buf: &[u8], mut f: impl FnMut([&[u8]; K])) {
    let Some(hdr_end) = memchr::memchr(b'\n', buf) else {
        return;
    };
    for_each_line_fields::<K>(&buf[hdr_end + 1..], |fields| f(fields));
    let _ = parse_csv_line::<K>; // keep import clean if needed
}

fn load_lookups(data_dir: &Path, hash_builder: &DefaultHashBuilder) -> io::Result<Lookups> {
    let prod_path = data_dir.join("products.csv");
    let prod_buf = if prod_path.is_file() {
        fs::read(&prod_path)?
    } else {
        Vec::new()
    };
    let prod_base = prod_buf.as_ptr() as usize;

    let mut raw_cats: Vec<(usize, usize, u64)> = Vec::with_capacity(64);
    let mut cat_table: HashTable<u32> = HashTable::with_capacity(64);
    let mut prod_entries: Vec<ProdEntry> = Vec::with_capacity(prod_buf.len() / 16 + 16);
    let mut prod_table: HashTable<u32> = HashTable::with_capacity(prod_buf.len() / 16 + 16);

    scan_buf_skip_header::<2>(&prod_buf, |[pid, cat]| {
        if pid.is_empty() || cat.is_empty() || !is_valid_utf8(pid) || !is_valid_utf8(cat) {
            return;
        }
        let ch = hash_builder.hash_one(cat);
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

        let ph = hash_builder.hash_one(pid);
        let poff = pid.as_ptr() as usize - prod_base;
        match prod_table.entry(
            ph,
            |&idx| {
                let e = &prod_entries[idx as usize];
                e.hash == ph && &prod_buf[e.off..e.off + e.len] == pid
            },
            |&idx| prod_entries[idx as usize].hash,
        ) {
            hashbrown::hash_table::Entry::Occupied(occ) => {
                prod_entries[*occ.get() as usize].cat_id = tmp_cat;
            }
            hashbrown::hash_table::Entry::Vacant(vac) => {
                let idx = prod_entries.len() as u32;
                prod_entries.push(ProdEntry {
                    off: poff,
                    len: pid.len(),
                    cat_id: tmp_cat,
                    hash: ph,
                });
                vac.insert(idx);
            }
        }
    });

    // Sort unique categories (+ "unknown") byte-wise ascending so tie-breaks compare cat_id integer!
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
    for e in &mut prod_entries {
        e.cat_id = remap[e.cat_id as usize];
    }

    let camp_path = data_dir.join("campaigns.csv");
    let mut camp_buf = if camp_path.is_file() {
        fs::read(&camp_path)?
    } else {
        Vec::new()
    };
    let camp_base = camp_buf.as_ptr() as usize;
    let mut camp_entries: Vec<CampEntry> = Vec::with_capacity(camp_buf.len() / 16 + 16);
    let mut camp_table: HashTable<u32> = HashTable::with_capacity(camp_buf.len() / 16 + 16);

    scan_buf_skip_header::<2>(&camp_buf, |[cid, ch_name]| {
        if cid.is_empty() || ch_name.is_empty() || !is_valid_utf8(cid) || !is_valid_utf8(ch_name) {
            return;
        }
        let h = hash_builder.hash_one(cid);
        let cid_off = cid.as_ptr() as usize - camp_base;
        let ch_off = ch_name.as_ptr() as usize - camp_base;
        let idx = camp_entries.len() as u32;
        camp_entries.push(CampEntry {
            cid_off,
            cid_len: cid.len(),
            ch_off,
            ch_len: ch_name.len(),
            camp_id: idx,
            hash: h,
        });
        camp_table.insert_unique(h, idx, |&i| camp_entries[i as usize].hash);
    });

    let organic_camp_id = camp_entries.len() as u32;
    let org_off = camp_buf.len();
    camp_buf.extend_from_slice(b"organic");
    camp_entries.push(CampEntry {
        cid_off: org_off,
        cid_len: 7,
        ch_off: org_off,
        ch_len: 7,
        camp_id: organic_camp_id,
        hash: 0,
    });

    Ok(Lookups {
        prod_buf,
        prod_entries,
        prod_table,
        categories,
        unknown_cat_id,
        camp_buf,
        camp_entries,
        camp_table,
        organic_camp_id,
    })
}

#[inline(always)]
fn resolve_event_slice<'a>(
    r: SliceRef,
    files: &'a FileSet,
    ev_overflow: &'a [Vec<OverflowSpan>],
    link_map: &'a LinkMap,
) -> &'a [u8] {
    if r.file_idx < FILE_IDX_OVERFLOW {
        files.resolve(r, &link_map.canon_arena, ev_overflow)
    } else if !link_map.is_empty() && (r.off >> 26) == 63 {
        link_map.canon_overflow_slice(r.off & ((1 << 26) - 1))
    } else {
        files.resolve(r, &link_map.canon_arena, ev_overflow)
    }
}

#[inline(always)]
fn resolve_click_slice<'a>(
    r: SliceRef,
    files: &'a FileSet,
    cl_overflow: &'a [Vec<OverflowSpan>],
    link_map: &'a LinkMap,
) -> &'a [u8] {
    if r.file_idx < FILE_IDX_OVERFLOW {
        files.resolve(r, &link_map.canon_arena, cl_overflow)
    } else if !link_map.is_empty() && (r.off >> 26) == 63 {
        link_map.canon_overflow_slice(r.off & ((1 << 26) - 1))
    } else {
        files.resolve(r, &link_map.canon_arena, cl_overflow)
    }
}

#[inline(always)]
fn resolve_inline_event<'a>(
    k: &'a InlineKey16,
    files: &'a FileSet,
    ev_overflow: &'a [Vec<OverflowSpan>],
    link_map: &'a LinkMap,
) -> &'a [u8] {
    if k.is_inline() {
        k.inline_slice()
    } else {
        resolve_event_slice(k.slice_ref(), files, ev_overflow, link_map)
    }
}

#[inline(always)]
fn inline_keys_equal_event(
    a: &InlineKey16,
    b: &InlineKey16,
    files: &FileSet,
    ev_overflow: &[Vec<OverflowSpan>],
    link_map: &LinkMap,
) -> bool {
    if a.is_inline() && b.is_inline() {
        a == b
    } else if a.is_inline() != b.is_inline() {
        false
    } else {
        resolve_event_slice(a.slice_ref(), files, ev_overflow, link_map)
            == resolve_event_slice(b.slice_ref(), files, ev_overflow, link_map)
    }
}

#[inline(always)]
fn inline_keys_equal_cross(
    cl_key: &InlineKey16,
    ev_key: &InlineKey16,
    cl_files: &FileSet,
    cl_ov: &[Vec<OverflowSpan>],
    ev_files: &FileSet,
    ev_ov: &[Vec<OverflowSpan>],
    link_map: &LinkMap,
) -> bool {
    if cl_key.is_inline() && ev_key.is_inline() {
        cl_key == ev_key
    } else if cl_key.is_inline() != ev_key.is_inline() {
        false
    } else {
        resolve_click_slice(cl_key.slice_ref(), cl_files, cl_ov, link_map)
            == resolve_event_slice(ev_key.slice_ref(), ev_files, ev_ov, link_map)
    }
}

#[inline(always)]
fn ev_key_hash(
    k: &InlineKey16,
    files: &FileSet,
    ev_overflow: &[Vec<OverflowSpan>],
    link_map: &LinkMap,
    hb: &DefaultHashBuilder,
) -> u64 {
    if k.is_inline() {
        k.hash_inline()
    } else {
        hb.hash_one(resolve_event_slice(k.slice_ref(), files, ev_overflow, link_map))
    }
}

#[inline(always)]
fn pack_canon_overflow(idx: u32) -> SliceRef {
    SliceRef {
        file_idx: FILE_IDX_OVERFLOW,
        len: 0,
        off: (63u32 << 26) | idx,
    }
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
    let hash_builder = DefaultHashBuilder::default();

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

    let t_startup = Instant::now();
    let link_paths = list_csv_files(&data_dir.join("links"))?;
    let (lookups_res, links_res) = rayon::join(
        || load_lookups(data_dir, &hash_builder),
        || build_link_map(&link_paths, &hash_builder, ncpu),
    );
    let lookups = lookups_res?;
    let link_map = links_res?;
    let t_links = Instant::now();
    let t_lookups = t_startup;

    // Stage 3: Events parse (parallel) -> P_DEDUP-shard dedup before validation -> P_PERSON-shard scatter
    let event_paths = list_csv_files(&data_dir.join("events"))?;
    let event_files = FileSet::open(&event_paths)?;
    let ev_chunks = event_files.chunks(CHUNK_BYTES);
    let n_ev_workers = ncpu.clamp(1, 63).min(ev_chunks.len().max(1));
    let total_ev_bytes: usize = ev_chunks.iter().map(|c| c.end - c.start).sum();
    let est_ev_cap = (total_ev_bytes / 105) / (n_ev_workers * P_DEDUP);
    let mut ev_worker_shards: Vec<Vec<Vec<ParsedEvent>>> = (0..n_ev_workers)
        .map(|_| (0..P_DEDUP).map(|_| Vec::with_capacity(est_ev_cap)).collect())
        .collect();
    let mut ev_worker_overflow: Vec<Vec<OverflowSpan>> =
        (0..n_ev_workers).map(|_| Vec::new()).collect();

    if !ev_chunks.is_empty() {
        let next_chunk = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for (wid, (buckets, ov_out)) in ev_worker_shards
                .iter_mut()
                .zip(ev_worker_overflow.iter_mut())
                .enumerate()
            {
                let files_ref = &event_files;
                let chunks_ref = &ev_chunks;
                let next_ref = &next_chunk;
                let lookups_ref = &lookups;
                let hb_ref = &hash_builder;
                scope.spawn(move || {
                    let mut dcache = DateCache::new();
                    loop {
                        let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                        let Some(chunk) = chunks_ref.get(cidx) else {
                            break;
                        };
                        let slice = &files_ref.file_bytes(chunk.file_idx)[chunk.start..chunk.end];
                        for_each_line_fields::<7>(slice, |[ev_id, uid, ts, ingest_ts, etype, pid, price]| {
                            if ev_id.is_empty() || !is_valid_utf8(ev_id) {
                                return;
                            }
                            let Some(ingest_ms) = dcache.parse_f1_ms(ingest_ts) else {
                                return;
                            };
                            let (ev_key, ev_hash) = if ev_id.len() <= 15 {
                                let k = InlineKey16::from_inline(ev_id);
                                let h = k.hash_inline();
                                (k, h)
                            } else {
                                let r = files_ref.make_ref(chunk.file_idx, ev_id, ov_out, wid);
                                (InlineKey16::from_ref(r), fast_hash_bytes(ev_id, hb_ref))
                            };
                            let d_shard = ((ev_hash >> 28) as usize) & (P_DEDUP - 1);

                            let mut valid = true;
                            let mut ts_ms = 0i64;
                            let mut price_val = 0u32;
                            let mut cat_id = 0u32;
                            let mut uid_key = InlineKey16::zero();

                            if uid.is_empty() || pid.is_empty() || !is_valid_utf8(uid) {
                                valid = false;
                            } else if let Some(t) = dcache.parse_ts_ms(ts) {
                                if t < window_start_ms
                                    || t >= window_end_ms
                                    || (ingest_ms as i128 - t as i128) > MS_DAY as i128
                                {
                                    valid = false;
                                } else {
                                    ts_ms = t;
                                    match etype {
                                        b"view" | b"cart" => {
                                            price_val = 0;
                                            cat_id = 0;
                                        }
                                        b"purchase" => {
                                            if let Some(p) = parse_price_cents(price) {
                                                price_val = p;
                                                cat_id = lookups_ref.get_product_cat(pid, hb_ref);
                                            } else {
                                                valid = false;
                                            }
                                        }
                                        _ => valid = false,
                                    }
                                    if valid {
                                        uid_key = if uid.len() <= 15 {
                                            InlineKey16::from_inline(uid)
                                        } else {
                                            InlineKey16::from_ref(
                                                files_ref.make_ref(chunk.file_idx, uid, ov_out, wid),
                                            )
                                        };
                                    }
                                }
                            } else {
                                valid = false;
                            }

                            buckets[d_shard].push(ParsedEvent {
                                ev_key,
                                ingest_ts_ms: ingest_ms,
                                ts_ms,
                                uid_key,
                                price_or_invalid: if valid { price_val } else { INVALID_EVENT },
                                cat_id,
                            });
                        });
                    }
                });
            }
        });
    }
    let t_events_parse = Instant::now();

    // Transpose [worker][d_shard] -> [d_shard][worker] so each dedup shard owns & drops its inputs!
    let mut dedup_inputs: Vec<Vec<Vec<ParsedEvent>>> = (0..P_DEDUP)
        .map(|_| Vec::with_capacity(n_ev_workers))
        .collect();
    for mut worker_vecs in ev_worker_shards {
        for (d_shard, v) in worker_vecs.drain(..).enumerate() {
            dedup_inputs[d_shard].push(v);
        }
    }

    // Stage 3b: In-place dedup per shard & scatter valid surviving events into P_PERSON shards.
    let dedup_results: Vec<Vec<Vec<PersonEvent>>> = dedup_inputs
        .into_par_iter()
        .map(|mut shard_vecs| {
            let total: usize = shard_vecs.iter().map(Vec::len).sum();
            let p_cap = if total >= P_PERSON * 64 {
                total / P_PERSON
            } else {
                0
            };
            let mut person_out: Vec<Vec<PersonEvent>> =
                (0..P_PERSON).map(|_| Vec::with_capacity(p_cap)).collect();
            if total == 0 {
                return person_out;
            }
            let mut table: HashTable<u32> = HashTable::with_capacity(total);
            for widx in 0..shard_vecs.len() {
                let batch_len = shard_vecs[widx].len();
                let wbase = (widx as u32) << 26;
                for ridx in 0..batch_len {
                    let ev = shard_vecs[widx][ridx];
                    let eh = ev_key_hash(
                        &ev.ev_key,
                        &event_files,
                        &ev_worker_overflow,
                        &link_map,
                        &hash_builder,
                    );
                    match table.entry(
                        eh,
                        |&packed| {
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            inline_keys_equal_event(
                                &shard_vecs[pw][pr].ev_key,
                                &ev.ev_key,
                                &event_files,
                                &ev_worker_overflow,
                                &link_map,
                            )
                        },
                        |&packed| {
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            ev_key_hash(
                                &shard_vecs[pw][pr].ev_key,
                                &event_files,
                                &ev_worker_overflow,
                                &link_map,
                                &hash_builder,
                            )
                        },
                    ) {
                        hashbrown::hash_table::Entry::Occupied(occ) => {
                            let packed = *occ.get();
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            if ev.ingest_ts_ms < shard_vecs[pw][pr].ingest_ts_ms {
                                shard_vecs[pw][pr] = ev;
                            }
                            shard_vecs[widx][ridx].price_or_invalid = DUPLICATE_DEAD;
                        }
                        hashbrown::hash_table::Entry::Vacant(vac) => {
                            vac.insert(wbase | (ridx as u32));
                        }
                    }
                }
            }
            drop(table);

            for batch in shard_vecs {
                for ev in batch {
                    if ev.price_or_invalid < DUPLICATE_DEAD {
                        let (uh, raw_uid) = if ev.uid_key.is_inline() {
                            (ev.uid_key.hash_inline(), ev.uid_key.inline_slice())
                        } else {
                            let rb = resolve_event_slice(
                                ev.uid_key.slice_ref(),
                                &event_files,
                                &ev_worker_overflow,
                                &link_map,
                            );
                            (fast_hash_bytes(rb, &hash_builder), rb)
                        };
                        let (person_key, ph) = if !link_map.is_empty() {
                            if let Some((canon_ref, ch)) = link_map.resolve(raw_uid, uh) {
                                let pkey = if canon_ref.file_idx == FILE_IDX_ARENA
                                    && canon_ref.len <= 15
                                {
                                    let off = canon_ref.off as usize;
                                    InlineKey16::from_inline(
                                        &link_map.canon_arena[off..off + canon_ref.len as usize],
                                    )
                                } else if canon_ref.file_idx == FILE_IDX_OVERFLOW {
                                    InlineKey16::from_ref(pack_canon_overflow(canon_ref.off))
                                } else {
                                    InlineKey16::from_ref(canon_ref)
                                };
                                (pkey, ch)
                            } else {
                                (ev.uid_key, uh)
                            }
                        } else {
                            (ev.uid_key, uh)
                        };
                        let pshard = ((ph >> 28) as usize) & (P_PERSON - 1);
                        person_out[pshard].push(PersonEvent {
                            person_key,
                            ts_ms: ev.ts_ms,
                            price_cents: ev.price_or_invalid,
                            cat_id: ev.cat_id,
                        });
                    }
                }
            }
            person_out
        })
        .collect();

    let mut person_event_batches: Vec<Vec<Vec<PersonEvent>>> =
        (0..P_PERSON).map(|_| Vec::with_capacity(P_DEDUP)).collect();
    let mut person_event_counts = vec![0usize; P_PERSON];
    for mut pvecs in dedup_results {
        for (ps, v) in pvecs.drain(..).enumerate() {
            if !v.is_empty() {
                person_event_counts[ps] += v.len();
                person_event_batches[ps].push(v);
            }
        }
    }
    let t_events_dedup = Instant::now();

    // Stage 4: Clicks parse + validate + direct P_PERSON-shard scatter
    let click_paths = list_csv_files(&data_dir.join("clicks"))?;
    let click_files = FileSet::open(&click_paths)?;
    let cl_chunks = click_files.chunks(CHUNK_BYTES);
    let n_cl_workers = ncpu.clamp(1, 63).min(cl_chunks.len().max(1));
    let total_cl_bytes: usize = cl_chunks.iter().map(|c| c.end - c.start).sum();
    let est_cl_cap = (total_cl_bytes / 75) / (n_cl_workers * P_PERSON);
    let mut cl_worker_shards: Vec<Vec<Vec<PersonClick>>> = (0..n_cl_workers)
        .map(|_| (0..P_PERSON).map(|_| Vec::with_capacity(est_cl_cap)).collect())
        .collect();
    let mut cl_worker_overflow: Vec<Vec<OverflowSpan>> =
        (0..n_cl_workers).map(|_| Vec::new()).collect();

    if !cl_chunks.is_empty() {
        let next_chunk = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for (wid, (buckets, ov_out)) in cl_worker_shards
                .iter_mut()
                .zip(cl_worker_overflow.iter_mut())
                .enumerate()
            {
                let files_ref = &click_files;
                let chunks_ref = &cl_chunks;
                let next_ref = &next_chunk;
                let lookups_ref = &lookups;
                let lm_ref = &link_map;
                let hb_ref = &hash_builder;
                scope.spawn(move || {
                    let mut dcache = DateCache::new();
                    loop {
                        let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                        let Some(chunk) = chunks_ref.get(cidx) else {
                            break;
                        };
                        let slice = &files_ref.file_bytes(chunk.file_idx)[chunk.start..chunk.end];
                        for_each_line_fields::<4>(slice, |[click_id, uid, camp_id, ts]| {
                            if click_id.is_empty()
                                || uid.is_empty()
                                || !is_valid_utf8(click_id)
                                || !is_valid_utf8(uid)
                            {
                                return;
                            }
                            let Some(cid) = lookups_ref.get_campaign(camp_id, hb_ref) else {
                                return;
                            };
                            let Some(ts_ms) = dcache.parse_ts_ms(ts) else {
                                return;
                            };
                            if ts_ms < click_window_start_ms || ts_ms >= window_end_ms {
                                return;
                            }
                            let (uid_key, uh) = if uid.len() <= 15 {
                                let k = InlineKey16::from_inline(uid);
                                let h = k.hash_inline();
                                (k, h)
                            } else {
                                let r = files_ref.make_ref(chunk.file_idx, uid, ov_out, wid);
                                (InlineKey16::from_ref(r), fast_hash_bytes(uid, hb_ref))
                            };
                            let (person_key, person_hash) = if !lm_ref.is_empty() {
                                if let Some((canon_ref, ch)) = lm_ref.resolve(uid, uh) {
                                    let pkey = if canon_ref.file_idx == FILE_IDX_ARENA
                                        && canon_ref.len <= 15
                                    {
                                        let off = canon_ref.off as usize;
                                        InlineKey16::from_inline(
                                            &lm_ref.canon_arena[off..off + canon_ref.len as usize],
                                        )
                                    } else if canon_ref.file_idx == FILE_IDX_OVERFLOW {
                                        InlineKey16::from_ref(pack_canon_overflow(canon_ref.off))
                                    } else {
                                        InlineKey16::from_ref(canon_ref)
                                    };
                                    (pkey, ch)
                                } else {
                                    (uid_key, uh)
                                }
                            } else {
                                (uid_key, uh)
                            };
                            let click_id_ref =
                                files_ref.make_ref(chunk.file_idx, click_id, ov_out, wid);
                            let pshard = ((person_hash >> 28) as usize) & (P_PERSON - 1);
                            buckets[pshard].push(PersonClick {
                                person_key,
                                click_id_ref,
                                ts_ms,
                                camp_id: cid,
                                _pad: 0,
                            });
                        });
                    }
                });
            }
        });
    }

    let mut person_click_batches: Vec<Vec<Vec<PersonClick>>> =
        (0..P_PERSON).map(|_| Vec::with_capacity(n_cl_workers)).collect();
    let mut person_click_counts = vec![0usize; P_PERSON];
    for mut worker_vecs in cl_worker_shards {
        for (ps, v) in worker_vecs.drain(..).enumerate() {
            if !v.is_empty() {
                person_click_counts[ps] += v.len();
                person_click_batches[ps].push(v);
            }
        }
    }
    let t_clicks = Instant::now();

    // Clean Parquet output directories
    let ud_dir = out_dir.join("user_daily");
    let cd_dir = out_dir.join("campaign_daily");
    clean_parquet_dir(&ud_dir)?;
    clean_parquet_dir(&cd_dir)?;

    // Stage 5: LPT-scheduled parallel shard processing -> UserDaily Parquet + CampDailyAcc
    let mut shard_order: Vec<usize> = (0..P_PERSON).collect();
    shard_order.sort_unstable_by(|&a, &b| {
        let wa = person_event_counts[a] + person_click_counts[a];
        let wb = person_event_counts[b] + person_click_counts[b];
        wb.cmp(&wa)
    });

    let mut shard_data: Vec<(Vec<Vec<PersonEvent>>, Vec<Vec<PersonClick>>, usize, usize)> =
        person_event_batches
            .into_iter()
            .zip(person_click_batches.into_iter())
            .zip(person_event_counts.into_iter().zip(person_click_counts.into_iter()))
            .map(|((eb, cb), (ec, cc))| (eb, cb, ec, cc))
            .collect();
    let shard_slots: Vec<
        std::sync::Mutex<Option<(Vec<Vec<PersonEvent>>, Vec<Vec<PersonClick>>, usize, usize)>>,
    > = shard_data
        .drain(..)
        .map(|item| std::sync::Mutex::new(Some(item)))
        .collect();

    let n_out_workers = ncpu.max(1).min(P_PERSON);
    let next_order = AtomicUsize::new(0);
    let num_camps = lookups.camp_entries.len();
    let num_cats = lookups.categories.len();
    let organic_camp = lookups.organic_camp_id;

    let mut worker_accs: Vec<CampDailyAcc> = (0..n_out_workers)
        .map(|_| CampDailyAcc::new(num_camps, min_day, max_day))
        .collect();
    let mut worker_ud_rows = vec![0usize; n_out_workers];
    let mut worker_err: Option<io::Error> = None;
    let err_lock = std::sync::Mutex::new(None::<io::Error>);

    std::thread::scope(|scope| {
        for (wid, (acc, ud_rows_out)) in worker_accs
            .iter_mut()
            .zip(worker_ud_rows.iter_mut())
            .enumerate()
        {
            let slots_ref = &shard_slots;
            let order_ref = &shard_order;
            let next_ref = &next_order;
            let ev_files_ref = &event_files;
            let ev_ov_ref = &ev_worker_overflow;
            let cl_files_ref = &click_files;
            let cl_ov_ref = &cl_worker_overflow;
            let lm_ref = &link_map;
            let lookups_ref = &lookups;
            let ud_path = ud_dir.join(format!("part-{wid}.parquet"));
            let err_lock_ref = &err_lock;

            scope.spawn(move || {
                let mut writer = match UserDailyWriter::create(
                    &ud_path,
                    USER_DAILY_BATCH_ROWS,
                    &lookups_ref.categories,
                    Compression::SNAPPY,
                ) {
                    Ok(w) => w,
                    Err(e) => {
                        *err_lock_ref.lock().unwrap() = Some(e);
                        return;
                    }
                };

                let mut cat_rev = vec![0i64; num_cats];
                let mut touched_cats: Vec<u32> = Vec::with_capacity(32);
                let mut active_count = vec![0u32; num_camps];
                let mut active_pos = vec![0u32; num_camps];
                let mut active_list: Vec<u32> = Vec::with_capacity(64);
                let mut sessions: Vec<SessionInfo> = Vec::with_capacity(256);
                let mut day_ranges: Vec<DayRange> = Vec::with_capacity(32);
                let mut camp_clicks: Vec<(u32, i64)> = Vec::with_capacity(256);

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

                    // 1. Intern unique person_ids from events
                    let p_cap = ev_total / 4 + 16;
                    let mut persons: Vec<InlineKey16> = Vec::with_capacity(p_cap);
                    let mut p_hashes: Vec<u64> = Vec::with_capacity(p_cap);
                    let mut p_table: HashTable<u32> = HashTable::with_capacity(p_cap);
                    let mut ev_pids: Vec<u32> = Vec::with_capacity(ev_total);

                    for batch in &evs_batches {
                        for ev in batch {
                            let ph = if ev.person_key.is_inline() {
                                ev.person_key.hash_inline()
                            } else {
                                hash_builder.hash_one(resolve_event_slice(
                                    ev.person_key.slice_ref(),
                                    ev_files_ref,
                                    ev_ov_ref,
                                    lm_ref,
                                ))
                            };
                            let pid = match p_table.find(ph, |&id| {
                                p_hashes[id as usize] == ph
                                    && inline_keys_equal_event(
                                        &persons[id as usize],
                                        &ev.person_key,
                                        ev_files_ref,
                                        ev_ov_ref,
                                        lm_ref,
                                    )
                            }) {
                                Some(&id) => id,
                                None => {
                                    let id = persons.len() as u32;
                                    persons.push(ev.person_key);
                                    p_hashes.push(ph);
                                    p_table.insert_unique(ph, id, |&idx| p_hashes[idx as usize]);
                                    id
                                }
                            };
                            ev_pids.push(pid);
                        }
                    }

                    let num_p = persons.len();
                    let mut ev_offsets = vec![0u32; num_p + 1];
                    for &pid in &ev_pids {
                        ev_offsets[pid as usize + 1] += 1;
                    }
                    for i in 1..=num_p {
                        ev_offsets[i] += ev_offsets[i - 1];
                    }
                    let mut ev_fill = ev_offsets[..num_p].to_vec();
                    let mut grouped_events = vec![
                        CompactEvent {
                            ts_ms: 0,
                            price_cents: 0,
                            cat_id: 0,
                        };
                        ev_total
                    ];
                    let mut pid_idx = 0usize;
                    for batch in evs_batches {
                        for ev in batch {
                            let pid = ev_pids[pid_idx] as usize;
                            pid_idx += 1;
                            let pos = ev_fill[pid] as usize;
                            ev_fill[pid] += 1;
                            grouped_events[pos] = CompactEvent {
                                ts_ms: ev.ts_ms,
                                price_cents: ev.price_cents,
                                cat_id: ev.cat_id,
                            };
                        }
                    }
                    drop(ev_pids);
                    drop(ev_fill);

                    // 2. Group matching clicks into CSR by pid (skip clicks for event-less persons)
                    let mut cl_counts = vec![0u32; num_p];
                    let mut cl_pids: Vec<u32> = Vec::with_capacity(cl_total);
                    for batch in &cls_batches {
                        for c in batch {
                            let ph = if c.person_key.is_inline() {
                                c.person_key.hash_inline()
                            } else {
                                hash_builder.hash_one(resolve_click_slice(
                                    c.person_key.slice_ref(),
                                    cl_files_ref,
                                    cl_ov_ref,
                                    lm_ref,
                                ))
                            };
                            let pid = p_table
                                .find(ph, |&id| {
                                    p_hashes[id as usize] == ph
                                        && inline_keys_equal_cross(
                                            &c.person_key,
                                            &persons[id as usize],
                                            cl_files_ref,
                                            cl_ov_ref,
                                            ev_files_ref,
                                            ev_ov_ref,
                                            lm_ref,
                                        )
                                })
                                .copied()
                                .unwrap_or(u32::MAX);
                            if pid != u32::MAX {
                                cl_counts[pid as usize] += 1;
                            }
                            cl_pids.push(pid);
                        }
                    }
                    let mut cl_offsets = vec![0u32; num_p + 1];
                    for i in 0..num_p {
                        cl_offsets[i + 1] = cl_offsets[i] + cl_counts[i];
                    }
                    let total_matched_cl = cl_offsets[num_p] as usize;
                    let mut cl_fill = cl_offsets[..num_p].to_vec();
                    let mut grouped_clicks = vec![
                        CompactClick {
                            ts_ms: 0,
                            click_id_ref: SliceRef {
                                file_idx: 0,
                                len: 0,
                                off: 0,
                            },
                            camp_id: 0,
                            _pad: 0,
                        };
                        total_matched_cl
                    ];
                    let mut cpid_idx = 0usize;
                    for batch in cls_batches {
                        for c in batch {
                            let pid = cl_pids[cpid_idx];
                            cpid_idx += 1;
                            if pid != u32::MAX {
                                let pos = cl_fill[pid as usize] as usize;
                                cl_fill[pid as usize] += 1;
                                grouped_clicks[pos] = CompactClick {
                                    ts_ms: c.ts_ms,
                                    click_id_ref: c.click_id_ref,
                                    camp_id: c.camp_id,
                                    _pad: 0,
                                };
                            }
                        }
                    }
                    drop(cl_pids);
                    drop(cl_counts);
                    drop(cl_fill);
                    drop(p_table);
                    drop(p_hashes);

                    // 3. Process each person independently
                    for pid in 0..num_p {
                        let e_lo = ev_offsets[pid] as usize;
                        let e_hi = ev_offsets[pid + 1] as usize;
                        let evs = &mut grouped_events[e_lo..e_hi];
                        evs.sort_unstable_by_key(|e| e.ts_ms);

                        let person_bytes =
                            resolve_inline_event(&persons[pid], ev_files_ref, ev_ov_ref, lm_ref);

                        sessions.clear();
                        let mut sess_start = evs[0].ts_ms;
                        let mut sess_day = sess_start.div_euclid(MS_DAY) as i32;
                        let mut sess_has_purch = if evs[0].price_cents > 0 { 1i64 } else { 0i64 };
                        let mut sess_rev = evs[0].price_cents as i64;
                        let mut prev_ts = evs[0].ts_ms;

                        let mut cur_day = sess_day;
                        let mut day_sessions = 1i64;
                        let mut day_events = 1i64;
                        let mut day_rev = evs[0].price_cents as i64;
                        if evs[0].price_cents > 0 {
                            let cid = evs[0].cat_id as usize;
                            cat_rev[cid] = evs[0].price_cents as i64;
                            touched_cats.push(evs[0].cat_id);
                        }

                        for e in &evs[1..] {
                            if e.ts_ms - prev_ts > MS_SESSION_GAP {
                                sessions.push(SessionInfo {
                                    start_ts: sess_start,
                                    day: sess_day,
                                    has_purchase: sess_has_purch,
                                    revenue_cents: sess_rev,
                                });
                                sess_start = e.ts_ms;
                                sess_day = e.ts_ms.div_euclid(MS_DAY) as i32;
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
                            prev_ts = e.ts_ms;
                            day_events += 1;
                            if e.price_cents > 0 {
                                let p64 = e.price_cents as i64;
                                sess_has_purch = 1;
                                sess_rev += p64;
                                day_rev += p64;
                                let cid = e.cat_id as usize;
                                if cat_rev[cid] == 0 {
                                    touched_cats.push(e.cat_id);
                                }
                                cat_rev[cid] += p64;
                            }
                        }

                        sessions.push(SessionInfo {
                            start_ts: sess_start,
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
                        let clks = &mut grouped_clicks[c_lo..c_hi];
                        if clks.is_empty() {
                            for s in &sessions {
                                acc.add_credit(organic_camp, s.day, s.has_purchase, s.revenue_cents);
                            }
                            continue;
                        }

                        clks.sort_unstable_by_key(|c| c.ts_ms);

                        // Primary credit: two-pointer sweep over sorted sessions and sorted clicks
                        let mut p = 0usize;
                        let mut has_click = false;
                        let mut best_ts = i64::MIN;
                        let mut best_idx = 0usize;
                        for s in &sessions {
                            while p < clks.len() && clks[p].ts_ms <= s.start_ts {
                                let c = &clks[p];
                                if !has_click || c.ts_ms > best_ts {
                                    has_click = true;
                                    best_ts = c.ts_ms;
                                    best_idx = p;
                                } else if c.ts_ms == best_ts {
                                    let cid_new = resolve_click_slice(
                                        c.click_id_ref,
                                        cl_files_ref,
                                        cl_ov_ref,
                                        lm_ref,
                                    );
                                    let cid_old = resolve_click_slice(
                                        clks[best_idx].click_id_ref,
                                        cl_files_ref,
                                        cl_ov_ref,
                                        lm_ref,
                                    );
                                    if cid_new < cid_old {
                                        best_idx = p;
                                    }
                                }
                                p += 1;
                            }
                            let camp = if has_click
                                && (s.start_ts as i128 - best_ts as i128) <= MS_CLICK_REACH as i128
                            {
                                clks[best_idx].camp_id
                            } else {
                                organic_camp
                            };
                            acc.add_credit(camp, s.day, s.has_purchase, s.revenue_cents);
                        }

                        // Assisting campaigns
                        if sessions.len() <= 32 && clks.len() <= 64 {
                            // Fast O(S + C) sliding window
                            let mut left = 0usize;
                            let mut right = 0usize;
                            for s in &sessions {
                                while right < clks.len() && clks[right].ts_ms <= s.start_ts {
                                    let cid = clks[right].camp_id as usize;
                                    let cnt = active_count[cid];
                                    active_count[cid] = cnt + 1;
                                    if cnt == 0 {
                                        active_pos[cid] = active_list.len() as u32;
                                        active_list.push(clks[right].camp_id);
                                    }
                                    right += 1;
                                }
                                while left < right
                                    && (s.start_ts as i128 - clks[left].ts_ms as i128)
                                        > MS_CLICK_REACH as i128
                                {
                                    let cid = clks[left].camp_id as usize;
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
                            // Scalable O(C log C + I log S + touched_days) merged intervals + day_ranges
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
                                camp_clicks.push((c.camp_id, c.ts_ms));
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
        worker_err = Some(e);
    }
    if let Some(e) = worker_err {
        return Err(e);
    }

    let total_ud_rows: usize = worker_ud_rows.iter().sum();
    if total_ud_rows == 0 {
        let empty_ud = UserDailyWriter::create(
            &ud_dir.join("part-0.parquet"),
            1,
            &lookups.categories,
            Compression::SNAPPY,
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
    write_campaign_daily(&cd_dir.join("part-0.parquet"), &cd_rows, Compression::SNAPPY)?;
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
    let s_lo = sessions.partition_point(|s| s.start_ts < iv_start);
    if s_lo >= sessions.len() {
        return;
    }
    let s_hi = s_lo + sessions[s_lo..].partition_point(|s| s.start_ts <= iv_end);
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

    #[test]
    fn test_sliding_window_vs_merged_intervals_equivalence() {
        // Deterministic pseudo-random fuzz comparing both assist paths across boundary edge cases.
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
                    start_ts: st,
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
            let mut acc_iv = CampDailyAcc::new(num_camps, min_d, max_d);

            // Brute-force / sliding-window path
            let mut active_count = vec![0u32; num_camps];
            let mut active_pos = vec![0u32; num_camps];
            let mut active_list: Vec<u32> = Vec::new();
            let mut left = 0usize;
            let mut right = 0usize;
            for s in &sessions {
                while right < clks.len() && clks[right].0 <= s.start_ts {
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
                    && (s.start_ts as i128 - clks[left].0 as i128) > MS_CLICK_REACH as i128
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

            // Merged-intervals path
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
                        emit_interval_assists(&mut acc_iv, camp, iv_start, iv_end, &sessions, &day_ranges);
                        iv_start = t;
                        iv_end = t.saturating_add(MS_CLICK_REACH);
                    }
                    i += 1;
                }
                emit_interval_assists(&mut acc_iv, camp, iv_start, iv_end, &sessions, &day_ranges);
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
}
