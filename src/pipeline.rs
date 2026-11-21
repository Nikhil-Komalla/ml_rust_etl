use std::fs;
use std::hash::BuildHasher;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use hashbrown::{DefaultHashBuilder, HashMap, HashTable};
use rayon::prelude::*;

use crate::csv::{
    for_each_line_fields, is_valid_utf8, list_csv_files, FileSet, OverflowSpan, SliceRef,
    CHUNK_BYTES, FILE_IDX_OVERFLOW,
};
use crate::links::{build_link_map, LinkMap};
use crate::parse::{
    parse_f1_ms, parse_price_cents, parse_ts_ms, Manifest, MS_CLICK_REACH, MS_DAY, MS_SESSION_GAP,
};
use crate::parquet_out::{clean_parquet_dir, write_campaign_daily, CampaignRow, UserDailyWriter};

const P_DEDUP: usize = 64;
const P_PERSON: usize = 128;
const INVALID_EVENT: u32 = u32::MAX;
const USER_DAILY_BATCH_ROWS: usize = 131_072;

#[derive(Clone, Copy)]
struct ParsedEvent {
    ev_hash: u64,
    ev_ref: SliceRef,
    ingest_ts_ms: i64,
    ts_ms: i64,
    person_ref: SliceRef,
    price_or_invalid: u32,
    cat_id: u32,
}

const _: () = assert!(std::mem::size_of::<ParsedEvent>() == 48);

#[derive(Clone, Copy)]
struct PersonEvent {
    person_ref: SliceRef,
    person_hash: u64,
    ts_ms: i64,
    price_cents: u32,
    cat_id: u32,
}

const _: () = assert!(std::mem::size_of::<PersonEvent>() == 32);

#[derive(Clone, Copy)]
struct PersonClick {
    person_ref: SliceRef,
    click_id_ref: SliceRef,
    ts_ms: i64,
    camp_id: u32,
    _pad: u32,
}

const _: () = assert!(std::mem::size_of::<PersonClick>() == 32);

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

struct Lookups {
    prod_map: HashMap<Box<[u8]>, u32, DefaultHashBuilder>,
    categories: Vec<Box<[u8]>>,
    unknown_cat_id: u32,
    camp_map: HashMap<Box<[u8]>, u32, DefaultHashBuilder>,
    camp_names: Vec<Box<[u8]>>,
    camp_channels: Vec<Box<[u8]>>,
    organic_camp_id: u32,
}

fn load_lookups(data_dir: &Path, hash_builder: &DefaultHashBuilder) -> io::Result<Lookups> {
    let prod_path = data_dir.join("products.csv");
    let mut raw_prods: Vec<(Box<[u8]>, Box<[u8]>)> = Vec::new();
    let mut raw_cats: Vec<Box<[u8]>> = vec![b"unknown".to_vec().into_boxed_slice()];
    if prod_path.is_file() {
        let pfiles = FileSet::open(&[prod_path])?;
        for ch in pfiles.chunks(usize::MAX / 2) {
            let slice = &pfiles.file_bytes(ch.file_idx)[ch.start..ch.end];
            for_each_line_fields::<2>(slice, |[pid, cat]| {
                if !pid.is_empty() && !cat.is_empty() && is_valid_utf8(pid) && is_valid_utf8(cat) {
                    raw_prods.push((
                        pid.to_vec().into_boxed_slice(),
                        cat.to_vec().into_boxed_slice(),
                    ));
                    raw_cats.push(cat.to_vec().into_boxed_slice());
                }
            });
        }
    }
    raw_cats.sort_unstable();
    raw_cats.dedup();
    let mut cat_to_id: HashMap<Box<[u8]>, u32, DefaultHashBuilder> =
        HashMap::with_capacity_and_hasher(raw_cats.len(), hash_builder.clone());
    for (i, c) in raw_cats.iter().enumerate() {
        cat_to_id.insert(c.clone(), i as u32);
    }
    let unknown_cat_id = *cat_to_id.get(b"unknown".as_slice()).unwrap();

    let mut prod_map: HashMap<Box<[u8]>, u32, DefaultHashBuilder> =
        HashMap::with_capacity_and_hasher(raw_prods.len(), hash_builder.clone());
    for (pid, cat) in raw_prods {
        let cid = *cat_to_id.get(cat.as_ref()).unwrap();
        prod_map.insert(pid, cid);
    }

    let camp_path = data_dir.join("campaigns.csv");
    let mut camp_map: HashMap<Box<[u8]>, u32, DefaultHashBuilder> =
        HashMap::with_hasher(hash_builder.clone());
    let mut camp_names: Vec<Box<[u8]>> = Vec::new();
    let mut camp_channels: Vec<Box<[u8]>> = Vec::new();
    if camp_path.is_file() {
        let cfiles = FileSet::open(&[camp_path])?;
        for ch in cfiles.chunks(usize::MAX / 2) {
            let slice = &cfiles.file_bytes(ch.file_idx)[ch.start..ch.end];
            for_each_line_fields::<2>(slice, |[cid, ch_name]| {
                if !cid.is_empty()
                    && !ch_name.is_empty()
                    && is_valid_utf8(cid)
                    && is_valid_utf8(ch_name)
                {
                    let id = camp_names.len() as u32;
                    camp_names.push(cid.to_vec().into_boxed_slice());
                    camp_channels.push(ch_name.to_vec().into_boxed_slice());
                    camp_map.insert(cid.to_vec().into_boxed_slice(), id);
                }
            });
        }
    }
    let organic_camp_id = camp_names.len() as u32;
    camp_names.push(b"organic".to_vec().into_boxed_slice());
    camp_channels.push(b"organic".to_vec().into_boxed_slice());

    Ok(Lookups {
        prod_map,
        categories: raw_cats,
        unknown_cat_id,
        camp_map,
        camp_names,
        camp_channels,
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
    let lookups = load_lookups(data_dir, &hash_builder)?;
    let t_lookups = Instant::now();

    let link_paths = list_csv_files(&data_dir.join("links"))?;
    let link_map = build_link_map(&link_paths, &hash_builder, ncpu)?;
    let t_links = Instant::now();

    // Stage 3: Events parse (parallel) -> 64-shard dedup before validation -> 128-shard scatter
    let event_paths = list_csv_files(&data_dir.join("events"))?;
    let event_files = FileSet::open(&event_paths)?;
    let ev_chunks = event_files.chunks(CHUNK_BYTES);
    let n_ev_workers = ncpu.clamp(1, 63).min(ev_chunks.len().max(1));
    let mut ev_worker_shards: Vec<Vec<Vec<ParsedEvent>>> = (0..n_ev_workers)
        .map(|_| (0..P_DEDUP).map(|_| Vec::new()).collect())
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
                let lm_ref = &link_map;
                let hb_ref = &hash_builder;
                scope.spawn(move || loop {
                    let cidx = next_ref.fetch_add(1, Ordering::Relaxed);
                    let Some(chunk) = chunks_ref.get(cidx) else {
                        break;
                    };
                    let slice = &files_ref.file_bytes(chunk.file_idx)[chunk.start..chunk.end];
                    for_each_line_fields::<7>(slice, |[ev_id, uid, ts, ingest_ts, etype, pid, price]| {
                        if ev_id.is_empty() || !is_valid_utf8(ev_id) {
                            return;
                        }
                        let Some(ingest_ms) = parse_f1_ms(ingest_ts) else {
                            return;
                        };
                        let ev_hash = hb_ref.hash_one(ev_id);
                        let ev_ref = files_ref.make_ref(chunk.file_idx, ev_id, ov_out, wid);
                        let d_shard = (ev_hash >> 58) as usize;

                        let mut valid = true;
                        let mut ts_ms = 0i64;
                        let mut price_val = 0u32;
                        let mut cat_id = 0u32;
                        let mut person_ref = SliceRef {
                            file_idx: 0,
                            len: 0,
                            off: 0,
                        };

                        if uid.is_empty() || pid.is_empty() || !is_valid_utf8(uid) {
                            valid = false;
                        } else if let Some(t) = parse_ts_ms(ts) {
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
                                            cat_id = *lookups_ref
                                                .prod_map
                                                .get(pid)
                                                .unwrap_or(&lookups_ref.unknown_cat_id);
                                        } else {
                                            valid = false;
                                        }
                                    }
                                    _ => valid = false,
                                }
                                if valid {
                                    if !lm_ref.is_empty() {
                                        let uh = hb_ref.hash_one(uid);
                                        if let Some((canon_ref, _)) = lm_ref.resolve(uid, uh) {
                                            person_ref = if canon_ref.file_idx == FILE_IDX_OVERFLOW
                                            {
                                                pack_canon_overflow(canon_ref.off)
                                            } else {
                                                canon_ref
                                            };
                                        } else {
                                            person_ref =
                                                files_ref.make_ref(chunk.file_idx, uid, ov_out, wid);
                                        }
                                    } else {
                                        person_ref =
                                            files_ref.make_ref(chunk.file_idx, uid, ov_out, wid);
                                    }
                                }
                            }
                        } else {
                            valid = false;
                        }

                        buckets[d_shard].push(ParsedEvent {
                            ev_hash,
                            ev_ref,
                            ingest_ts_ms: ingest_ms,
                            ts_ms,
                            person_ref,
                            price_or_invalid: if valid { price_val } else { INVALID_EVENT },
                            cat_id,
                        });
                    });
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

    // Stage 3b: Deduplicate each shard & scatter valid surviving events into P_PERSON shards.
    let dedup_results: Vec<Vec<Vec<PersonEvent>>> = dedup_inputs
        .into_par_iter()
        .map(|shard_vecs| {
            let total: usize = shard_vecs.iter().map(Vec::len).sum();
            let mut person_out: Vec<Vec<PersonEvent>> =
                (0..P_PERSON).map(|_| Vec::new()).collect();
            if total == 0 {
                return person_out;
            }
            let mut table: HashTable<u32> = HashTable::with_capacity(total);
            for (widx, batch) in shard_vecs.iter().enumerate() {
                let wbase = (widx as u32) << 26;
                for (ridx, ev) in batch.iter().enumerate() {
                    let ev_bytes =
                        resolve_event_slice(ev.ev_ref, &event_files, &ev_worker_overflow, &link_map);
                    match table.entry(
                        ev.ev_hash,
                        |&packed| {
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            let existing = &shard_vecs[pw][pr];
                            existing.ev_hash == ev.ev_hash
                                && resolve_event_slice(
                                    existing.ev_ref,
                                    &event_files,
                                    &ev_worker_overflow,
                                    &link_map,
                                ) == ev_bytes
                        },
                        |&packed| {
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            shard_vecs[pw][pr].ev_hash
                        },
                    ) {
                        hashbrown::hash_table::Entry::Occupied(mut occ) => {
                            let packed = *occ.get();
                            let pw = (packed >> 26) as usize;
                            let pr = (packed & ((1 << 26) - 1)) as usize;
                            if ev.ingest_ts_ms < shard_vecs[pw][pr].ingest_ts_ms {
                                *occ.get_mut() = wbase | (ridx as u32);
                            }
                        }
                        hashbrown::hash_table::Entry::Vacant(vac) => {
                            vac.insert(wbase | (ridx as u32));
                        }
                    }
                }
            }

            for &packed in &table {
                let pw = (packed >> 26) as usize;
                let pr = (packed & ((1 << 26) - 1)) as usize;
                let ev = &shard_vecs[pw][pr];
                if ev.price_or_invalid != INVALID_EVENT {
                    let pbytes = resolve_event_slice(
                        ev.person_ref,
                        &event_files,
                        &ev_worker_overflow,
                        &link_map,
                    );
                    let ph = hash_builder.hash_one(pbytes);
                    let pshard = (ph as usize) & (P_PERSON - 1);
                    person_out[pshard].push(PersonEvent {
                        person_ref: ev.person_ref,
                        person_hash: ph,
                        ts_ms: ev.ts_ms,
                        price_cents: ev.price_or_invalid,
                        cat_id: ev.cat_id,
                    });
                }
            }
            drop(table);
            drop(shard_vecs);
            person_out
        })
        .collect();

    let mut person_events: Vec<Vec<PersonEvent>> = (0..P_PERSON).map(|_| Vec::new()).collect();
    for mut pvecs in dedup_results {
        for (ps, mut v) in pvecs.drain(..).enumerate() {
            person_events[ps].append(&mut v);
        }
    }
    let t_events_dedup = Instant::now();

    // Stage 4: Clicks parse + validate + direct 128-shard person scatter
    let click_paths = list_csv_files(&data_dir.join("clicks"))?;
    let click_files = FileSet::open(&click_paths)?;
    let cl_chunks = click_files.chunks(CHUNK_BYTES);
    let n_cl_workers = ncpu.clamp(1, 63).min(cl_chunks.len().max(1));
    let mut cl_worker_shards: Vec<Vec<Vec<PersonClick>>> = (0..n_cl_workers)
        .map(|_| (0..P_PERSON).map(|_| Vec::new()).collect())
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
                scope.spawn(move || loop {
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
                        let Some(&cid) = lookups_ref.camp_map.get(camp_id) else {
                            return;
                        };
                        let Some(ts_ms) = parse_ts_ms(ts) else {
                            return;
                        };
                        if ts_ms < click_window_start_ms || ts_ms >= window_end_ms {
                            return;
                        }
                        let (person_ref, person_hash) = if !lm_ref.is_empty() {
                            let uh = hb_ref.hash_one(uid);
                            if let Some((canon_ref, ch)) = lm_ref.resolve(uid, uh) {
                                let pref = if canon_ref.file_idx == FILE_IDX_OVERFLOW {
                                    pack_canon_overflow(canon_ref.off)
                                } else {
                                    canon_ref
                                };
                                (pref, ch)
                            } else {
                                (files_ref.make_ref(chunk.file_idx, uid, ov_out, wid), uh)
                            }
                        } else {
                            let uh = hb_ref.hash_one(uid);
                            (files_ref.make_ref(chunk.file_idx, uid, ov_out, wid), uh)
                        };
                        let click_id_ref = files_ref.make_ref(chunk.file_idx, click_id, ov_out, wid);
                        let pshard = (person_hash as usize) & (P_PERSON - 1);
                        buckets[pshard].push(PersonClick {
                            person_ref,
                            click_id_ref,
                            ts_ms,
                            camp_id: cid,
                            _pad: 0,
                        });
                    });
                });
            }
        });
    }

    let mut person_clicks: Vec<Vec<PersonClick>> = (0..P_PERSON).map(|_| Vec::new()).collect();
    for mut worker_vecs in cl_worker_shards {
        for (ps, mut v) in worker_vecs.drain(..).enumerate() {
            person_clicks[ps].append(&mut v);
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
        let wa = person_events[a].len() + person_clicks[a].len();
        let wb = person_events[b].len() + person_clicks[b].len();
        wb.cmp(&wa)
    });

    // Zip into movable per-shard packets wrapped in Option/Mutex-free indexed storage
    let mut shard_data: Vec<(Vec<PersonEvent>, Vec<PersonClick>)> = person_events
        .into_iter()
        .zip(person_clicks.into_iter())
        .collect();
    // Wrap in std::sync::Mutex<Option<...>> only so workers can take() one shard at a time cleanly without unsafe.
    let shard_slots: Vec<std::sync::Mutex<Option<(Vec<PersonEvent>, Vec<PersonClick>)>>> =
        shard_data
            .drain(..)
            .map(|pair| std::sync::Mutex::new(Some(pair)))
            .collect();

    let n_out_workers = ncpu.max(1).min(P_PERSON);
    let next_order = AtomicUsize::new(0);
    let num_camps = lookups.camp_names.len();
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
                let mut writer = match UserDailyWriter::create(&ud_path, USER_DAILY_BATCH_ROWS) {
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
                    let Some((evs_in, cls_in)) = slots_ref[shard_idx].lock().unwrap().take() else {
                        break;
                    };
                    if evs_in.is_empty() {
                        continue;
                    }

                    // 1. Intern unique person_ids from events
                    let mut persons: Vec<SliceRef> = Vec::with_capacity(evs_in.len() / 4 + 16);
                    let mut p_hashes: Vec<u64> = Vec::with_capacity(evs_in.len() / 4 + 16);
                    let mut p_table: HashTable<u32> = HashTable::with_capacity(evs_in.len() / 4 + 16);
                    let mut ev_pids: Vec<u32> = Vec::with_capacity(evs_in.len());

                    for ev in &evs_in {
                        let pb = resolve_event_slice(ev.person_ref, ev_files_ref, ev_ov_ref, lm_ref);
                        let pid = match p_table.find(ev.person_hash, |&id| {
                            p_hashes[id as usize] == ev.person_hash
                                && resolve_event_slice(
                                    persons[id as usize],
                                    ev_files_ref,
                                    ev_ov_ref,
                                    lm_ref,
                                ) == pb
                        }) {
                            Some(&id) => id,
                            None => {
                                let id = persons.len() as u32;
                                persons.push(ev.person_ref);
                                p_hashes.push(ev.person_hash);
                                p_table.insert_unique(ev.person_hash, id, |&idx| p_hashes[idx as usize]);
                                id
                            }
                        };
                        ev_pids.push(pid);
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
                        evs_in.len()
                    ];
                    for (ev, &pid) in evs_in.iter().zip(ev_pids.iter()) {
                        let pos = ev_fill[pid as usize] as usize;
                        ev_fill[pid as usize] += 1;
                        grouped_events[pos] = CompactEvent {
                            ts_ms: ev.ts_ms,
                            price_cents: ev.price_cents,
                            cat_id: ev.cat_id,
                        };
                    }
                    drop(evs_in);
                    drop(ev_pids);
                    drop(ev_fill);

                    // 2. Group matching clicks into CSR by pid (skip clicks for event-less persons)
                    let mut cl_counts = vec![0u32; num_p];
                    let mut cl_pids: Vec<u32> = Vec::with_capacity(cls_in.len());
                    for c in &cls_in {
                        let pb = resolve_click_slice(c.person_ref, cl_files_ref, cl_ov_ref, lm_ref);
                        let ph = hash_builder.hash_one(pb);
                        let pid = p_table
                            .find(ph, |&id| {
                                p_hashes[id as usize] == ph
                                    && resolve_event_slice(
                                        persons[id as usize],
                                        ev_files_ref,
                                        ev_ov_ref,
                                        lm_ref,
                                    ) == pb
                            })
                            .copied()
                            .unwrap_or(u32::MAX);
                        if pid != u32::MAX {
                            cl_counts[pid as usize] += 1;
                        }
                        cl_pids.push(pid);
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
                    for (c, &pid) in cls_in.iter().zip(cl_pids.iter()) {
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
                    drop(cls_in);
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
                            resolve_event_slice(persons[pid], ev_files_ref, ev_ov_ref, lm_ref);

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
                                    let top_cat = pick_and_reset_top_cat(
                                        &mut cat_rev,
                                        &mut touched_cats,
                                        &lookups_ref.categories,
                                    );
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
                        let top_cat = pick_and_reset_top_cat(
                            &mut cat_rev,
                            &mut touched_cats,
                            &lookups_ref.categories,
                        );
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
        let empty_ud = UserDailyWriter::create(&ud_dir.join("part-0.parquet"), 1)?;
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
            cells,
        } => {
            for c in 0..*num_camps {
                let c_name = lookups.camp_names[c].as_ref();
                let ch_name = lookups.camp_channels[c].as_ref();
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
                        campaign_id: lookups.camp_names[c as usize].as_ref(),
                        channel: lookups.camp_channels[c as usize].as_ref(),
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
            "PROFILE startup={:.4}s lookups={:.4}s links={:.4}s events_parse={:.4}s events_dedup={:.4}s clicks={:.4}s sessionize_attr_write={:.4}s total={:.4}s vm_hwm_kb={}",
            (t_startup - t0).as_secs_f64(),
            (t_lookups - t_startup).as_secs_f64(),
            (t_links - t_lookups).as_secs_f64(),
            (t_events_parse - t_links).as_secs_f64(),
            (t_events_dedup - t_events_parse).as_secs_f64(),
            (t_clicks - t_events_dedup).as_secs_f64(),
            (t_done - t_clicks).as_secs_f64(),
            (t_done - t0).as_secs_f64(),
            vm_hwm
        );
    }

    Ok(())
}

#[inline(always)]
fn pick_and_reset_top_cat<'a>(
    cat_rev: &mut [i64],
    touched_cats: &mut Vec<u32>,
    categories: &'a [Box<[u8]>],
) -> Option<&'a [u8]> {
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
    Some(categories[best_id as usize].as_ref())
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
