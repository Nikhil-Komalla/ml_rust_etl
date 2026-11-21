use std::fs::{self, File};
use std::io::{self, BufWriter, IoSlice, Write};
use std::path::Path;
use std::sync::Arc;

use parquet::basic::Compression;
use parquet::column::writer::ColumnWriter;
use parquet::data_type::ByteArray;
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;

const CAMPAIGN_DAILY_SCHEMA: &str = "
message campaign_daily {
    REQUIRED BINARY campaign_id (UTF8);
    REQUIRED BINARY channel (UTF8);
    REQUIRED INT32 day (DATE);
    REQUIRED INT64 sessions;
    REQUIRED INT64 purchasing_sessions;
    REQUIRED INT64 revenue_cents;
    REQUIRED INT64 assisted_sessions;
}
";

pub fn clean_parquet_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("parquet") && path.is_file() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

// TCompactProtocol wire type tags
const CT_I32: u8 = 5;
const CT_I64: u8 = 6;
const CT_BINARY: u8 = 8;
const CT_LIST: u8 = 9;
const CT_STRUCT: u8 = 12;

// Parquet enums
const PQ_TYPE_INT32: i32 = 1;
const PQ_TYPE_INT64: i32 = 2;
const PQ_TYPE_BYTE_ARRAY: i32 = 6;
const PQ_REP_REQUIRED: i32 = 0;
const PQ_REP_OPTIONAL: i32 = 1;
const PQ_CT_UTF8: i32 = 0;
const PQ_CT_DATE: i32 = 6;
const PQ_ENC_PLAIN: i32 = 0;
const PQ_ENC_RLE: i32 = 3;
const PQ_CODEC_UNCOMPRESSED: i32 = 0;
const PQ_PAGE_DATA: i32 = 0;

struct ThriftBuf(Vec<u8>);

impl ThriftBuf {
    #[inline]
    fn new(cap: usize) -> Self {
        Self(Vec::with_capacity(cap))
    }

    #[inline(always)]
    fn uvarint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.0.push((v as u8 & 0x7F) | 0x80);
            v >>= 7;
        }
        self.0.push(v as u8);
    }

    #[inline(always)]
    fn i32_zigzag(&mut self, n: i32) {
        self.uvarint((((n << 1) ^ (n >> 31)) as u32) as u64);
    }

    #[inline(always)]
    fn i64_zigzag(&mut self, n: i64) {
        self.uvarint(((n << 1) ^ (n >> 63)) as u64);
    }

    #[inline(always)]
    fn field(&mut self, last_id: &mut u8, id: u8, ttype: u8) {
        let delta = id - *last_id;
        if delta <= 15 {
            self.0.push((delta << 4) | ttype);
        } else {
            self.0.push(ttype);
            self.i32_zigzag(id as i32);
        }
        *last_id = id;
    }

    #[inline(always)]
    fn field_i32(&mut self, last_id: &mut u8, id: u8, val: i32) {
        self.field(last_id, id, CT_I32);
        self.i32_zigzag(val);
    }

    #[inline(always)]
    fn field_i64(&mut self, last_id: &mut u8, id: u8, val: i64) {
        self.field(last_id, id, CT_I64);
        self.i64_zigzag(val);
    }

    #[inline(always)]
    fn field_str(&mut self, last_id: &mut u8, id: u8, s: &[u8]) {
        self.field(last_id, id, CT_BINARY);
        self.uvarint(s.len() as u64);
        self.0.extend_from_slice(s);
    }

    #[inline(always)]
    fn list_hdr(&mut self, elem_type: u8, len: usize) {
        if len < 15 {
            self.0.push(((len as u8) << 4) | elem_type);
        } else {
            self.0.push(0xF0 | elem_type);
            self.uvarint(len as u64);
        }
    }

    #[inline(always)]
    fn stop(&mut self) {
        self.0.push(0);
    }
}

fn write_data_page_header(buf: &mut ThriftBuf, num_values: i32, page_size: i32) {
    buf.0.clear();
    let mut ph_last = 0u8;
    buf.field_i32(&mut ph_last, 1, PQ_PAGE_DATA);
    buf.field_i32(&mut ph_last, 2, page_size);
    buf.field_i32(&mut ph_last, 3, page_size);
    buf.field(&mut ph_last, 5, CT_STRUCT);
    let mut dph_last = 0u8;
    buf.field_i32(&mut dph_last, 1, num_values);
    buf.field_i32(&mut dph_last, 2, PQ_ENC_PLAIN);
    buf.field_i32(&mut dph_last, 3, PQ_ENC_RLE);
    buf.field_i32(&mut dph_last, 4, PQ_ENC_RLE);
    buf.stop();
    buf.stop();
}

fn encode_rle_bitpacked_def1(def_bits: &[u8], row_count: usize, out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&[0u8; 4]);
    let n_bytes = (row_count + 7) >> 3;
    let mut pos = 0usize;
    while pos < n_bytes {
        let chunk = (n_bytes - pos).min(63);
        out.push(((chunk as u8) << 1) | 1);
        out.extend_from_slice(&def_bits[pos..pos + chunk]);
        pos += chunk;
    }
    let stream_len = (out.len() - 4) as u32;
    out[0..4].copy_from_slice(&stream_len.to_le_bytes());
}

fn write_all_slices(file: &mut File, slices: &[&[u8]]) -> io::Result<()> {
    let total: usize = slices.iter().map(|s| s.len()).sum();
    if total == 0 {
        return Ok(());
    }
    const MAX_IOV: usize = 16;
    debug_assert!(slices.len() <= MAX_IOV);
    let mut iov = [IoSlice::new(&[]); MAX_IOV];
    let n_slices = slices.len();
    for (dst, &src) in iov[..n_slices].iter_mut().zip(slices.iter()) {
        *dst = IoSlice::new(src);
    }
    match file.write_vectored(&iov[..n_slices]) {
        Ok(n) if n == total => Ok(()),
        Ok(mut skip) => {
            for &s in slices {
                if skip >= s.len() {
                    skip -= s.len();
                } else {
                    file.write_all(&s[skip..])?;
                    skip = 0;
                }
            }
            Ok(())
        }
        Err(_) => {
            for &s in slices {
                file.write_all(s)?;
            }
            Ok(())
        }
    }
}

#[cfg(target_endian = "little")]
#[inline(always)]
fn i32_as_le_bytes(v: &[i32]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

#[cfg(target_endian = "little")]
#[inline(always)]
fn i64_as_le_bytes(v: &[i64]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

struct ColChunkMeta {
    name: &'static [u8],
    pq_type: i32,
    num_values: i64,
    total_size: i64,
    data_page_offset: i64,
}

struct RowGroupMeta {
    cols: [ColChunkMeta; 6],
    total_byte_size: i64,
    num_rows: i64,
    file_offset: i64,
}

fn write_schema_elem(
    buf: &mut ThriftBuf,
    pq_type: Option<i32>,
    rep: Option<i32>,
    name: &[u8],
    num_children: Option<i32>,
    converted: Option<i32>,
    logical_field_id: Option<u8>,
) {
    let mut last = 0u8;
    if let Some(t) = pq_type {
        buf.field_i32(&mut last, 1, t);
    }
    if let Some(r) = rep {
        buf.field_i32(&mut last, 3, r);
    }
    buf.field_str(&mut last, 4, name);
    if let Some(c) = num_children {
        buf.field_i32(&mut last, 5, c);
    }
    if let Some(ct) = converted {
        buf.field_i32(&mut last, 6, ct);
    }
    if let Some(lf) = logical_field_id {
        buf.field(&mut last, 10, CT_STRUCT);
        let mut lt_last = 0u8;
        buf.field(&mut lt_last, lf, CT_STRUCT);
        buf.stop(); // empty inner logical type struct (StringType / DateType)
        buf.stop(); // LogicalType union
    }
    buf.stop();
}

pub struct UserDailyWriter {
    file: File,
    file_pos: i64,
    row_groups: Vec<RowGroupMeta>,
    uid_plain: Vec<u8>,
    days: Vec<i32>,
    sessions: Vec<i32>,
    events: Vec<i32>,
    revenues: Vec<i64>,
    cat_def_bits: Vec<u8>,
    cat_def_rle: Vec<u8>,
    cat_plain: Vec<u8>,
    cat_encoded: Vec<Box<[u8]>>,
    hdr_bufs: [Vec<u8>; 6],
    total_rows: usize,
    batch_rows: usize,
}

impl UserDailyWriter {
    pub fn create(
        path: &Path,
        batch_rows: usize,
        categories: &[Box<[u8]>],
        _compression: Compression,
    ) -> io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(b"PAR1")?;
        let cap = batch_rows.min(131_072);
        let cat_encoded = categories
            .iter()
            .map(|c| {
                let mut v = Vec::with_capacity(4 + c.len());
                v.extend_from_slice(&(c.len() as u32).to_le_bytes());
                v.extend_from_slice(c.as_ref());
                v.into_boxed_slice()
            })
            .collect();
        Ok(Self {
            file,
            file_pos: 4,
            row_groups: Vec::new(),
            uid_plain: Vec::with_capacity(cap * 16),
            days: Vec::with_capacity(cap),
            sessions: Vec::with_capacity(cap),
            events: Vec::with_capacity(cap),
            revenues: Vec::with_capacity(cap),
            cat_def_bits: Vec::with_capacity((cap + 7) >> 3),
            cat_def_rle: Vec::with_capacity(((cap + 7) >> 3) + 64),
            cat_plain: Vec::with_capacity(cap * 12),
            cat_encoded,
            hdr_bufs: std::array::from_fn(|_| Vec::with_capacity(32)),
            total_rows: 0,
            batch_rows,
        })
    }

    #[inline(always)]
    pub fn push(
        &mut self,
        user_id: &[u8],
        day: i32,
        sessions: i64,
        events: i64,
        revenue: i64,
        top_cat_id: Option<u32>,
    ) -> io::Result<()> {
        let rg_idx = self.days.len();
        self.uid_plain
            .extend_from_slice(&(user_id.len() as u32).to_le_bytes());
        self.uid_plain.extend_from_slice(user_id);
        self.days.push(day);
        self.sessions.push(sessions as i32);
        self.events.push(events as i32);
        self.revenues.push(revenue);

        let byte_idx = rg_idx >> 3;
        if byte_idx == self.cat_def_bits.len() {
            self.cat_def_bits.push(0);
        }
        if let Some(cid) = top_cat_id {
            unsafe {
                *self.cat_def_bits.get_unchecked_mut(byte_idx) |= 1u8 << (rg_idx & 7);
            }
            let enc = unsafe { self.cat_encoded.get_unchecked(cid as usize) };
            self.cat_plain.extend_from_slice(enc);
        }

        self.total_rows += 1;
        if self.days.len() >= self.batch_rows {
            self.flush_row_group()?;
        }
        Ok(())
    }

    pub fn flush_row_group(&mut self) -> io::Result<()> {
        let n = self.days.len();
        if n == 0 {
            return Ok(());
        }
        let n_i32 = n as i32;
        let n_i64 = n as i64;
        let rg_file_offset = self.file_pos;

        encode_rle_bitpacked_def1(&self.cat_def_bits, n, &mut self.cat_def_rle);

        let d_bytes = i32_as_le_bytes(&self.days);
        let s_bytes = i32_as_le_bytes(&self.sessions);
        let e_bytes = i32_as_le_bytes(&self.events);
        let r_bytes = i64_as_le_bytes(&self.revenues);

        let col0_page_len = self.uid_plain.len() as i32;
        let col1_page_len = d_bytes.len() as i32;
        let col2_page_len = s_bytes.len() as i32;
        let col3_page_len = e_bytes.len() as i32;
        let col4_page_len = r_bytes.len() as i32;
        let col5_page_len = (self.cat_def_rle.len() + self.cat_plain.len()) as i32;

        let page_lens = [
            col0_page_len,
            col1_page_len,
            col2_page_len,
            col3_page_len,
            col4_page_len,
            col5_page_len,
        ];

        let mut tmp_tb = ThriftBuf::new(32);
        for (i, &plen) in page_lens.iter().enumerate() {
            write_data_page_header(&mut tmp_tb, n_i32, plen);
            self.hdr_bufs[i].clear();
            self.hdr_bufs[i].extend_from_slice(&tmp_tb.0);
        }

        let slices: [&[u8]; 13] = [
            &self.hdr_bufs[0],
            &self.uid_plain,
            &self.hdr_bufs[1],
            d_bytes,
            &self.hdr_bufs[2],
            s_bytes,
            &self.hdr_bufs[3],
            e_bytes,
            &self.hdr_bufs[4],
            r_bytes,
            &self.hdr_bufs[5],
            &self.cat_def_rle,
            &self.cat_plain,
        ];
        write_all_slices(&mut self.file, &slices)?;

        let names: [&'static [u8]; 6] = [
            b"user_id",
            b"day",
            b"sessions",
            b"events",
            b"revenue_cents",
            b"top_category",
        ];
        let pq_types = [
            PQ_TYPE_BYTE_ARRAY,
            PQ_TYPE_INT32,
            PQ_TYPE_INT32,
            PQ_TYPE_INT32,
            PQ_TYPE_INT64,
            PQ_TYPE_BYTE_ARRAY,
        ];

        let mut off = rg_file_offset;
        let mut total_rg_bytes = 0i64;
        let cols: [ColChunkMeta; 6] = std::array::from_fn(|i| {
            let chunk_bytes = (self.hdr_bufs[i].len() as i64) + (page_lens[i] as i64);
            let meta = ColChunkMeta {
                name: names[i],
                pq_type: pq_types[i],
                num_values: n_i64,
                total_size: chunk_bytes,
                data_page_offset: off,
            };
            off += chunk_bytes;
            total_rg_bytes += chunk_bytes;
            meta
        });
        self.file_pos = off;

        self.row_groups.push(RowGroupMeta {
            cols,
            total_byte_size: total_rg_bytes,
            num_rows: n_i64,
            file_offset: rg_file_offset,
        });

        self.uid_plain.clear();
        self.days.clear();
        self.sessions.clear();
        self.events.clear();
        self.revenues.clear();
        self.cat_def_bits.clear();
        self.cat_plain.clear();
        Ok(())
    }

    pub fn close(mut self) -> io::Result<usize> {
        self.flush_row_group()?;

        let mut tb = ThriftBuf::new(2048);
        let mut fm_last = 0u8;
        tb.field_i32(&mut fm_last, 1, 1);

        // schema (field 2, LIST<STRUCT>)
        tb.field(&mut fm_last, 2, CT_LIST);
        tb.list_hdr(CT_STRUCT, 7);
        write_schema_elem(&mut tb, None, None, b"user_daily", Some(6), None, None);
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_BYTE_ARRAY),
            Some(PQ_REP_REQUIRED),
            b"user_id",
            None,
            Some(PQ_CT_UTF8),
            Some(1),
        );
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_INT32),
            Some(PQ_REP_REQUIRED),
            b"day",
            None,
            Some(PQ_CT_DATE),
            Some(6),
        );
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_INT32),
            Some(PQ_REP_REQUIRED),
            b"sessions",
            None,
            None,
            None,
        );
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_INT32),
            Some(PQ_REP_REQUIRED),
            b"events",
            None,
            None,
            None,
        );
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_INT64),
            Some(PQ_REP_REQUIRED),
            b"revenue_cents",
            None,
            None,
            None,
        );
        write_schema_elem(
            &mut tb,
            Some(PQ_TYPE_BYTE_ARRAY),
            Some(PQ_REP_OPTIONAL),
            b"top_category",
            None,
            Some(PQ_CT_UTF8),
            Some(1),
        );

        // num_rows (field 3, I64)
        tb.field_i64(&mut fm_last, 3, self.total_rows as i64);

        // row_groups (field 4, LIST<STRUCT>)
        tb.field(&mut fm_last, 4, CT_LIST);
        tb.list_hdr(CT_STRUCT, self.row_groups.len());
        for rg in &self.row_groups {
            let mut rg_last = 0u8;
            tb.field(&mut rg_last, 1, CT_LIST);
            tb.list_hdr(CT_STRUCT, rg.cols.len());
            for c in &rg.cols {
                let mut cc_last = 0u8;
                tb.field_i64(&mut cc_last, 2, c.data_page_offset);
                tb.field(&mut cc_last, 3, CT_STRUCT);
                let mut cm_last = 0u8;
                tb.field_i32(&mut cm_last, 1, c.pq_type);
                tb.field(&mut cm_last, 2, CT_LIST);
                tb.list_hdr(CT_I32, 2);
                tb.i32_zigzag(PQ_ENC_PLAIN);
                tb.i32_zigzag(PQ_ENC_RLE);
                tb.field(&mut cm_last, 3, CT_LIST);
                tb.list_hdr(CT_BINARY, 1);
                tb.uvarint(c.name.len() as u64);
                tb.0.extend_from_slice(c.name);
                tb.field_i32(&mut cm_last, 4, PQ_CODEC_UNCOMPRESSED);
                tb.field_i64(&mut cm_last, 5, c.num_values);
                tb.field_i64(&mut cm_last, 6, c.total_size);
                tb.field_i64(&mut cm_last, 7, c.total_size);
                tb.field_i64(&mut cm_last, 9, c.data_page_offset);
                tb.stop(); // ColumnMetaData
                tb.stop(); // ColumnChunk
            }
            tb.field_i64(&mut rg_last, 2, rg.total_byte_size);
            tb.field_i64(&mut rg_last, 3, rg.num_rows);
            tb.field_i64(&mut rg_last, 5, rg.file_offset);
            tb.field_i64(&mut rg_last, 6, rg.total_byte_size);
            tb.stop(); // RowGroup
        }

        // created_by (field 6, STRING)
        tb.field_str(&mut fm_last, 6, b"shopping-sessions");
        tb.stop(); // FileMetaData

        let footer_len = (tb.0.len() as u32).to_le_bytes();
        let footer_slices: [&[u8]; 3] = [&tb.0, &footer_len, b"PAR1"];
        write_all_slices(&mut self.file, &footer_slices)?;
        Ok(self.total_rows)
    }
}

pub struct CampaignRow<'a> {
    pub campaign_id: &'a [u8],
    pub channel: &'a [u8],
    pub day: i32,
    pub sessions: i64,
    pub purchasing_sessions: i64,
    pub revenue_cents: i64,
    pub assisted_sessions: i64,
}

pub fn write_campaign_daily(
    path: &Path,
    rows: &[CampaignRow<'_>],
    compression: Compression,
) -> io::Result<()> {
    let schema = Arc::new(
        parse_message_type(CAMPAIGN_DAILY_SCHEMA)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
    );
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(compression)
            .set_statistics_enabled(EnabledStatistics::None)
            .build(),
    );
    let file = BufWriter::with_capacity(256 * 1024, File::create(path)?);
    let mut writer = SerializedFileWriter::new(file, schema, props)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    if !rows.is_empty() {
        let mut camp_ids = Vec::with_capacity(rows.len());
        let mut channels = Vec::with_capacity(rows.len());
        let mut days = Vec::with_capacity(rows.len());
        let mut sessions = Vec::with_capacity(rows.len());
        let mut purch = Vec::with_capacity(rows.len());
        let mut rev = Vec::with_capacity(rows.len());
        let mut assists = Vec::with_capacity(rows.len());
        for r in rows {
            camp_ids.push(ByteArray::from(r.campaign_id));
            channels.push(ByteArray::from(r.channel));
            days.push(r.day);
            sessions.push(r.sessions);
            purch.push(r.purchasing_sessions);
            rev.push(r.revenue_cents);
            assists.push(r.assisted_sessions);
        }

        let mut rg = writer
            .next_row_group()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let mut col_idx = 0usize;
        while let Some(mut col) = rg
            .next_column()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        {
            match (col_idx, col.untyped()) {
                (0, ColumnWriter::ByteArrayColumnWriter(w)) => {
                    w.write_batch(&camp_ids, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (1, ColumnWriter::ByteArrayColumnWriter(w)) => {
                    w.write_batch(&channels, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (2, ColumnWriter::Int32ColumnWriter(w)) => {
                    w.write_batch(&days, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (3, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&sessions, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (4, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&purch, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (5, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&rev, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (6, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&assists, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                _ => unreachable!("unexpected campaign_daily column index {col_idx}"),
            }
            col.close()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            col_idx += 1;
        }
        rg.close()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    writer
        .close()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use parquet::record::{Field, RowAccessor};

    #[test]
    fn test_direct_user_daily_writer_roundtrip_and_boundaries() {
        let dir = std::env::temp_dir().join("ss_test_direct_pq_v1");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let cats: Vec<Box<[u8]>> = vec![b"books".to_vec().into_boxed_slice(), b"shoes".to_vec().into_boxed_slice()];

        let check_case = |name: &str,
                          n: usize,
                          batch: usize,
                          mode: u8,
                          wide_rev: bool| {
            let p = dir.join(format!("{name}.parquet"));
            let mut w = UserDailyWriter::create(&p, batch, &cats, Compression::UNCOMPRESSED).unwrap();
            let mut expected = Vec::with_capacity(n);
            for i in 0..n {
                let uid = format!("user_{i}");
                let day = 20_000 + (i as i32 % 14);
                let sess = (i as i64 % 5) + 1;
                let evs = sess * 3;
                let rev = if wide_rev && i == 0 {
                    3_000_000_000i64
                } else if mode == 1 {
                    0
                } else {
                    (i as i64) * 100
                };
                let cat = match mode {
                    1 => None,
                    2 => Some((i % 2) as u32),
                    _ => {
                        if i % 3 == 0 {
                            None
                        } else {
                            Some((i % 2) as u32)
                        }
                    }
                };
                w.push(uid.as_bytes(), day, sess, evs, rev, cat).unwrap();
                expected.push((
                    uid,
                    day,
                    sess as i32,
                    evs as i32,
                    rev,
                    cat.map(|c| String::from_utf8(cats[c as usize].to_vec()).unwrap()),
                ));
            }
            assert_eq!(w.close().unwrap(), n);

            let rdr = SerializedFileReader::new(File::open(&p).unwrap()).unwrap();
            assert_eq!(rdr.metadata().file_metadata().num_rows(), n as i64);
            let mut got = Vec::new();
            for r in rdr.get_row_iter(None).unwrap() {
                let r = r.unwrap();
                let day_val = match r.get_column_iter().nth(1).unwrap().1 {
                    Field::Date(d) => *d,
                    other => panic!("expected Date, got {other:?}"),
                };
                let top = match r.get_string(5) {
                    Ok(s) => Some(s.clone()),
                    Err(_) => None,
                };
                got.push((
                    r.get_string(0).unwrap().clone(),
                    day_val,
                    r.get_int(2).unwrap(),
                    r.get_int(3).unwrap(),
                    r.get_long(4).unwrap(),
                    top,
                ));
            }
            assert_eq!(got, expected, "mismatch on {name} n={n}");
        };

        check_case("c0", 0, 100, 0, false);
        check_case("c1_null", 1, 100, 1, true);
        check_case("c7", 7, 100, 0, false);
        check_case("c8", 8, 100, 2, false);
        check_case("c9", 9, 100, 0, false);
        check_case("c504", 504, 1000, 0, false);
        check_case("c505", 505, 1000, 0, false);
        check_case("c2000_all_null", 2000, 300, 1, false);
        check_case("c2000_all_nonnull", 2000, 300, 2, false);
        check_case("c2000_mixed_wide", 2000, 350, 0, true);

        let _ = fs::remove_dir_all(&dir);
    }
}
