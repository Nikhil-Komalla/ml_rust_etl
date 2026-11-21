use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::sync::Arc;

use parquet::basic::Compression;
use parquet::column::writer::ColumnWriter;
use parquet::data_type::ByteArray;
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use parquet::schema::types::ColumnPath;

const USER_DAILY_SCHEMA: &str = "
message user_daily {
    REQUIRED BINARY user_id (UTF8);
    REQUIRED INT32 day (DATE);
    REQUIRED INT64 sessions;
    REQUIRED INT64 events;
    REQUIRED INT64 revenue_cents;
    OPTIONAL BINARY top_category (UTF8);
}
";

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

pub struct UserDailyWriter {
    writer: SerializedFileWriter<File>,
    user_ids: Vec<ByteArray>,
    days: Vec<i32>,
    sessions: Vec<i64>,
    events: Vec<i64>,
    revenues: Vec<i64>,
    top_cats: Vec<ByteArray>,
    top_cat_defs: Vec<i16>,
    total_rows: usize,
    batch_rows: usize,
}

impl UserDailyWriter {
    pub fn create(path: &Path, batch_rows: usize) -> io::Result<Self> {
        let schema = Arc::new(
            parse_message_type(USER_DAILY_SCHEMA)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        );
        let props = Arc::new(
            WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .set_statistics_enabled(EnabledStatistics::None)
                .set_column_dictionary_enabled(ColumnPath::from("user_id"), false)
                .build(),
        );
        let file = File::create(path)?;
        let writer = SerializedFileWriter::new(file, schema, props)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self {
            writer,
            user_ids: Vec::with_capacity(batch_rows.min(65536)),
            days: Vec::with_capacity(batch_rows.min(65536)),
            sessions: Vec::with_capacity(batch_rows.min(65536)),
            events: Vec::with_capacity(batch_rows.min(65536)),
            revenues: Vec::with_capacity(batch_rows.min(65536)),
            top_cats: Vec::with_capacity(batch_rows.min(65536)),
            top_cat_defs: Vec::with_capacity(batch_rows.min(65536)),
            total_rows: 0,
            batch_rows,
        })
    }

    #[inline]
    pub fn push(
        &mut self,
        user_id: &[u8],
        day: i32,
        sessions: i64,
        events: i64,
        revenue: i64,
        top_category: Option<&[u8]>,
    ) -> io::Result<()> {
        self.user_ids.push(ByteArray::from(user_id));
        self.days.push(day);
        self.sessions.push(sessions);
        self.events.push(events);
        self.revenues.push(revenue);
        if let Some(cat) = top_category {
            self.top_cats.push(ByteArray::from(cat));
            self.top_cat_defs.push(1);
        } else {
            self.top_cat_defs.push(0);
        }
        self.total_rows += 1;
        if self.days.len() >= self.batch_rows {
            self.flush_row_group()?;
        }
        Ok(())
    }

    pub fn flush_row_group(&mut self) -> io::Result<()> {
        if self.days.is_empty() {
            return Ok(());
        }
        let mut rg = self
            .writer
            .next_row_group()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let mut col_idx = 0usize;
        while let Some(mut col) = rg
            .next_column()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        {
            match (col_idx, col.untyped()) {
                (0, ColumnWriter::ByteArrayColumnWriter(w)) => {
                    w.write_batch(&self.user_ids, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (1, ColumnWriter::Int32ColumnWriter(w)) => {
                    w.write_batch(&self.days, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (2, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&self.sessions, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (3, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&self.events, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (4, ColumnWriter::Int64ColumnWriter(w)) => {
                    w.write_batch(&self.revenues, None, None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                (5, ColumnWriter::ByteArrayColumnWriter(w)) => {
                    w.write_batch(&self.top_cats, Some(&self.top_cat_defs), None)
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                }
                _ => unreachable!("unexpected user_daily column index {col_idx}"),
            }
            col.close()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            col_idx += 1;
        }
        rg.close()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        self.user_ids.clear();
        self.days.clear();
        self.sessions.clear();
        self.events.clear();
        self.revenues.clear();
        self.top_cats.clear();
        self.top_cat_defs.clear();
        Ok(())
    }

    pub fn close(mut self) -> io::Result<usize> {
        self.flush_row_group()?;
        let n = self.total_rows;
        self.writer
            .close()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(n)
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

pub fn write_campaign_daily(path: &Path, rows: &[CampaignRow<'_>]) -> io::Result<()> {
    let schema = Arc::new(
        parse_message_type(CAMPAIGN_DAILY_SCHEMA)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
    );
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_statistics_enabled(EnabledStatistics::None)
            .build(),
    );
    let file = File::create(path)?;
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
