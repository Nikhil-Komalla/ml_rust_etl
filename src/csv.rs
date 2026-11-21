use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use memchr::{memchr, memchr_iter};
use memmap2::Mmap;

pub const CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_MMAP_FILES: usize = 65533;
pub const FILE_IDX_ARENA: u16 = 65533;
pub const FILE_IDX_OVERFLOW: u16 = 65534;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SliceRef {
    pub file_idx: u16,
    pub len: u16,
    pub off: u32,
}

const _: () = assert!(std::mem::size_of::<SliceRef>() == 8);

enum FileBacking {
    Mmap(Mmap),
    Bytes(Vec<u8>),
}

impl FileBacking {
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        match self {
            FileBacking::Mmap(m) => m.as_ref(),
            FileBacking::Bytes(v) => v.as_slice(),
        }
    }
}

pub struct FileSet {
    files: Vec<FileBacking>,
}

#[derive(Clone, Copy, Debug)]
pub struct CsvChunk {
    pub file_idx: usize,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct OverflowSpan {
    pub file_idx: usize,
    pub off: usize,
    pub len: usize,
}

impl FileSet {
    pub fn open(paths: &[PathBuf]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let file = File::open(path)?;
            let meta_len = file.metadata()?.len();
            if meta_len == 0 {
                files.push(FileBacking::Bytes(Vec::new()));
                continue;
            }
            // SAFETY: Input files under DATA_DIR are mounted read-only and never mutated during execution.
            match unsafe { Mmap::map(&file) } {
                Ok(mmap) => files.push(FileBacking::Mmap(mmap)),
                Err(_) => files.push(FileBacking::Bytes(fs::read(path)?)),
            }
        }
        Ok(Self { files })
    }

    #[inline(always)]
    pub fn file_bytes(&self, file_idx: usize) -> &[u8] {
        self.files[file_idx].as_bytes()
    }

    #[inline(always)]
    pub fn slice_ptr_range(&self, file_idx: usize, slice: &[u8]) -> usize {
        let base = self.file_bytes(file_idx).as_ptr() as usize;
        slice.as_ptr() as usize - base
    }

    #[inline(always)]
    pub fn make_ref(
        &self,
        file_idx: usize,
        slice: &[u8],
        local_overflow: &mut Vec<OverflowSpan>,
        worker_id: usize,
    ) -> SliceRef {
        let off = self.slice_ptr_range(file_idx, slice);
        let len = slice.len();
        if file_idx < MAX_MMAP_FILES && off <= u32::MAX as usize && len <= u16::MAX as usize {
            SliceRef {
                file_idx: file_idx as u16,
                len: len as u16,
                off: off as u32,
            }
        } else {
            let idx = local_overflow.len();
            debug_assert!(worker_id < 64 && idx < (1 << 26));
            local_overflow.push(OverflowSpan { file_idx, off, len });
            SliceRef {
                file_idx: FILE_IDX_OVERFLOW,
                len: 0,
                off: ((worker_id as u32) << 26) | (idx as u32),
            }
        }
    }

    #[inline(always)]
    pub fn resolve<'a>(
        &'a self,
        r: SliceRef,
        arena: &'a [u8],
        overflow_by_worker: &'a [Vec<OverflowSpan>],
    ) -> &'a [u8] {
        if r.file_idx < FILE_IDX_ARENA {
            let b = self.files[r.file_idx as usize].as_bytes();
            let off = r.off as usize;
            &b[off..off + r.len as usize]
        } else if r.file_idx == FILE_IDX_ARENA {
            let off = r.off as usize;
            &arena[off..off + r.len as usize]
        } else {
            let worker = (r.off >> 26) as usize;
            let idx = (r.off & ((1 << 26) - 1)) as usize;
            let span = overflow_by_worker[worker][idx];
            &self.files[span.file_idx].as_bytes()[span.off..span.off + span.len]
        }
    }

    pub fn chunks(&self, chunk_bytes: usize) -> Vec<CsvChunk> {
        let mut out = Vec::new();
        for (file_idx, backing) in self.files.iter().enumerate() {
            let data = backing.as_bytes();
            let Some(hdr_end) = memchr(b'\n', data) else {
                continue;
            };
            let mut pos = hdr_end + 1;
            while pos < data.len() {
                let mut end = pos.saturating_add(chunk_bytes).min(data.len());
                if end < data.len() {
                    end = match memchr(b'\n', &data[end..]) {
                        Some(nl) => end + nl + 1,
                        None => data.len(),
                    };
                }
                if pos < end {
                    out.push(CsvChunk {
                        file_idx,
                        start: pos,
                        end,
                    });
                }
                pos = end;
            }
        }
        out
    }
}

pub fn list_csv_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("csv") && path.is_file() {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

#[inline(always)]
pub fn unquote_field(f: &[u8]) -> Option<&[u8]> {
    if f.is_empty() {
        return Some(b"");
    }
    if f[0] == b'"' {
        if f.len() < 2 || f[f.len() - 1] != b'"' {
            return None;
        }
        let inner = &f[1..f.len() - 1];
        if memchr(b'"', inner).is_some() {
            return None;
        }
        Some(inner)
    } else if memchr(b'"', f).is_some() {
        None
    } else {
        Some(f)
    }
}

#[inline(always)]
pub fn parse_csv_line<const K: usize>(line: &[u8]) -> Option<[&[u8]; K]> {
    if line.is_empty() {
        return None;
    }
    let has_quote = memchr(b'"', line).is_some();
    let mut out: [&[u8]; K] = [&[]; K];
    let mut pos = 0usize;
    if !has_quote {
        for slot in out.iter_mut().take(K - 1) {
            let c = memchr(b',', &line[pos..])?;
            *slot = &line[pos..pos + c];
            pos += c + 1;
        }
        let last = &line[pos..];
        if memchr(b',', last).is_some() {
            return None;
        }
        out[K - 1] = last;
    } else {
        for slot in out.iter_mut().take(K - 1) {
            let c = memchr(b',', &line[pos..])?;
            *slot = unquote_field(&line[pos..pos + c])?;
            pos += c + 1;
        }
        let last = &line[pos..];
        if memchr(b',', last).is_some() {
            return None;
        }
        out[K - 1] = unquote_field(last)?;
    }
    Some(out)
}

#[inline(always)]
pub fn for_each_line_fields<const K: usize>(chunk: &[u8], mut f: impl FnMut([&[u8]; K])) {
    let mut start = 0usize;
    for nl in memchr_iter(b'\n', chunk) {
        let line = &chunk[start..nl];
        start = nl + 1;
        if let Some(fields) = parse_csv_line::<K>(line) {
            f(fields);
        }
    }
    if start < chunk.len() {
        let line = &chunk[start..];
        if let Some(fields) = parse_csv_line::<K>(line) {
            f(fields);
        }
    }
}

#[inline(always)]
pub fn is_valid_utf8(b: &[u8]) -> bool {
    b.is_ascii() || std::str::from_utf8(b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_dialect_cr_quotes_malformed() {
        // Exact CR preservation inside final field
        let f = parse_csv_line::<7>(b"e1,u1,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,purchase,p1,900\r")
            .unwrap();
        assert_eq!(f[6], b"900\r");

        // Quotes wrap whole fields only
        let f = parse_csv_line::<2>(b"\" u1\",\"\"").unwrap();
        assert_eq!(f[0], b" u1");
        assert_eq!(f[1], b"");

        // Malformed quotes & wrong column count
        assert!(parse_csv_line::<2>(b"").is_none());
        assert!(parse_csv_line::<2>(b"u1").is_none());
        assert!(parse_csv_line::<2>(b"u1,u2,u3").is_none());
        assert!(parse_csv_line::<2>(b" \"u1\",u2").is_none());
        assert!(parse_csv_line::<2>(b"\"u1\" ,u2").is_none());
        assert!(parse_csv_line::<2>(b"\"\"u1\",u2").is_none());
        assert!(parse_csv_line::<2>(b"u1\",u2").is_none());
        assert!(parse_csv_line::<2>(b"\",u2").is_none());
    }

    #[test]
    fn test_chunk_splitting_preserves_every_line() {
        let content = b"a,b\n1,2\n3,4\n\n5,6\r\n7,8";
        let backing = FileBacking::Bytes(content.to_vec());
        let fs = FileSet {
            files: vec![backing],
        };
        let mut collected = Vec::new();
        for ch in fs.chunks(3) {
            let slice = &fs.file_bytes(ch.file_idx)[ch.start..ch.end];
            for_each_line_fields::<2>(slice, |fields| {
                collected.push((fields[0].to_vec(), fields[1].to_vec()));
            });
        }
        assert_eq!(
            collected,
            vec![
                (b"1".to_vec(), b"2".to_vec()),
                (b"3".to_vec(), b"4".to_vec()),
                (b"5".to_vec(), b"6\r".to_vec()),
                (b"7".to_vec(), b"8".to_vec()),
            ]
        );
    }
}
