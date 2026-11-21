use std::cmp::Ordering;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use memchr::{memchr, memrchr};

#[cfg(unix)]
pub(crate) mod sys_mmap {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::raw::c_int;
    use std::os::unix::io::AsRawFd;

    const PROT_READ: c_int = 1;
    const MAP_PRIVATE: c_int = 2;
    const MAP_FAILED: *mut c_void = !0usize as *mut c_void;
    const MADV_SEQUENTIAL: c_int = 2;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const MADV_HUGEPAGE: c_int = 14;

    extern "C" {
        fn mmap(
            addr: *mut c_void,
            length: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        fn munmap(addr: *mut c_void, length: usize) -> c_int;
        fn madvise(addr: *mut c_void, length: usize, advice: c_int) -> c_int;
    }

    pub(crate) struct MmapRegion {
        ptr: *mut u8,
        len: usize,
    }

    unsafe impl Send for MmapRegion {}
    unsafe impl Sync for MmapRegion {}

    impl MmapRegion {
        pub(crate) fn map_file(file: &File, len: usize) -> io::Result<Option<Self>> {
            if len == 0 {
                return Ok(None);
            }
            let ptr = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    len,
                    PROT_READ,
                    MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                )
            };
            if ptr == MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            unsafe {
                let _ = madvise(ptr, len, MADV_SEQUENTIAL);
                if len >= 2 * 1024 * 1024 {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    let _ = madvise(ptr, len, MADV_HUGEPAGE);
                }
            }
            Ok(Some(Self {
                ptr: ptr as *mut u8,
                len,
            }))
        }

        #[inline(always)]
        pub(crate) fn as_slice(&self) -> &[u8] {
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    impl Drop for MmapRegion {
        fn drop(&mut self) {
            if self.len > 0 && !self.ptr.is_null() {
                unsafe {
                    let _ = munmap(self.ptr as *mut c_void, self.len);
                }
            }
        }
    }
}

pub const CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const READ_BLOCK_BYTES: usize = 256 * 1024;

pub const LONG_LEN_OVERFLOW: usize = 0xF_FFFF;
pub const LONG_LEN_MASK: u64 = 0xF_FFFF;
pub const LONG_OFF_MASK: u64 = (1u64 << 37) - 1;

#[inline(always)]
pub const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[inline(always)]
fn pext7(tail_be: u64) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    unsafe {
        std::arch::x86_64::_pext_u64(tail_be, 0x7F7F_7F7F_7F7F_7F7F)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "bmi2")))]
    {
        let mut x = tail_be & 0x7F7F_7F7F_7F7F_7F7F;
        x = ((x & 0x7F00_7F00_7F00_7F00) >> 1) | (x & 0x007F_007F_007F_007F);
        x = ((x & 0x3FFF_0000_3FFF_0000) >> 2) | (x & 0x0000_3FFF_0000_3FFF);
        ((x & 0x0FFF_FFFF_0000_0000) >> 4) | (x & 0x0000_0000_0FFF_FFFF)
    }
}

#[inline(always)]
fn pdep7(packed: u64) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    unsafe {
        std::arch::x86_64::_pdep_u64(packed, 0x7F7F_7F7F_7F7F_7F7F)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "bmi2")))]
    {
        let mut x = packed & 0x00FF_FFFF_FFFF_FFFF;
        x = ((x & 0x00FF_FFFF_F000_0000) << 4) | (x & 0x0000_0000_0FFF_FFFF);
        x = ((x & 0x0FFF_C000_0FFF_C000) << 2) | (x & 0x0000_3FFF_0000_3FFF);
        ((x & 0x3F80_3F80_3F80_3F80) << 1) | (x & 0x007F_007F_007F_007F)
    }
}

#[inline(always)]
pub fn hash_bytes_fast(mut b: &[u8]) -> u64 {
    const K1: u64 = 0xA076_1D64_78BD_642F;
    const K2: u64 = 0xE703_7ED1_A0B4_28DB;
    const K3: u64 = 0x8EBC_6AF0_9C88_C6E3;
    let len = b.len() as u64;
    let mut seed = K1 ^ len.wrapping_mul(K2);
    while b.len() >= 8 {
        let v = u64::from_le_bytes(b[..8].try_into().unwrap());
        let p = ((seed ^ v) as u128).wrapping_mul((seed ^ K3) as u128);
        seed = (p as u64) ^ ((p >> 64) as u64);
        b = &b[8..];
    }
    if !b.is_empty() {
        let mut buf = [0u8; 8];
        buf[..b.len()].copy_from_slice(b);
        seed ^= u64::from_le_bytes(buf);
    }
    mix64(seed ^ K2)
}

/// 64-bit compact identifier (never 0 when valid):
/// - `0`: `EMPTY` sentinel
/// - `1 ..= u32::MAX + 1` (`(val >> 56) == 0 && val != 0`): linked `comp_id + 1`
/// - `(1u64 << 56) ..= 0x7FFF_FFFF_FFFF_FFFF` (`bit 63 == 0` and `(val >> 56) != 0`):
///   lossless 1..=9 byte non-NUL ASCII string (`s[0]` in bits `62..56`, `pext7(s[1..])` BE in `55..0`)
/// - `bit 63 == 1`: arena ref `(1 << 63) | (wid:6 << 57) | (off:37 << 20) | (len:20)`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CompactKey64(pub u64);

const _: () = assert!(std::mem::size_of::<CompactKey64>() == 8);

impl CompactKey64 {
    pub const EMPTY: Self = Self(0);

    #[inline(always)]
    pub const fn from_comp(comp_id: u32) -> Self {
        Self((comp_id as u64) + 1)
    }

    #[inline(always)]
    pub const fn is_comp(self) -> bool {
        (self.0 >> 56) == 0 && self.0 != 0
    }

    #[inline(always)]
    pub const fn comp_id(self) -> u32 {
        (self.0 - 1) as u32
    }

    #[inline(always)]
    pub const fn is_inline(self) -> bool {
        (self.0 as i64) >= (1i64 << 56)
    }

    #[inline(always)]
    pub const fn is_ref(self) -> bool {
        (self.0 as i64) < 0
    }

    #[inline(always)]
    pub fn encode_raw_inline(s: &[u8]) -> Option<Self> {
        let n = s.len();
        if n == 9 {
            let b0 = unsafe { *s.get_unchecked(0) };
            let tail = unsafe { u64::from_be_bytes(*(s.as_ptr().add(1) as *const [u8; 8])) };
            if b0.wrapping_sub(1) > 126
                || ((tail | tail.wrapping_sub(0x0101_0101_0101_0101)) & 0x8080_8080_8080_8080)
                    != 0
            {
                return None;
            }
            return Some(Self(((b0 as u64) << 56) | pext7(tail)));
        }
        if n == 8 {
            let w = unsafe { u64::from_be_bytes(*(s.as_ptr() as *const [u8; 8])) };
            if ((w | w.wrapping_sub(0x0101_0101_0101_0101)) & 0x8080_8080_8080_8080) != 0 {
                return None;
            }
            return Some(Self((w & 0xFF00_0000_0000_0000) | pext7(w << 8)));
        }
        if n >= 1 && n <= 7 {
            let mut buf = [0u8; 8];
            unsafe {
                std::ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr(), n);
            }
            let w = u64::from_be_bytes(buf);
            let mask = !0u64 << ((8 - n) * 8);
            let w_check = w | (!mask & 0x0101_0101_0101_0101);
            if ((w_check | w_check.wrapping_sub(0x0101_0101_0101_0101)) & 0x8080_8080_8080_8080)
                != 0
            {
                return None;
            }
            return Some(Self((w & 0xFF00_0000_0000_0000) | pext7(w << 8)));
        }
        None
    }

    #[inline(always)]
    pub fn encode_raw_inline_padded(padded: &[u8], start: usize, len: usize) -> Option<Self> {
        debug_assert!(padded.len() >= start + 16);
        let ptr = unsafe { padded.as_ptr().add(start) };
        if len.wrapping_sub(2) <= 7 {
            let b0 = unsafe { *ptr };
            let tail_raw = unsafe { u64::from_be_bytes(*(ptr.add(1) as *const [u8; 8])) };
            let mask = !0u64 << ((9 - len) * 8);
            let tail = tail_raw & mask;
            let tail_check = tail | (!mask & 0x0101_0101_0101_0101);
            if b0.wrapping_sub(1) > 126
                || ((tail_check | tail_check.wrapping_sub(0x0101_0101_0101_0101))
                    & 0x8080_8080_8080_8080)
                    != 0
            {
                return None;
            }
            return Some(Self(((b0 as u64) << 56) | pext7(tail)));
        }
        if len == 1 {
            let b0 = unsafe { *ptr };
            if b0.wrapping_sub(1) > 126 {
                return None;
            }
            return Some(Self((b0 as u64) << 56));
        }
        None
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn encode_raw(s: &[u8], wid: usize, arena: &mut LongArena) -> Self {
        match Self::encode_raw_inline(s) {
            Some(k) => k,
            None => arena.push_ref(wid, s),
        }
    }

    #[inline(always)]
    pub fn decode_inline(self, buf: &mut [u8; 10]) -> usize {
        debug_assert!(self.is_inline());
        buf[0] = (self.0 >> 56) as u8;
        let tail_be = pdep7(self.0);
        buf[1..9].copy_from_slice(&tail_be.to_be_bytes());
        9 - ((tail_be.trailing_zeros() >> 3) as usize)
    }
}

#[derive(Default)]
pub struct LongArena {
    pub buf: Vec<u8>,
    pub overflow: Vec<Box<[u8]>>,
}

impl LongArena {
    #[inline(always)]
    pub fn push_ref(&mut self, wid: usize, s: &[u8]) -> CompactKey64 {
        debug_assert!(wid < 64);
        if s.len() < LONG_LEN_OVERFLOW && self.buf.len() + s.len() <= (1usize << 37) {
            let off = self.buf.len();
            self.buf.extend_from_slice(s);
            CompactKey64(
                (1u64 << 63) | ((wid as u64) << 57) | ((off as u64) << 20) | (s.len() as u64),
            )
        } else {
            let idx = self.overflow.len();
            self.overflow.push(s.to_vec().into_boxed_slice());
            CompactKey64(
                (1u64 << 63)
                    | ((wid as u64) << 57)
                    | ((idx as u64) << 20)
                    | (LONG_LEN_OVERFLOW as u64),
            )
        }
    }

    #[inline(always)]
    pub fn resolve_in<'a>(arenas: &'a [LongArena], key: CompactKey64) -> &'a [u8] {
        debug_assert!(key.is_ref());
        let wid = ((key.0 >> 57) & 63) as usize;
        let off = ((key.0 >> 20) & LONG_OFF_MASK) as usize;
        let len = (key.0 & LONG_LEN_MASK) as usize;
        let arena = &arenas[wid];
        if len != LONG_LEN_OVERFLOW {
            &arena.buf[off..off + len]
        } else {
            &arena.overflow[off]
        }
    }
}

#[inline(always)]
pub fn resolve_raw_key<'a>(
    key: CompactKey64,
    arenas: &'a [LongArena],
    scratch: &'a mut [u8; 10],
) -> &'a [u8] {
    if key.is_ref() {
        LongArena::resolve_in(arenas, key)
    } else {
        let len = key.decode_inline(scratch);
        &scratch[..len]
    }
}

#[inline(always)]
pub fn cmp_raw_keys(
    a: CompactKey64,
    b: CompactKey64,
    arenas_a: &[LongArena],
    arenas_b: &[LongArena],
) -> Ordering {
    if a.is_inline() && b.is_inline() {
        return a.0.cmp(&b.0);
    }
    let mut ba = [0u8; 10];
    let mut bb = [0u8; 10];
    let sa = resolve_raw_key(a, arenas_a, &mut ba);
    let sb = resolve_raw_key(b, arenas_b, &mut bb);
    sa.cmp(sb)
}

#[inline(always)]
pub fn hash_raw_key(k: CompactKey64, arenas: &[LongArena]) -> u64 {
    if !k.is_ref() {
        mix64(k.0)
    } else {
        hash_bytes_fast(LongArena::resolve_in(arenas, k))
    }
}

#[inline(always)]
fn emit_line_if_valid<const K: usize>(
    data: &[u8],
    line_start: usize,
    line_end: usize,
    commas: &[usize; K],
    n_commas: usize,
    total_quotes: u32,
    non_ascii: u32,
    f: &mut impl FnMut([&[u8]; K]),
) {
    if line_end <= line_start || n_commas != K - 1 {
        return;
    }
    if non_ascii != 0 && std::str::from_utf8(&data[line_start..line_end]).is_err() {
        return;
    }
    let mut fields: [&[u8]; K] = [&[]; K];
    let mut prev = line_start;
    let mut expected_quotes = 0u32;
    let mut i = 0usize;
    while i < K {
        let end = if i < K - 1 { commas[i] } else { line_end };
        let len = end - prev;
        let is_q = if len >= 2 {
            usize::from((data[prev] == b'"') & (data[end - 1] == b'"'))
        } else {
            0
        };
        fields[i] = &data[prev + is_q..end - is_q];
        expected_quotes += (is_q as u32) << 1;
        prev = end + 1;
        i += 1;
    }
    if expected_quotes != total_quotes {
        return;
    }
    f(fields);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn scan_avx2_step<const K: usize>(
    data: &[u8],
    p: usize,
    mut nl_mask: u32,
    mut cm_mask: u32,
    mut qt_mask: u32,
    mut na_mask: u32,
    line_start: &mut usize,
    commas: &mut [usize; K],
    n_commas: &mut usize,
    total_quotes: &mut u32,
    non_ascii: &mut u32,
    f: &mut impl FnMut([&[u8]; K]),
) {
    while nl_mask != 0 {
        let nl_bit = nl_mask.trailing_zeros();
        let line_end = p + nl_bit as usize;
        let before_nl = (1u32 << nl_bit) - 1;
        let mut line_cm = cm_mask & before_nl;
        while line_cm != 0 {
            let cbit = line_cm.trailing_zeros() as usize;
            if *n_commas < K - 1 {
                commas[*n_commas] = p + cbit;
            }
            *n_commas += 1;
            line_cm &= line_cm - 1;
        }
        *total_quotes += (qt_mask & before_nl).count_ones();
        *non_ascii |= na_mask & before_nl;

        emit_line_if_valid::<K>(
            data,
            *line_start,
            line_end,
            commas,
            *n_commas,
            *total_quotes,
            *non_ascii,
            f,
        );

        *line_start = line_end + 1;
        *n_commas = 0;
        *total_quotes = 0;
        *non_ascii = 0;

        let keep_after = ((!0u64) << (nl_bit + 1)) as u32;
        nl_mask &= keep_after;
        cm_mask &= keep_after;
        qt_mask &= keep_after;
        na_mask &= keep_after;
    }

    while cm_mask != 0 {
        let cbit = cm_mask.trailing_zeros() as usize;
        if *n_commas < K - 1 {
            commas[*n_commas] = p + cbit;
        }
        *n_commas += 1;
        cm_mask &= cm_mask - 1;
    }
    *total_quotes += qt_mask.count_ones();
    *non_ascii |= na_mask;
}

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
pub fn for_each_line_fields_padded<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut f: impl FnMut([&[u8]; K]),
) {
    assert!(K >= 2);
    assert!(padded_buf.len() >= valid_len + 32);
    if valid_len == 0 {
        return;
    }
    let data = &padded_buf[..valid_len];
    let mut line_start = 0usize;
    let mut commas = [0usize; K];
    let mut n_commas = 0usize;
    let mut total_quotes = 0u32;
    let mut non_ascii = 0u32;
    let mut p = 0usize;

    unsafe {
        use std::arch::x86_64::*;
        let v_nl = _mm256_set1_epi8(b'\n' as i8);
        let v_cm = _mm256_set1_epi8(b',' as i8);
        let v_qt = _mm256_set1_epi8(b'"' as i8);
        let base = padded_buf.as_ptr();

        while p + 32 <= valid_len {
            let v = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let nl_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_nl)) as u32;
            let cm_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_cm)) as u32;
            let qt_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_qt)) as u32;
            let na_mask = _mm256_movemask_epi8(v) as u32;
            scan_avx2_step::<K>(
                data,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut commas,
                &mut n_commas,
                &mut total_quotes,
                &mut non_ascii,
                &mut f,
            );
            p += 32;
        }

        if p < valid_len {
            let rem = valid_len - p;
            let valid_mask = (1u32 << rem) - 1;
            let v = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let nl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_nl)) as u32) & valid_mask;
            let cm_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_cm)) as u32) & valid_mask;
            let qt_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_qt)) as u32) & valid_mask;
            let na_mask = (_mm256_movemask_epi8(v) as u32) & valid_mask;
            scan_avx2_step::<K>(
                data,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut commas,
                &mut n_commas,
                &mut total_quotes,
                &mut non_ascii,
                &mut f,
            );
        }
    }

    if line_start < valid_len {
        emit_line_if_valid::<K>(
            data,
            line_start,
            valid_len,
            &commas,
            n_commas,
            total_quotes,
            non_ascii,
            &mut f,
        );
    }
}

#[cfg(all(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
#[inline(always)]
pub fn for_each_line_fields_padded<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    f: impl FnMut([&[u8]; K]),
) {
    for_each_line_fields_slice::<K>(&padded_buf[..valid_len], f);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
pub fn for_each_line_fields_slice<const K: usize>(slice: &[u8], mut f: impl FnMut([&[u8]; K])) {
    assert!(K >= 2);
    let valid_len = slice.len();
    if valid_len == 0 {
        return;
    }
    let mut line_start = 0usize;
    let mut commas = [0usize; K];
    let mut n_commas = 0usize;
    let mut total_quotes = 0u32;
    let mut non_ascii = 0u32;
    let mut p = 0usize;

    unsafe {
        use std::arch::x86_64::*;
        let v_nl = _mm256_set1_epi8(b'\n' as i8);
        let v_cm = _mm256_set1_epi8(b',' as i8);
        let v_qt = _mm256_set1_epi8(b'"' as i8);
        let base = slice.as_ptr();

        while p + 32 <= valid_len {
            let v = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let nl_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_nl)) as u32;
            let cm_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_cm)) as u32;
            let qt_mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_qt)) as u32;
            let na_mask = _mm256_movemask_epi8(v) as u32;
            scan_avx2_step::<K>(
                slice,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut commas,
                &mut n_commas,
                &mut total_quotes,
                &mut non_ascii,
                &mut f,
            );
            p += 32;
        }

        if p < valid_len {
            let rem = valid_len - p;
            let mut tail = [0u8; 32];
            tail[..rem].copy_from_slice(&slice[p..]);
            let valid_mask = (1u32 << rem) - 1;
            let v = _mm256_loadu_si256(tail.as_ptr() as *const __m256i);
            let nl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_nl)) as u32) & valid_mask;
            let cm_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_cm)) as u32) & valid_mask;
            let qt_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, v_qt)) as u32) & valid_mask;
            let na_mask = (_mm256_movemask_epi8(v) as u32) & valid_mask;
            scan_avx2_step::<K>(
                slice,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut commas,
                &mut n_commas,
                &mut total_quotes,
                &mut non_ascii,
                &mut f,
            );
        }
    }

    if line_start < valid_len {
        emit_line_if_valid::<K>(
            slice,
            line_start,
            valid_len,
            &commas,
            n_commas,
            total_quotes,
            non_ascii,
            &mut f,
        );
    }
}

#[derive(Clone, Copy)]
pub struct LineBounds<const K: usize> {
    pub line_start: u32,
    pub commas_and_end: [u32; K],
}

impl<const K: usize> LineBounds<K> {
    #[inline(always)]
    pub fn span(&self, idx: usize) -> (usize, usize) {
        let raw_s = if idx == 0 {
            self.line_start as usize
        } else {
            ((self.commas_and_end[idx - 1] & 0x7FFF_FFFF) as usize) + 1
        };
        let entry = self.commas_and_end[idx];
        let raw_e = (entry & 0x7FFF_FFFF) as usize;
        let q = (entry >> 31) as usize;
        (raw_s + q, raw_e - q)
    }
}

const BATCH_SCAN_FLUSH: usize = 512;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn push_line_bounds_if_valid<const K: usize>(
    padded_buf: &[u8],
    line_start: usize,
    line_end: usize,
    commas_ptr: *const u32,
    n_commas: usize,
    total_quotes: u32,
    non_ascii: u32,
    batch: &mut Vec<LineBounds<K>>,
) {
    if line_end <= line_start || n_commas != K - 1 || (total_quotes & 1) != 0 {
        return;
    }
    if non_ascii != 0 && std::str::from_utf8(&padded_buf[line_start..line_end]).is_err() {
        return;
    }
    if batch.len() == batch.capacity() {
        batch.reserve(65);
    }
    let idx = batch.len();
    let dst = batch.as_mut_ptr().add(idx);
    let ptr = padded_buf.as_ptr();
    (*dst).line_start = line_start as u32;
    let mut prev = line_start;
    let mut expected_quotes = 0u32;
    let mut i = 0usize;
    while i < K {
        let end = if i < K - 1 {
            *commas_ptr.add(i) as usize
        } else {
            line_end
        };
        let last = if end > prev { end - 1 } else { prev };
        let is_q = usize::from(
            (end.wrapping_sub(prev) >= 2)
                & (*ptr.add(prev) == b'"')
                & (*ptr.add(last) == b'"'),
        );
        *(*dst).commas_and_end.get_unchecked_mut(i) = (end as u32) | ((is_q as u32) << 31);
        expected_quotes += (is_q as u32) << 1;
        prev = end + 1;
        i += 1;
    }
    if expected_quotes == total_quotes {
        batch.set_len(idx + 1);
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn scan_step64<const K: usize>(
    padded_buf: &[u8],
    p: usize,
    mut nl_mask: u64,
    cm_mask: u64,
    qt_mask: u64,
    na_mask: u64,
    line_start: &mut usize,
    cm_buf: &mut [u32; 576],
    cm_head: &mut usize,
    cm_tail: &mut usize,
    total_quotes: &mut u32,
    non_ascii: &mut u32,
    batch: &mut Vec<LineBounds<K>>,
) {
    if *cm_tail >= 512 {
        let carry = *cm_tail - *cm_head;
        if carry <= K {
            std::ptr::copy(cm_buf.as_ptr().add(*cm_head), cm_buf.as_mut_ptr(), carry);
            *cm_head = 0;
            *cm_tail = carry;
        } else {
            *cm_head = 0;
            *cm_tail = K + 1;
        }
    }

    let base_tail = *cm_tail;
    let block_cm = cm_mask.count_ones() as usize;
    {
        let mut m = cm_mask;
        let dst = cm_buf.as_mut_ptr().add(base_tail);
        *dst.add(0) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(1) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(2) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(3) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(4) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(5) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(6) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        *dst.add(7) = (p + m.trailing_zeros() as usize) as u32;
        m &= m.wrapping_sub(1);
        if m != 0 {
            let mut i = 8usize;
            while m != 0 {
                *dst.add(i) = (p + m.trailing_zeros() as usize) as u32;
                i += 1;
                m &= m.wrapping_sub(1);
            }
        }
    }

    let mut prev_done = 0u64;
    while nl_mask != 0 {
        let nl_bit = nl_mask.trailing_zeros();
        let line_end = p + nl_bit as usize;
        let nl_flag = 1u64 << nl_bit;
        let before_nl = nl_flag - 1;
        let seg = before_nl & !prev_done;
        let line_cm_end = base_tail + (cm_mask & before_nl).count_ones() as usize;
        let n_commas = line_cm_end - *cm_head;
        *total_quotes += (qt_mask & seg).count_ones();
        *non_ascii |= ((na_mask & seg) != 0) as u32;

        push_line_bounds_if_valid::<K>(
            padded_buf,
            *line_start,
            line_end,
            cm_buf.as_ptr().add(*cm_head),
            n_commas,
            *total_quotes,
            *non_ascii,
            batch,
        );

        *line_start = line_end + 1;
        *cm_head = line_cm_end;
        *total_quotes = 0;
        *non_ascii = 0;
        prev_done = before_nl | nl_flag;
        nl_mask &= nl_mask - 1;
    }

    *cm_tail = base_tail + block_cm;
    let rem = !prev_done;
    *total_quotes += (qt_mask & rem).count_ones();
    *non_ascii |= ((na_mask & rem) != 0) as u32;
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512bw")]
unsafe fn scan_lines_batched_avx512bw<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    batch: &mut Vec<LineBounds<K>>,
    mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    batch.clear();
    if valid_len == 0 {
        return;
    }
    batch.reserve(BATCH_SCAN_FLUSH + 65);
    let mut line_start = 0usize;
    let mut cm_buf = [0u32; 576];
    let mut cm_head = 0usize;
    let mut cm_tail = 0usize;
    let mut total_quotes = 0u32;
    let mut non_ascii = 0u32;
    let mut p = 0usize;

    use std::arch::x86_64::*;
    let v_nl = _mm512_set1_epi8(b'\n' as i8);
    let v_cm = _mm512_set1_epi8(b',' as i8);
    let v_qt = _mm512_set1_epi8(b'"' as i8);
    let base = padded_buf.as_ptr();

    while p + 64 <= valid_len {
        let v = _mm512_loadu_si512(base.add(p).cast());
        let nl_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_nl);
        let cm_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_cm);
        let qt_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_qt);
        let na_mask: u64 = _mm512_movepi8_mask(v);
        scan_step64::<K>(
            padded_buf,
            p,
            nl_mask,
            cm_mask,
            qt_mask,
            na_mask,
            &mut line_start,
            &mut cm_buf,
            &mut cm_head,
            &mut cm_tail,
            &mut total_quotes,
            &mut non_ascii,
            batch,
        );
        if batch.len() >= BATCH_SCAN_FLUSH {
            on_batch(padded_buf, batch);
            batch.clear();
        }
        p += 64;
    }

    if p < valid_len {
        let rem = valid_len - p;
        let valid_mask = (1u64 << rem) - 1;
        let v = _mm512_loadu_si512(base.add(p).cast());
        let nl_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_nl) & valid_mask;
        let cm_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_cm) & valid_mask;
        let qt_mask: u64 = _mm512_cmpeq_epi8_mask(v, v_qt) & valid_mask;
        let na_mask: u64 = _mm512_movepi8_mask(v) & valid_mask;
        scan_step64::<K>(
            padded_buf,
            p,
            nl_mask,
            cm_mask,
            qt_mask,
            na_mask,
            &mut line_start,
            &mut cm_buf,
            &mut cm_head,
            &mut cm_tail,
            &mut total_quotes,
            &mut non_ascii,
            batch,
        );
    }

    if line_start < valid_len {
        push_line_bounds_if_valid::<K>(
            padded_buf,
            line_start,
            valid_len,
            cm_buf.as_ptr().add(cm_head),
            cm_tail - cm_head,
            total_quotes,
            non_ascii,
            batch,
        );
    }
    if !batch.is_empty() {
        on_batch(padded_buf, batch);
        batch.clear();
    }
}

pub fn scan_lines_batched<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    batch: &mut Vec<LineBounds<K>>,
    on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    #[cfg(target_arch = "x86_64")]
    {
        static HAS_AVX512BW: OnceLock<bool> = OnceLock::new();
        if *HAS_AVX512BW.get_or_init(|| std::is_x86_feature_detected!("avx512bw")) {
            unsafe {
                scan_lines_batched_avx512bw::<K>(padded_buf, valid_len, batch, on_batch);
            }
            return;
        }
    }
    scan_lines_batched_avx2::<K>(padded_buf, valid_len, batch, on_batch);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub fn scan_lines_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    batch: &mut Vec<LineBounds<K>>,
    mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    batch.clear();
    if valid_len == 0 {
        return;
    }
    batch.reserve(BATCH_SCAN_FLUSH + 65);
    let mut line_start = 0usize;
    let mut cm_buf = [0u32; 576];
    let mut cm_head = 0usize;
    let mut cm_tail = 0usize;
    let mut total_quotes = 0u32;
    let mut non_ascii = 0u32;
    let mut p = 0usize;

    unsafe {
        use std::arch::x86_64::*;
        let v_nl = _mm256_set1_epi8(b'\n' as i8);
        let v_cm = _mm256_set1_epi8(b',' as i8);
        let v_qt = _mm256_set1_epi8(b'"' as i8);
        let base = padded_buf.as_ptr();

        while p + 64 <= valid_len {
            let v0 = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let v1 = _mm256_loadu_si256(base.add(p + 32) as *const __m256i);
            let nl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_nl)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_nl)) as u32 as u64) << 32);
            let cm_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_cm)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_cm)) as u32 as u64) << 32);
            let qt_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_qt)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_qt)) as u32 as u64) << 32);
            let na_mask = (_mm256_movemask_epi8(v0) as u32 as u64)
                | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32);
            scan_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut total_quotes,
                &mut non_ascii,
                batch,
            );
            if batch.len() >= BATCH_SCAN_FLUSH {
                on_batch(padded_buf, batch);
                batch.clear();
            }
            p += 64;
        }

        if p < valid_len {
            let rem = valid_len - p;
            let valid_mask = (1u64 << rem) - 1;
            let v0 = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let v1 = _mm256_loadu_si256(base.add(p + 32) as *const __m256i);
            let nl_mask = ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_nl)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_nl)) as u32 as u64) << 32))
                & valid_mask;
            let cm_mask = ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_cm)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_cm)) as u32 as u64) << 32))
                & valid_mask;
            let qt_mask = ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_qt)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_qt)) as u32 as u64) << 32))
                & valid_mask;
            let na_mask = ((_mm256_movemask_epi8(v0) as u32 as u64)
                | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32))
                & valid_mask;
            scan_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut total_quotes,
                &mut non_ascii,
                batch,
            );
        }
    }

    if line_start < valid_len {
        unsafe {
            push_line_bounds_if_valid::<K>(
                padded_buf,
                line_start,
                valid_len,
                cm_buf.as_ptr().add(cm_head),
                cm_tail - cm_head,
                total_quotes,
                non_ascii,
                batch,
            );
        }
    }
    if !batch.is_empty() {
        on_batch(padded_buf, batch);
        batch.clear();
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
pub fn scan_lines_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    batch: &mut Vec<LineBounds<K>>,
    mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    batch.clear();
    batch.reserve(BATCH_SCAN_FLUSH);
    let data = &padded_buf[..valid_len];
    let base = padded_buf.as_ptr() as usize;
    for_each_line_fields_slice::<K>(data, |fields| {
        let raw_0 = (fields[0].as_ptr() as usize) - base;
        let line_start = if raw_0 > 0 && padded_buf[raw_0 - 1] == b'"' {
            raw_0 - 1
        } else {
            raw_0
        };
        let mut commas_and_end = [0u32; K];
        for i in 0..K {
            let f_s = (fields[i].as_ptr() as usize) - base;
            let f_e = f_s + fields[i].len();
            let is_q = if i == 0 {
                f_s > line_start
            } else {
                let prev_raw_e = (commas_and_end[i - 1] & 0x7FFF_FFFF) as usize;
                f_s > prev_raw_e + 1
            };
            let raw_e = f_e + usize::from(is_q);
            commas_and_end[i] = (raw_e as u32) | ((is_q as u32) << 31);
        }
        batch.push(LineBounds {
            line_start: line_start as u32,
            commas_and_end,
        });
        if batch.len() >= BATCH_SCAN_FLUSH {
            on_batch(padded_buf, batch);
            batch.clear();
        }
    });
    if !batch.is_empty() {
        on_batch(padded_buf, batch);
        batch.clear();
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
#[inline(always)]
pub fn for_each_line_fields_slice<const K: usize>(slice: &[u8], mut f: impl FnMut([&[u8]; K])) {
    #[inline(always)]
    fn parse_line_scalar<const K: usize>(line: &[u8]) -> Option<[&[u8]; K]> {
        if line.is_empty() || (!line.is_ascii() && std::str::from_utf8(line).is_err()) {
            return None;
        }
        let mut out: [&[u8]; K] = [&[]; K];
        let mut pos = 0usize;
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
        if memchr(b'"', line).is_some() {
            for slot in &mut out {
                if memchr(b'"', slot).is_some() {
                    if slot.len() >= 2 && slot[0] == b'"' && slot[slot.len() - 1] == b'"' {
                        let inner = &slot[1..slot.len() - 1];
                        if memchr(b'"', inner).is_some() {
                            return None;
                        }
                        *slot = inner;
                    } else {
                        return None;
                    }
                }
            }
        }
        Some(out)
    }

    let mut start = 0usize;
    for nl in memchr::memchr_iter(b'\n', slice) {
        if let Some(fields) = parse_line_scalar::<K>(&slice[start..nl]) {
            f(fields);
        }
        start = nl + 1;
    }
    if start < slice.len() {
        if let Some(fields) = parse_line_scalar::<K>(&slice[start..]) {
            f(fields);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ChunkTask {
    pub file_idx: usize,
    pub start: usize,
    pub end: usize,
    pub skip_header: bool,
    pub align_start: bool,
}

pub struct CsvSource {
    files: Vec<File>,
    lens: Vec<usize>,
    mmaps: Vec<Option<sys_mmap::MmapRegion>>,
    total_bytes: usize,
}

#[inline]
fn read_at_full(file: &File, mut dst: &mut [u8], mut offset: u64) -> io::Result<usize> {
    let mut total = 0usize;
    while !dst.is_empty() {
        match file.read_at(dst, offset) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                offset += n as u64;
                dst = &mut dst[n..];
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

impl CsvSource {
    pub fn open(paths: &[PathBuf]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(paths.len());
        let mut lens = Vec::with_capacity(paths.len());
        let mut mmaps = Vec::with_capacity(paths.len());
        let mut total_bytes = 0usize;
        for path in paths {
            let file = File::open(path)?;
            let len = file.metadata()?.len() as usize;
            let region = sys_mmap::MmapRegion::map_file(&file, len)?;
            files.push(file);
            lens.push(len);
            mmaps.push(region);
            total_bytes += len;
        }
        Ok(Self {
            files,
            lens,
            mmaps,
            total_bytes,
        })
    }

    #[inline(always)]
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn chunks(&self, chunk_bytes: usize) -> Vec<ChunkTask> {
        let chunk_bytes = chunk_bytes.max(1);
        let mut out = Vec::new();
        for (file_idx, &len) in self.lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            if len <= chunk_bytes {
                out.push(ChunkTask {
                    file_idx,
                    start: 0,
                    end: len,
                    skip_header: true,
                    align_start: false,
                });
                continue;
            }
            let mut pos = 0usize;
            let mut first = true;
            while pos < len {
                let end = pos.saturating_add(chunk_bytes).min(len);
                out.push(ChunkTask {
                    file_idx,
                    start: pos,
                    end,
                    skip_header: first,
                    align_start: !first,
                });
                first = false;
                pos = end;
            }
        }
        out
    }

    fn for_each_chunk_blocks(
        &self,
        task: ChunkTask,
        buf: &mut Vec<u8>,
        pad: usize,
        mut feed: impl FnMut(&[u8], usize),
    ) -> io::Result<()> {
        let file = &self.files[task.file_idx];
        let file_len = self.lens[task.file_idx];
        if buf.len() < READ_BLOCK_BYTES + pad {
            buf.resize(READ_BLOCK_BYTES + pad, 0);
        }

        let mut offset = task.start as u64;
        let mut carry = 0usize;

        if task.skip_header || task.align_start {
            if task.align_start {
                offset = (task.start as u64) - 1;
            }
            let mut found = false;
            while offset < task.end as u64 {
                let to_read = READ_BLOCK_BYTES.min(task.end - offset as usize);
                if buf.len() < to_read + pad {
                    buf.resize(to_read + pad, 0);
                }
                let n = read_at_full(file, &mut buf[..to_read], offset)?;
                if n == 0 {
                    break;
                }
                offset += n as u64;
                if let Some(nl) = memchr(b'\n', &buf[..n]) {
                    let rem = n - (nl + 1);
                    buf.copy_within(nl + 1..n, 0);
                    carry = rem;
                    found = true;
                    break;
                }
            }
            if !found {
                return Ok(());
            }
        }

        loop {
            if carry > 0 {
                if let Some(last_nl) = memrchr(b'\n', &buf[..carry]) {
                    let process_end = last_nl + 1;
                    feed(buf, process_end);
                    let rem = carry - process_end;
                    buf.copy_within(process_end..carry, 0);
                    carry = rem;
                }
            }
            if offset >= task.end as u64 {
                break;
            }
            let to_read = READ_BLOCK_BYTES.min(task.end - offset as usize);
            if buf.len() < carry + to_read + pad {
                buf.resize((carry + to_read).next_power_of_two() + pad, 0);
            }
            let n = read_at_full(file, &mut buf[carry..carry + to_read], offset)?;
            if n == 0 {
                break;
            }
            offset += n as u64;
            carry += n;
        }

        if carry > 0 {
            if task.end < file_len {
                let mut pos = task.end as u64;
                let mut line_len = carry;
                loop {
                    let step = 65536.min(file_len - pos as usize);
                    if step == 0 {
                        break;
                    }
                    if buf.len() < line_len + step + pad {
                        buf.resize((line_len + step).next_power_of_two() + pad, 0);
                    }
                    let n = read_at_full(file, &mut buf[line_len..line_len + step], pos)?;
                    if n == 0 {
                        break;
                    }
                    pos += n as u64;
                    if let Some(rel_nl) = memchr(b'\n', &buf[line_len..line_len + n]) {
                        line_len += rel_nl + 1;
                        break;
                    }
                    line_len += n;
                }
                if buf.len() < line_len + pad {
                    buf.resize(line_len + pad, 0);
                }
                feed(buf, line_len);
            } else {
                if buf.len() < carry + pad {
                    buf.resize(carry + pad, 0);
                }
                feed(buf, carry);
            }
        }
        Ok(())
    }

    fn for_each_chunk_mmap(
        &self,
        task: ChunkTask,
        region: &sys_mmap::MmapRegion,
        buf: &mut Vec<u8>,
        pad: usize,
        mut feed: impl FnMut(&[u8], usize),
    ) -> io::Result<()> {
        let file_bytes = region.as_slice();
        let file_len = file_bytes.len();
        let mut body_start = task.start;

        if task.skip_header || task.align_start {
            let scan_from = if task.align_start {
                task.start - 1
            } else {
                task.start
            };
            if let Some(nl) = memchr(b'\n', &file_bytes[scan_from..task.end]) {
                body_start = scan_from + nl + 1;
            } else {
                return Ok(());
            }
        }

        if body_start >= task.end {
            return Ok(());
        }

        let body_end = if task.end < file_len && file_bytes[task.end - 1] != b'\n' {
            match memchr(b'\n', &file_bytes[task.end..file_len]) {
                Some(rel_nl) => task.end + rel_nl + 1,
                None => file_len,
            }
        } else {
            task.end
        };

        let safe_eof_cutoff = file_len.saturating_sub(pad);
        let mut pos = body_start;
        while pos < body_end && pos < safe_eof_cutoff {
            let max_end = safe_eof_cutoff.min(body_end).min(pos + (1 << 30));
            let slice_end = if max_end == body_end {
                body_end
            } else if let Some(rel_nl) = memrchr(b'\n', &file_bytes[pos..max_end]) {
                pos + rel_nl + 1
            } else {
                break;
            };
            let valid_len = slice_end - pos;
            if valid_len > 0 {
                feed(&file_bytes[pos..], valid_len);
                pos = slice_end;
            } else {
                break;
            }
        }

        if pos < body_end {
            let rem = body_end - pos;
            if buf.len() < rem + pad {
                buf.resize(rem + pad, 0);
            }
            buf[..rem].copy_from_slice(&file_bytes[pos..body_end]);
            buf[rem..rem + pad].fill(0);
            feed(&buf[..rem + pad], rem);
        }
        Ok(())
    }

    pub fn for_each_chunk_batch<const K: usize>(
        &self,
        task: ChunkTask,
        buf: &mut Vec<u8>,
        batch: &mut Vec<LineBounds<K>>,
        mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
    ) -> io::Result<()> {
        if let Some(Some(region)) = self.mmaps.get(task.file_idx) {
            self.for_each_chunk_mmap(task, region, buf, 64, |padded, valid_len| {
                scan_lines_batched::<K>(padded, valid_len, batch, &mut on_batch);
            })
        } else {
            self.for_each_chunk_blocks(task, buf, 64, |padded, valid_len| {
                scan_lines_batched::<K>(padded, valid_len, batch, &mut on_batch);
            })
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csv_dialect_cr_quotes_malformed() {
        let mut out = Vec::new();
        let samples: &[&[u8]] = &[
            b"e1,u1,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,purchase,p1,900\r\n",
            b"\n",
            b"e2,u1,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,view,p1\n",
            b"e3,u1,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,view,p1,,x\n",
            b" \"u1\",u2,a,b,c,d,e\n",
            b"\"u1\" ,u2,a,b,c,d,e\n",
            b"\"\"u1\",u2,a,b,c,d,e\n",
            b"u1\",u2,a,b,c,d,e\n",
            b"\",u2,a,b,c,d,e\n",
            b"\"e4\",\" u1\",\"\",a,b,c,\"\"\n",
        ];
        let joined: Vec<u8> = samples.concat();
        for_each_line_fields_slice::<7>(&joined, |f| {
            out.push(f.iter().map(|s| s.to_vec()).collect::<Vec<_>>());
        });
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0], b"e1");
        assert_eq!(out[0][6], b"900\r");
        assert_eq!(out[1][0], b"e4");
        assert_eq!(out[1][1], b" u1");
        assert_eq!(out[1][2], b"");
        assert_eq!(out[1][6], b"");
    }

    #[test]
    fn test_avx2_csv_matches_scalar_across_lengths_and_quotes() {
        let mut data = Vec::new();
        let lines: &[&[u8]] = &[
            b"",
            b"a,b",
            b"\"a\",\"b\"",
            b"\"\",\"\"",
            b"a,b,c",
            b"a",
            b"\"a\" ,b",
            b" \"a\",b",
            b"\"\"a\",b",
            b"a\"b,c",
            b"\"a\"b\",c",
            b"a\r,b\r",
            b"\" u1 \",\"p\xc3\xa9\"",
            b"\xff,\xfe",
            b"1234567890123456789012345678901234567890,z",
        ];
        for (idx, line) in lines.iter().enumerate() {
            data.extend_from_slice(line);
            if idx + 1 < lines.len() {
                data.push(b'\n');
            }
        }
        let mut padded = data.clone();
        padded.resize(data.len() + 64, 0);
        let mut padded_rows = Vec::new();
        for_each_line_fields_padded::<2>(&padded, data.len(), |f| {
            padded_rows.push((f[0].to_vec(), f[1].to_vec()));
        });
        let mut spans_rows = Vec::new();
        let mut batch = Vec::new();
        scan_lines_batched_avx2::<2>(&padded, data.len(), &mut batch, |d, lines| {
            for lb in lines {
                let (s0, e0) = lb.span(0);
                let (s1, e1) = lb.span(1);
                spans_rows.push((d[s0..e0].to_vec(), d[s1..e1].to_vec()));
            }
        });
        let mut slice_rows = Vec::new();
        for_each_line_fields_slice::<2>(&data, |f| {
            slice_rows.push((f[0].to_vec(), f[1].to_vec()));
        });
        assert_eq!(padded_rows, slice_rows);
        assert_eq!(spans_rows, slice_rows);
        assert_eq!(
            slice_rows,
            vec![
                (b"a".to_vec(), b"b".to_vec()),
                (b"a".to_vec(), b"b".to_vec()),
                (b"".to_vec(), b"".to_vec()),
                (b"a\r".to_vec(), b"b\r".to_vec()),
                (b" u1 ".to_vec(), b"p\xc3\xa9".to_vec()),
                (
                    b"1234567890123456789012345678901234567890".to_vec(),
                    b"z".to_vec()
                ),
            ]
        );
    }

    #[test]
    fn test_csv_source_chunk_splitting_all_sizes() {
        let dir = std::env::temp_dir().join("ss_test_csv_source_chunks");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let content = b"a,b\n1,2\n3,4\n\n\"5\",6\r\nlong_field_12345678901234567890,abcdef\n7,8";
        let p_normal = dir.join("p0.csv");
        let p_hdr_only = dir.join("p1.csv");
        let p_empty = dir.join("p2.csv");
        fs::write(&p_normal, content).unwrap();
        fs::write(&p_hdr_only, b"a,b\n").unwrap();
        fs::write(&p_empty, b"").unwrap();

        let src = CsvSource::open(&[p_normal, p_hdr_only, p_empty]).unwrap();
        let expected = vec![
            (b"1".to_vec(), b"2".to_vec()),
            (b"3".to_vec(), b"4".to_vec()),
            (b"5".to_vec(), b"6\r".to_vec()),
            (
                b"long_field_12345678901234567890".to_vec(),
                b"abcdef".to_vec(),
            ),
            (b"7".to_vec(), b"8".to_vec()),
        ];

        for chunk_sz in 1..=70 {
            let chunks = src.chunks(chunk_sz);
            let mut got = Vec::new();
            let mut buf = Vec::new();
            let mut batch = Vec::new();
            for task in chunks {
                src.for_each_chunk_batch::<2>(task, &mut buf, &mut batch, |data, lines| {
                    for lb in lines {
                        let (s0, e0) = lb.span(0);
                        let (s1, e1) = lb.span(1);
                        got.push((data[s0..e0].to_vec(), data[s1..e1].to_vec()));
                    }
                })
                .unwrap();
            }
            assert_eq!(got, expected, "mismatch at chunk_sz={chunk_sz}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_batched_avx2_csv_matches_slice_across_boundaries() {
        let mut data = Vec::new();
        let lines: &[&[u8]] = &[
            b"",
            b"a,b",
            b"\"a\",\"b\"",
            b"\"\",\"\"",
            b"a,b,c",
            b" \"a\",b",
            b"\"\"a\",b",
            b"a\r,b\r",
            b"\" u1 \",\"p\xc3\xa9\"",
            b"\xff,\xfe",
            b"123456789012345678901234567890123456789012345678901234567890123,x",
            b"exactly_64_bytes_with_quote_at_boundary_position_here_abcdefghi,\"ok\"",
            b"z,w",
        ];
        for _rep in 0..80 {
            for &line in lines {
                data.extend_from_slice(line);
                data.push(b'\n');
            }
        }
        data.extend_from_slice(b"tail0,tail1");
        let mut padded = data.clone();
        padded.resize(data.len() + 64, 0);
        let mut batched = Vec::new();
        let mut batch = Vec::new();
        scan_lines_batched_avx2::<2>(&padded, data.len(), &mut batch, |d, lines| {
            for lb in lines {
                let (s0, e0) = lb.span(0);
                let (s1, e1) = lb.span(1);
                batched.push((d[s0..e0].to_vec(), d[s1..e1].to_vec()));
            }
        });
        let mut expected = Vec::new();
        for_each_line_fields_slice::<2>(&data, |f| {
            expected.push((f[0].to_vec(), f[1].to_vec()));
        });
        assert_eq!(batched, expected);
    }

    #[test]
    fn test_compact_key64_tags_order_and_arena() {
        let mut arena = LongArena::default();
        let c0 = CompactKey64::from_comp(0);
        assert_ne!(c0, CompactKey64::EMPTY);
        assert!(c0.is_comp());
        assert!(!c0.is_inline());
        assert!(!c0.is_ref());
        assert_eq!(c0.comp_id(), 0);
        let cmax = CompactKey64::from_comp(u32::MAX);
        assert!(cmax.is_comp());
        assert_eq!(cmax.comp_id(), u32::MAX);

        assert!(CompactKey64::encode_raw_inline(b"").is_none());
        assert!(CompactKey64::encode_raw_inline(b"u\x00").is_none());
        assert!(CompactKey64::encode_raw_inline(b"u\x00abcdefg").is_none());
        assert!(CompactKey64::encode_raw_inline(b"12345678\x00").is_none());
        assert!(CompactKey64::encode_raw_inline(b"12345678\x80").is_none());
        assert!(CompactKey64::encode_raw_inline(b"\xff").is_none());
        assert!(CompactKey64::encode_raw_inline(b"1234567890").is_none());

        for case in [
            b"".as_slice(),
            b"u",
            b"u12345",
            b"u1234567",
            b"u12345678",
            b"u\x00abc",
            b"12345678\x80",
            b"\xff",
            b"1234567890",
            b"123456789012",
        ] {
            let mut pad = vec![0xFFu8; 3 + case.len() + 32];
            pad[3..3 + case.len()].copy_from_slice(case);
            assert_eq!(
                CompactKey64::encode_raw_inline_padded(&pad, 3, case.len()),
                CompactKey64::encode_raw_inline(case),
                "padded mismatch for {case:?}"
            );
        }

        let k_empty = CompactKey64::encode_raw(b"", 0, &mut arena);
        assert!(k_empty.is_ref());
        let k_unul = CompactKey64::encode_raw(b"u\x00", 0, &mut arena);
        assert!(k_unul.is_ref());
        let k_u = CompactKey64::encode_raw_inline(b"u").unwrap();
        assert!(k_u.is_inline());

        let mut buf = [0u8; 10];
        let samples: &[&[u8]] = &[
            b"\x01",
            b"!root",
            b"a",
            b"a\t\r12z",
            b"a\t\r12\x7fz",
            b"id_500",
            b"1234567",
            b"u1234567",
            b"u12345678",
            b"~zzzzzzzz",
        ];
        for &s in samples {
            let k = CompactKey64::encode_raw_inline(s).unwrap();
            assert!(k.is_inline());
            assert!(!k.is_comp());
            assert!(!k.is_ref());
            let n = k.decode_inline(&mut buf);
            assert_eq!(&buf[..n], s, "roundtrip failed for {s:?}");
        }

        // Mixed-length 1..=9 non-NUL ASCII lexicographic ordering
        let mut ordered: Vec<&[u8]> = vec![
            b"\x01",
            b"!a",
            b"!root",
            b"0",
            b"00",
            b"00000000",
            b"000000000",
            b"00000001",
            b"AAAAAAAA",
            b"ZZZZZZZZZ",
            b"_",
            b"________",
            b"a",
            b"a\t\r12z",
            b"aa",
            b"u",
            b"u1",
            b"u10",
            b"u1234567",
            b"u12345678",
            b"z",
            b"zzzzzzzzz",
            b"~",
        ];
        ordered.sort();
        for w in ordered.windows(2) {
            let ka = CompactKey64::encode_raw_inline(w[0]).unwrap();
            let kb = CompactKey64::encode_raw_inline(w[1]).unwrap();
            assert_eq!(
                ka.0.cmp(&kb.0),
                w[0].cmp(w[1]),
                "order mismatch for {:?} vs {:?}",
                w[0],
                w[1]
            );
        }

        let k_special = CompactKey64::encode_raw(b"!chain_min", 0, &mut arena);
        assert!(k_special.is_ref());
        let k_long = CompactKey64::encode_raw(b"chain_00000", 0, &mut arena);
        assert!(k_long.is_ref());
        let arenas = [arena];
        assert_eq!(
            cmp_raw_keys(k_special, k_long, &arenas, &arenas),
            Ordering::Less
        );
    }

    #[test]
    fn test_csv_source_mmap_page_boundaries() {
        let dir = std::env::temp_dir().join("ss_test_csv_mmap_boundaries");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let collect_via = |path: &PathBuf, chunk_size: usize, use_mmap: bool| -> Vec<Vec<Vec<u8>>> {
            let src = CsvSource::open(std::slice::from_ref(path)).unwrap();
            let chunks = src.chunks(chunk_size);
            let mut rows = Vec::new();
            let mut buf = Vec::new();
            let mut batch = Vec::new();
            for task in chunks {
                if use_mmap {
                    let region = sys_mmap::MmapRegion::map_file(
                        &src.files[task.file_idx],
                        src.lens[task.file_idx],
                    )
                    .unwrap()
                    .unwrap();
                    src.for_each_chunk_mmap(task, &region, &mut buf, 64, |padded, valid_len| {
                        scan_lines_batched::<2>(padded, valid_len, &mut batch, |d, lines| {
                            for lb in lines {
                                let (s0, e0) = lb.span(0);
                                let (s1, e1) = lb.span(1);
                                rows.push(vec![d[s0..e0].to_vec(), d[s1..e1].to_vec()]);
                            }
                        });
                    })
                    .unwrap();
                } else {
                    src.for_each_chunk_blocks(task, &mut buf, 64, |padded, valid_len| {
                        scan_lines_batched::<2>(padded, valid_len, &mut batch, |d, lines| {
                            for lb in lines {
                                let (s0, e0) = lb.span(0);
                                let (s1, e1) = lb.span(1);
                                rows.push(vec![d[s0..e0].to_vec(), d[s1..e1].to_vec()]);
                            }
                        });
                    })
                    .unwrap();
                }
            }
            rows
        };

        // 1. Tiny files (< 64 bytes), empty, header-only, no trailing newline
        for (idx, content) in [
            b"".as_slice(),
            b"h1,h2\n",
            b"h1,h2",
            b"h1,h2\na,b",
            b"h1,h2\n\"a\",\"b\"\nc,d\n",
        ]
        .iter()
        .enumerate()
        {
            let p = dir.join(format!("tiny_{idx}.csv"));
            fs::write(&p, content).unwrap();
            let pread_rows = collect_via(&p, 7, false);
            if !content.is_empty() {
                let mmap_rows = collect_via(&p, 7, true);
                assert_eq!(mmap_rows, pread_rows, "tiny_{idx} mmap vs pread");
            }
            let src = CsvSource::open(std::slice::from_ref(&p)).unwrap();
            let mut batch_rows = Vec::new();
            let mut buf = Vec::new();
            let mut batch = Vec::new();
            for task in src.chunks(7) {
                src.for_each_chunk_batch::<2>(task, &mut buf, &mut batch, |d, lines| {
                    for lb in lines {
                        let (s0, e0) = lb.span(0);
                        let (s1, e1) = lb.span(1);
                        batch_rows.push(vec![d[s0..e0].to_vec(), d[s1..e1].to_vec()]);
                    }
                })
                .unwrap();
            }
            assert_eq!(batch_rows, pread_rows, "tiny_{idx} default batch");
        }

        // 2. Exact 4096-byte and 8192-byte page-aligned files, with lines straddling EOF-64 and page borders
        for (target_len, trailing_nl) in [(4096usize, true), (4096usize, false), (8192usize, false)]
        {
            let mut data = b"col_a,col_b\n".to_vec();
            let mut row_id = 0usize;
            while data.len() + 30 < target_len {
                let line = format!("key_{row_id:04},\"val_{row_id:04}_pad\"\n");
                data.extend_from_slice(line.as_bytes());
                row_id += 1;
            }
            let rem = target_len - data.len();
            let pad_need = if trailing_nl { rem - 4 } else { rem - 3 };
            data.extend_from_slice(b"z");
            for _ in 0..pad_need {
                data.push(b'x');
            }
            data.extend_from_slice(if trailing_nl { b",y\n" } else { b",y" });
            assert_eq!(data.len(), target_len);

            let p = dir.join(format!("page_{target_len}_{trailing_nl}.csv"));
            fs::write(&p, &data).unwrap();
            for chunk_size in [17usize, 64, 128, 4096, CHUNK_BYTES] {
                let expected = collect_via(&p, chunk_size, false);
                let got = collect_via(&p, chunk_size, true);
                assert_eq!(
                    got, expected,
                    "page boundary mismatch len={target_len} nl={trailing_nl} chunk={chunk_size}"
                );
                assert!(got.len() > 100);
            }
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_lines_batched_edge_cases() {
        // 1. Multiple \n within 64 bytes, \n at byte 63, >600 commas malformed, odd-quote malformed
        let mut data = Vec::new();
        // Many short lines inside 64B (K=2)
        for i in 0..20 {
            data.extend_from_slice(format!("a{i},b{i}\n").as_bytes());
        }
        // Pad so next line ends with \n at exact byte offset 63 mod 64
        let rem = (64 - (data.len() % 64)) % 64;
        if rem != 0 {
            for _ in 0..rem {
                data.push(b'\n');
            }
        }
        assert_eq!(data.len() % 64, 0);
        // 63 payload bytes + \n at byte index 63
        data.extend_from_slice(&[b'x'; 58]);
        data.extend_from_slice(b",yyyy\n");
        assert_eq!(data.len() % 64, 0);
        // Odd quotes (dropped)
        data.extend_from_slice(b"\"a,b\n");
        data.extend_from_slice(b"a\",b\n");
        data.extend_from_slice(b"\"\"\"a,b\n");
        // Malformed line with >600 commas (triggers cm_buf compaction >K drop path)
        for _ in 0..700 {
            data.push(b',');
        }
        data.push(b'\n');
        data.extend_from_slice(b"after700,ok700\n");
        // Another >512 comma line followed by EOF valid line without trailing \n
        for _ in 0..520 {
            data.push(b',');
        }
        data.push(b'\n');
        data.extend_from_slice(b"tail_k1,tail_k2");

        let mut padded = data.clone();
        padded.resize(data.len() + 64, 0);
        let mut got = Vec::new();
        let mut batch = Vec::new();
        scan_lines_batched::<2>(&padded, data.len(), &mut batch, |d, lines| {
            for lb in lines {
                let (s0, e0) = lb.span(0);
                let (s1, e1) = lb.span(1);
                got.push((
                    String::from_utf8_lossy(&d[s0..e0]).into_owned(),
                    String::from_utf8_lossy(&d[s1..e1]).into_owned(),
                ));
            }
        });
        let mut expected = Vec::new();
        for i in 0..20 {
            expected.push((format!("a{i}"), format!("b{i}")));
        }
        expected.push((String::from_utf8(vec![b'x'; 58]).unwrap(), "yyyy".to_string()));
        expected.push(("after700".to_string(), "ok700".to_string()));
        expected.push(("tail_k1".to_string(), "tail_k2".to_string()));
        assert_eq!(got, expected);

        // 2. Also exercise K=7 (events schema) with 8+ commas in a single 64B chunk and multiple lines in 64B
        let mut ev_data = Vec::new();
        ev_data.extend_from_slice(b"e1,u1,t1,i1,view,p1,\n");
        ev_data.extend_from_slice(b"bad,,,,,,,,,,,,,,,,\n");
        ev_data.extend_from_slice(b"e2,u2,t2,i2,cart,p2,10\n");
        ev_data.extend_from_slice(b"\"e3\",\"u3\",t3,i3,purchase,p3,500");
        let mut ev_pad = ev_data.clone();
        ev_pad.resize(ev_data.len() + 64, 0);
        let mut ev_got = Vec::new();
        let mut ev_batch = Vec::new();
        scan_lines_batched::<7>(&ev_pad, ev_data.len(), &mut ev_batch, |d, lines| {
            for lb in lines {
                let (s0, e0) = lb.span(0);
                let (s6, e6) = lb.span(6);
                ev_got.push((
                    String::from_utf8_lossy(&d[s0..e0]).into_owned(),
                    String::from_utf8_lossy(&d[s6..e6]).into_owned(),
                ));
            }
        });
        assert_eq!(
            ev_got,
            vec![
                ("e1".to_string(), "".to_string()),
                ("e2".to_string(), "10".to_string()),
                ("e3".to_string(), "500".to_string()),
            ]
        );
    }
}
