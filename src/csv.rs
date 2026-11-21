use std::cmp::Ordering;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use memchr::{memchr, memrchr};

pub const CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const READ_BLOCK_BYTES: usize = 256 * 1024;

pub const LONG_LEN_OVERFLOW: usize = 0xF_FFFF;
pub const LONG_LEN_MASK: u64 = 0xF_FFFF;
pub const LONG_OFF_MASK: u64 = (1u64 << 36) - 1;

const fn build_enc6() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut b = b'0';
    while b <= b'9' {
        t[b as usize] = (b - b'0') + 1;
        b += 1;
    }
    let mut b = b'A';
    while b <= b'Z' {
        t[b as usize] = (b - b'A') + 11;
        b += 1;
    }
    t[b'_' as usize] = 37;
    let mut b = b'a';
    while b <= b'z' {
        t[b as usize] = (b - b'a') + 38;
        b += 1;
    }
    t
}

const fn build_dec6() -> [u8; 64] {
    let mut t = [0u8; 64];
    let mut i = 0u8;
    while i < 10 {
        t[(i + 1) as usize] = b'0' + i;
        i += 1;
    }
    let mut i = 0u8;
    while i < 26 {
        t[(i + 11) as usize] = b'A' + i;
        i += 1;
    }
    t[37] = b'_';
    let mut i = 0u8;
    while i < 26 {
        t[(i + 38) as usize] = b'a' + i;
        i += 1;
    }
    t
}

static ENC6: [u8; 256] = build_enc6();
static DEC6: [u8; 64] = build_dec6();

#[inline(always)]
pub const fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
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

/// 64-bit compact identifier with 4 disjoint canonical tags in bits 63..62 (never 0):
/// - `0` (reserved EMPTY sentinel)
/// - Tag `0b00`: linked `comp_id + 1` (1..=u32::MAX+1)
/// - Tag `0b01`: raw UTF-8/bytes up to 7 bytes (`len` in bits 61..59, raw LE bytes in 0..55)
/// - Tag `0b10`: 6-bit ASCII-ordered packed `[0-9A-Z_a-z]` of length 8..=10 (big-endian in 0..59)
/// - Tag `0b11`: arena ref `(wid:6 << 56) | (off:36 << 20) | (len:20)`
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
        (self.0 >> 62) == 0 && self.0 != 0
    }

    #[inline(always)]
    pub const fn comp_id(self) -> u32 {
        (self.0 - 1) as u32
    }

    #[inline(always)]
    pub const fn is_pack10(self) -> bool {
        (self.0 >> 62) == 2
    }

    #[inline(always)]
    pub const fn is_ref(self) -> bool {
        (self.0 >> 62) == 3
    }

    #[inline(always)]
    pub fn encode_raw_inline(s: &[u8]) -> Option<Self> {
        let n = s.len();
        if n <= 7 {
            let mut buf = [0u8; 8];
            buf[..n].copy_from_slice(s);
            let raw = u64::from_le_bytes(buf);
            return Some(Self((1u64 << 62) | ((n as u64) << 59) | raw));
        }
        match n {
            8 => {
                let c0 = ENC6[s[0] as usize];
                let c1 = ENC6[s[1] as usize];
                let c2 = ENC6[s[2] as usize];
                let c3 = ENC6[s[3] as usize];
                let c4 = ENC6[s[4] as usize];
                let c5 = ENC6[s[5] as usize];
                let c6 = ENC6[s[6] as usize];
                let c7 = ENC6[s[7] as usize];
                if ((c0.wrapping_sub(1)
                    | c1.wrapping_sub(1)
                    | c2.wrapping_sub(1)
                    | c3.wrapping_sub(1)
                    | c4.wrapping_sub(1)
                    | c5.wrapping_sub(1)
                    | c6.wrapping_sub(1)
                    | c7.wrapping_sub(1))
                    & 0x80)
                    != 0
                {
                    return None;
                }
                Some(Self(
                    (2u64 << 62)
                        | ((c0 as u64) << 54)
                        | ((c1 as u64) << 48)
                        | ((c2 as u64) << 42)
                        | ((c3 as u64) << 36)
                        | ((c4 as u64) << 30)
                        | ((c5 as u64) << 24)
                        | ((c6 as u64) << 18)
                        | ((c7 as u64) << 12),
                ))
            }
            9 => {
                let c0 = ENC6[s[0] as usize];
                let c1 = ENC6[s[1] as usize];
                let c2 = ENC6[s[2] as usize];
                let c3 = ENC6[s[3] as usize];
                let c4 = ENC6[s[4] as usize];
                let c5 = ENC6[s[5] as usize];
                let c6 = ENC6[s[6] as usize];
                let c7 = ENC6[s[7] as usize];
                let c8 = ENC6[s[8] as usize];
                if ((c0.wrapping_sub(1)
                    | c1.wrapping_sub(1)
                    | c2.wrapping_sub(1)
                    | c3.wrapping_sub(1)
                    | c4.wrapping_sub(1)
                    | c5.wrapping_sub(1)
                    | c6.wrapping_sub(1)
                    | c7.wrapping_sub(1)
                    | c8.wrapping_sub(1))
                    & 0x80)
                    != 0
                {
                    return None;
                }
                Some(Self(
                    (2u64 << 62)
                        | ((c0 as u64) << 54)
                        | ((c1 as u64) << 48)
                        | ((c2 as u64) << 42)
                        | ((c3 as u64) << 36)
                        | ((c4 as u64) << 30)
                        | ((c5 as u64) << 24)
                        | ((c6 as u64) << 18)
                        | ((c7 as u64) << 12)
                        | ((c8 as u64) << 6),
                ))
            }
            10 => {
                let c0 = ENC6[s[0] as usize];
                let c1 = ENC6[s[1] as usize];
                let c2 = ENC6[s[2] as usize];
                let c3 = ENC6[s[3] as usize];
                let c4 = ENC6[s[4] as usize];
                let c5 = ENC6[s[5] as usize];
                let c6 = ENC6[s[6] as usize];
                let c7 = ENC6[s[7] as usize];
                let c8 = ENC6[s[8] as usize];
                let c9 = ENC6[s[9] as usize];
                if ((c0.wrapping_sub(1)
                    | c1.wrapping_sub(1)
                    | c2.wrapping_sub(1)
                    | c3.wrapping_sub(1)
                    | c4.wrapping_sub(1)
                    | c5.wrapping_sub(1)
                    | c6.wrapping_sub(1)
                    | c7.wrapping_sub(1)
                    | c8.wrapping_sub(1)
                    | c9.wrapping_sub(1))
                    & 0x80)
                    != 0
                {
                    return None;
                }
                Some(Self(
                    (2u64 << 62)
                        | ((c0 as u64) << 54)
                        | ((c1 as u64) << 48)
                        | ((c2 as u64) << 42)
                        | ((c3 as u64) << 36)
                        | ((c4 as u64) << 30)
                        | ((c5 as u64) << 24)
                        | ((c6 as u64) << 18)
                        | ((c7 as u64) << 12)
                        | ((c8 as u64) << 6)
                        | (c9 as u64),
                ))
            }
            _ => None,
        }
    }

    #[inline(always)]
    pub fn encode_raw(s: &[u8], wid: usize, arena: &mut LongArena) -> Self {
        match Self::encode_raw_inline(s) {
            Some(k) => k,
            None => arena.push_ref(wid, s),
        }
    }

    #[inline(always)]
    pub fn decode_inline(self, buf: &mut [u8; 10]) -> usize {
        if (self.0 >> 62) == 1 {
            let len = ((self.0 >> 59) & 7) as usize;
            let le = self.0.to_le_bytes();
            buf[..7].copy_from_slice(&le[..7]);
            len
        } else {
            debug_assert!((self.0 >> 62) == 2);
            let mut i = 0usize;
            while i < 10 {
                let c = ((self.0 >> (54 - 6 * i)) & 63) as usize;
                if c == 0 {
                    return i;
                }
                buf[i] = DEC6[c];
                i += 1;
            }
            10
        }
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
        if s.len() < LONG_LEN_OVERFLOW && self.buf.len() + s.len() <= (1usize << 36) {
            let off = self.buf.len();
            self.buf.extend_from_slice(s);
            CompactKey64(
                (3u64 << 62) | ((wid as u64) << 56) | ((off as u64) << 20) | (s.len() as u64),
            )
        } else {
            let idx = self.overflow.len();
            self.overflow.push(s.to_vec().into_boxed_slice());
            CompactKey64(
                (3u64 << 62)
                    | ((wid as u64) << 56)
                    | ((idx as u64) << 20)
                    | (LONG_LEN_OVERFLOW as u64),
            )
        }
    }

    #[inline(always)]
    pub fn resolve_in<'a>(arenas: &'a [LongArena], key: CompactKey64) -> &'a [u8] {
        debug_assert!(key.is_ref());
        let wid = ((key.0 >> 56) & 63) as usize;
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
    if a.is_pack10() && b.is_pack10() {
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

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
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

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
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
        let mut total_bytes = 0usize;
        for path in paths {
            let file = File::open(path)?;
            let len = file.metadata()?.len() as usize;
            files.push(file);
            lens.push(len);
            total_bytes += len;
        }
        Ok(Self {
            files,
            lens,
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

    pub fn for_each_chunk_line<const K: usize>(
        &self,
        task: ChunkTask,
        buf: &mut Vec<u8>,
        mut f: impl FnMut([&[u8]; K]),
    ) -> io::Result<()> {
        let file = &self.files[task.file_idx];
        let file_len = self.lens[task.file_idx];
        if buf.len() < READ_BLOCK_BYTES + 32 {
            buf.resize(READ_BLOCK_BYTES + 32, 0);
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
                if buf.len() < to_read + 32 {
                    buf.resize(to_read + 32, 0);
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
                    for_each_line_fields_padded::<K>(buf, process_end, &mut f);
                    let rem = carry - process_end;
                    buf.copy_within(process_end..carry, 0);
                    carry = rem;
                }
            }
            if offset >= task.end as u64 {
                break;
            }
            let to_read = READ_BLOCK_BYTES.min(task.end - offset as usize);
            if buf.len() < carry + to_read + 32 {
                buf.resize((carry + to_read).next_power_of_two() + 32, 0);
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
                    if buf.len() < line_len + step + 32 {
                        buf.resize((line_len + step).next_power_of_two() + 32, 0);
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
                if buf.len() < line_len + 32 {
                    buf.resize(line_len + 32, 0);
                }
                for_each_line_fields_padded::<K>(buf, line_len, &mut f);
            } else {
                if buf.len() < carry + 32 {
                    buf.resize(carry + 32, 0);
                }
                for_each_line_fields_padded::<K>(buf, carry, &mut f);
            }
        }
        Ok(())
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
        padded.resize(data.len() + 32, 0);
        let mut padded_rows = Vec::new();
        for_each_line_fields_padded::<2>(&padded, data.len(), |f| {
            padded_rows.push((f[0].to_vec(), f[1].to_vec()));
        });
        let mut slice_rows = Vec::new();
        for_each_line_fields_slice::<2>(&data, |f| {
            slice_rows.push((f[0].to_vec(), f[1].to_vec()));
        });
        assert_eq!(padded_rows, slice_rows);
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
            for task in chunks {
                src.for_each_chunk_line::<2>(task, &mut buf, |f| {
                    got.push((f[0].to_vec(), f[1].to_vec()));
                })
                .unwrap();
            }
            assert_eq!(got, expected, "mismatch at chunk_sz={chunk_sz}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_compact_key64_tags_order_and_arena() {
        let mut arena = LongArena::default();
        let c0 = CompactKey64::from_comp(0);
        assert_ne!(c0, CompactKey64::EMPTY);
        assert!(c0.is_comp());
        assert_eq!(c0.comp_id(), 0);

        let k_empty = CompactKey64::encode_raw_inline(b"").unwrap();
        let k_u = CompactKey64::encode_raw_inline(b"u").unwrap();
        let k_unul = CompactKey64::encode_raw_inline(b"u\x00").unwrap();
        let k_7 = CompactKey64::encode_raw_inline(b"a\t\r12\xffz").unwrap();
        assert_ne!(k_u, k_unul);
        assert_ne!(k_empty, CompactKey64::EMPTY);
        let mut buf = [0u8; 10];
        let n7 = k_7.decode_inline(&mut buf);
        assert_eq!(&buf[..n7], b"a\t\r12\xffz");
        let nunul = k_unul.decode_inline(&mut buf);
        assert_eq!(&buf[..nunul], b"u\x00");

        let ordered = [
            b"00000000".as_slice(),
            b"000000000",
            b"0000000000",
            b"00000001",
            b"AAAAAAAA",
            b"________",
            b"aaaaaaaa",
            b"u1234567",
            b"u12345670",
            b"zzzzzzzzzz",
        ];
        let mut packed = Vec::new();
        for &s in &ordered {
            let k = CompactKey64::encode_raw_inline(s).unwrap();
            assert!(k.is_pack10());
            let n = k.decode_inline(&mut buf);
            assert_eq!(&buf[..n], s);
            packed.push(k);
        }
        for w in packed.windows(2) {
            assert!(w[0].0 < w[1].0, "order failed for {:?} vs {:?}", w[0], w[1]);
        }

        assert!(CompactKey64::encode_raw_inline(b"!chain_min").is_none());
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
}
