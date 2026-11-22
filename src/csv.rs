use std::cmp::Ordering;
use std::fs::{self, File};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr;

use memchr::{memchr, memrchr};

pub const CHUNK_BYTES: usize = 2 * 1024 * 1024;
pub const READ_BLOCK_BYTES: usize = 256 * 1024;

pub const LONG_LEN_OVERFLOW: usize = 0xF_FFFF;
pub const LONG_LEN_MASK: u64 = 0xF_FFFF;
pub const LONG_OFF_MASK: u64 = (1u64 << 37) - 1;

pub const B37_MASK42: u64 = (1u64 << 42) - 1;
const B37_M1: u64 = 0x27D4_EB2D_1656_67B1;
const B37_M2: u64 = 0x1656_67B1_9E37_79B9;

const fn modinv42(a: u64) -> u64 {
    let mut inv = 1u64;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(inv))) & B37_MASK42;
        i += 1;
    }
    inv
}

const B37_M1_INV: u64 = modinv42(B37_M1);
const B37_M2_INV: u64 = modinv42(B37_M2);
const _: () = assert!((B37_M1.wrapping_mul(B37_M1_INV) & B37_MASK42) == 1);
const _: () = assert!((B37_M2.wrapping_mul(B37_M2_INV) & B37_MASK42) == 1);

#[inline(always)]
pub const fn biject42(mut x: u64) -> u64 {
    x &= B37_MASK42;
    x ^= x >> 21;
    x = x.wrapping_mul(B37_M1) & B37_MASK42;
    x ^= x >> 21;
    x = x.wrapping_mul(B37_M2) & B37_MASK42;
    x ^= x >> 21;
    x
}

#[inline(always)]
pub const fn inv_biject42(mut y: u64) -> u64 {
    y &= B37_MASK42;
    y ^= y >> 21;
    y = y.wrapping_mul(B37_M2_INV) & B37_MASK42;
    y ^= y >> 21;
    y = y.wrapping_mul(B37_M1_INV) & B37_MASK42;
    y ^= y >> 21;
    y
}

const fn build_b37_pairs() -> [[u8; 2]; 1369] {
    let mut ch = [0u8; 37];
    let mut i = 0;
    while i < 10 {
        ch[1 + i] = b'0' + (i as u8);
        i += 1;
    }
    let mut j = 0;
    while j < 26 {
        ch[11 + j] = b'a' + (j as u8);
        j += 1;
    }
    let mut pairs = [[0u8; 2]; 1369];
    let mut hi = 0;
    while hi < 37 {
        let mut lo = 0;
        while lo < 37 {
            pairs[hi * 37 + lo] = [ch[hi], ch[lo]];
            lo += 1;
        }
        hi += 1;
    }
    pairs
}

static B37_PAIRS: [[u8; 2]; 1369] = build_b37_pairs();

static B37_LANE_MASKS: [u64; 10] = [
    0,
    0,
    0x0000_0000_0000_00FF,
    0x0000_0000_0000_FFFF,
    0x0000_0000_00FF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_00FF_FFFF_FFFF,
    0x0000_FFFF_FFFF_FFFF,
    0x00FF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

#[inline(always)]
pub fn encode_b37_padded(padded: &[u8], start: usize, len: usize, prefix: u8) -> Option<u64> {
    debug_assert!(padded.len() >= start + 16);
    if len.wrapping_sub(2) > 7 {
        return None;
    }
    let ptr = unsafe { padded.as_ptr().add(start) };
    if unsafe { *ptr } != prefix {
        return None;
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
    unsafe {
        use std::arch::x86_64::*;
        let tail_le = *(ptr.add(1) as *const u64);
        let v_raw = _mm_cvtsi64_si128(tail_le as i64);
        let d_sub = _mm_sub_epi8(v_raw, _mm_set1_epi8((b'0' as i8).wrapping_sub(-128)));
        let is_dig = _mm_cmplt_epi8(d_sub, _mm_set1_epi8(-118));
        let a_sub = _mm_sub_epi8(v_raw, _mm_set1_epi8((b'a' as i8).wrapping_sub(-128)));
        let is_low = _mm_cmplt_epi8(a_sub, _mm_set1_epi8(-102));
        let valid_mask = (_mm_movemask_epi8(_mm_or_si128(is_dig, is_low)) as u32) & 0xFF;
        let need_mask = (1u32 << (len - 1)) - 1;
        if (valid_mask & need_mask) != need_mask {
            return None;
        }
        let mapped = _mm_sub_epi8(
            _mm_sub_epi8(v_raw, _mm_set1_epi8(47)),
            _mm_and_si128(is_low, _mm_set1_epi8(39)),
        );
        let lane_mask = _mm_cvtsi64_si128(*B37_LANE_MASKS.get_unchecked(len) as i64);
        let clean = _mm_and_si128(mapped, lane_mask);
        let pairs = _mm_maddubs_epi16(
            clean,
            _mm_setr_epi8(37, 1, 37, 1, 37, 1, 37, 1, 0, 0, 0, 0, 0, 0, 0, 0),
        );
        let quads = _mm_madd_epi16(pairs, _mm_setr_epi16(1369, 1, 1369, 1, 0, 0, 0, 0));
        let q64 = _mm_cvtsi128_si64(quads) as u64;
        let hi = (q64 & 0xFFFF_FFFF) as u64;
        let lo = (q64 >> 32) as u64;
        Some(hi * 1_874_161 + lo)
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse4.1")))]
    {
        let mut acc = 0u64;
        let mut w = 94_931_877_133u64;
        for i in 1..len {
            let b = unsafe { *ptr.add(i) };
            let v = if b.is_ascii_digit() {
                (b - b'0' + 1) as u64
            } else if (b'a'..=b'z').contains(&b) {
                (b - b'a' + 11) as u64
            } else {
                return None;
            };
            acc += v * w;
            w /= 37;
        }
        Some(acc)
    }
}

#[inline(always)]
pub fn encode_b37_pair_padded(
    padded: &[u8],
    s0: usize,
    len0: usize,
    pfx0: u8,
    s1: usize,
    len1: usize,
    pfx1: u8,
) -> Option<(u64, u64)> {
    debug_assert!(padded.len() >= s0 + 16 && padded.len() >= s1 + 16);
    if len0.wrapping_sub(2) > 7 || len1.wrapping_sub(2) > 7 {
        return None;
    }
    let p0 = unsafe { padded.as_ptr().add(s0) };
    let p1 = unsafe { padded.as_ptr().add(s1) };
    if unsafe { *p0 != pfx0 || *p1 != pfx1 } {
        return None;
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
    unsafe {
        use std::arch::x86_64::*;
        let t0 = *(p0.add(1) as *const u64);
        let t1 = *(p1.add(1) as *const u64);
        let v_raw = _mm_set_epi64x(t1 as i64, t0 as i64);
        let d_sub = _mm_sub_epi8(v_raw, _mm_set1_epi8((b'0' as i8).wrapping_sub(-128)));
        let is_dig = _mm_cmplt_epi8(d_sub, _mm_set1_epi8(-118));
        let a_sub = _mm_sub_epi8(v_raw, _mm_set1_epi8((b'a' as i8).wrapping_sub(-128)));
        let is_low = _mm_cmplt_epi8(a_sub, _mm_set1_epi8(-102));
        let valid_mask = _mm_movemask_epi8(_mm_or_si128(is_dig, is_low)) as u32;
        let need_mask = ((1u32 << (len0 - 1)) - 1) | (((1u32 << (len1 - 1)) - 1) << 8);
        if (valid_mask & need_mask) != need_mask {
            return None;
        }
        let mapped = _mm_sub_epi8(
            _mm_sub_epi8(v_raw, _mm_set1_epi8(47)),
            _mm_and_si128(is_low, _mm_set1_epi8(39)),
        );
        let lane_mask = _mm_set_epi64x(
            *B37_LANE_MASKS.get_unchecked(len1) as i64,
            *B37_LANE_MASKS.get_unchecked(len0) as i64,
        );
        let clean = _mm_and_si128(mapped, lane_mask);
        let pairs = _mm_maddubs_epi16(
            clean,
            _mm_setr_epi8(37, 1, 37, 1, 37, 1, 37, 1, 37, 1, 37, 1, 37, 1, 37, 1),
        );
        let quads = _mm_madd_epi16(pairs, _mm_setr_epi16(1369, 1, 1369, 1, 1369, 1, 1369, 1));
        let q0 = _mm_cvtsi128_si64(quads) as u64;
        let q1 = _mm_extract_epi64::<1>(quads) as u64;
        let v0 = (q0 & 0xFFFF_FFFF) * 1_874_161 + (q0 >> 32);
        let v1 = (q1 & 0xFFFF_FFFF) * 1_874_161 + (q1 >> 32);
        Some((v0, v1))
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "sse4.1")))]
    {
        Some((
            encode_b37_padded(padded, s0, len0, pfx0)?,
            encode_b37_padded(padded, s1, len1, pfx1)?,
        ))
    }
}

#[inline(always)]
pub fn decode_b37(val: u64, prefix: u8, buf: &mut [u8; 10]) -> usize {
    debug_assert!(val > 0 && val <= B37_MASK42);
    buf[0] = prefix;
    let hi4 = (val / 1_874_161) as usize;
    let lo4 = (val % 1_874_161) as usize;
    let p0 = hi4 / 1369;
    let p1 = hi4 % 1369;
    let p2 = lo4 / 1369;
    let p3 = lo4 % 1369;
    unsafe {
        let a0 = *B37_PAIRS.get_unchecked(p0);
        let a1 = *B37_PAIRS.get_unchecked(p1);
        let a2 = *B37_PAIRS.get_unchecked(p2);
        let a3 = *B37_PAIRS.get_unchecked(p3);
        let w = [a0[0], a0[1], a1[0], a1[1], a2[0], a2[1], a3[0], a3[1]];
        ptr::copy_nonoverlapping(w.as_ptr(), buf.as_mut_ptr().add(1), 8);
        let be = u64::from_be_bytes(w);
        9 - ((be.trailing_zeros() >> 3) as usize)
    }
}

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
/// - `1 ..= u32::MAX + 1` (`(val >> 54) == 0 && val != 0`): linked `comp_id + 1`
/// - `(1u64 << 54) ..= ...` (`(val >> 54) == 1`): `k_b37` (`^k[0-9a-z]{1,8}$`)
/// - `(2u64 << 54) ..= ...` (`(val >> 54) == 2`): `u_b37` (`^u[0-9a-z]{1,8}$`)
/// - `(3u64 << 54) ..= ...` (`(val >> 54) == 3`): `uh42` (`biject42(u_b37)`)
/// - `(1u64 << 56) ..= 0x7FFF_FFFF_FFFF_FFFF` (`bit 63 == 0` and `(val >> 56) != 0`):
///   lossless 1..=9 byte non-NUL ASCII string (`s[0]` in bits `62..56`, `pext7(s[1..])` BE in `55..0`)
/// - `bit 63 == 1`: arena ref `(1 << 63) | (wid:6 << 57) | (off:37 << 20) | (len:20)`
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct CompactKey64(pub u64);

const _: () = assert!(std::mem::size_of::<CompactKey64>() == 8);

const TAG_KB37_SHIFT: u64 = 1u64 << 54;
const TAG_UB37_SHIFT: u64 = 2u64 << 54;
const TAG_UH42_SHIFT: u64 = 3u64 << 54;

impl CompactKey64 {
    pub const EMPTY: Self = Self(0);

    #[inline(always)]
    pub const fn from_comp(comp_id: u32) -> Self {
        Self((comp_id as u64) + 1)
    }

    #[inline(always)]
    pub const fn is_comp(self) -> bool {
        (self.0 >> 54) == 0 && self.0 != 0
    }

    #[inline(always)]
    pub const fn comp_id(self) -> u32 {
        (self.0 - 1) as u32
    }

    #[inline(always)]
    pub const fn from_kb37(val: u64) -> Self {
        Self(TAG_KB37_SHIFT | val)
    }

    #[inline(always)]
    pub const fn is_kb37(self) -> bool {
        (self.0 >> 54) == 1
    }

    #[inline(always)]
    pub const fn from_ub37(val: u64) -> Self {
        Self(TAG_UB37_SHIFT | val)
    }

    #[inline(always)]
    pub const fn is_ub37(self) -> bool {
        (self.0 >> 54) == 2
    }

    #[inline(always)]
    pub const fn ub37_val(self) -> u64 {
        self.0 & B37_MASK42
    }

    #[inline(always)]
    pub const fn from_uh42(h42: u64) -> Self {
        Self(TAG_UH42_SHIFT | h42)
    }

    #[inline(always)]
    pub const fn is_uh42(self) -> bool {
        (self.0 >> 54) == 3
    }

    #[inline(always)]
    pub const fn uh42_val(self) -> u64 {
        self.0 & B37_MASK42
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
    pub fn encode_user_inline_padded(padded: &[u8], start: usize, len: usize) -> Option<Self> {
        if let Some(u37) = encode_b37_padded(padded, start, len, b'u') {
            return Some(Self::from_ub37(u37));
        }
        Self::encode_raw_inline_padded(padded, start, len)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn encode_user_inline(s: &[u8]) -> Option<Self> {
        let mut pad = [0u8; 32];
        if s.len() <= 16 {
            pad[..s.len()].copy_from_slice(s);
            return Self::encode_user_inline_padded(&pad, 0, s.len());
        }
        Self::encode_raw_inline(s)
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
    } else if key.is_ub37() {
        let len = decode_b37(key.ub37_val(), b'u', scratch);
        &scratch[..len]
    } else if key.is_uh42() {
        let len = decode_b37(inv_biject42(key.uh42_val()), b'u', scratch);
        &scratch[..len]
    } else if key.is_kb37() {
        let len = decode_b37(key.0 & B37_MASK42, b'k', scratch);
        &scratch[..len]
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
    if (a.is_inline() && b.is_inline())
        || (a.is_ub37() && b.is_ub37())
        || (a.is_kb37() && b.is_kb37())
    {
        return a.0.cmp(&b.0);
    }
    let mut ba = [0u8; 10];
    let mut bb = [0u8; 10];
    let sa = resolve_raw_key(a, arenas_a, &mut ba);
    let sb = resolve_raw_key(b, arenas_b, &mut bb);
    sa.cmp(sb)
}

#[inline(always)]
pub fn eq_raw_keys(
    a: CompactKey64,
    b: CompactKey64,
    arenas_a: &[LongArena],
    arenas_b: &[LongArena],
) -> bool {
    let mut ba = [0u8; 10];
    let mut bb = [0u8; 10];
    let sa = resolve_raw_key(a, arenas_a, &mut ba);
    let sb = resolve_raw_key(b, arenas_b, &mut bb);
    sa == sb
}

#[inline(always)]
pub fn hash_raw_key(k: CompactKey64, arenas: &[LongArena]) -> u64 {
    if !k.is_ref() && !k.is_ub37() && !k.is_uh42() && !k.is_kb37() {
        mix64(k.0)
    } else {
        let mut buf = [0u8; 10];
        let s = resolve_raw_key(k, arenas, &mut buf);
        hash_bytes_fast(s)
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

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn scan_direct_step64<const K: usize>(
    padded_buf: &[u8],
    p: usize,
    mut nl_mask: u64,
    cm_mask: u64,
    qt_mask: u64,
    na_mask: u64,
    d_for_ends: u64,
    next_d0: u64,
    prev_delim: &mut u64,
    prev_in_q: &mut u64,
    line_start: &mut usize,
    cm_buf: &mut [u32; 576],
    cm_head: &mut usize,
    cm_tail: &mut usize,
    line_start_parity: &mut u64,
    line_bad: &mut u64,
    line_na: &mut u64,
    on_line: &mut impl FnMut(&[u8], usize, usize, *const u32),
) {
    let d = cm_mask | nl_mask;
    let starts = (d << 1) | *prev_delim;
    let ends = (d_for_ends >> 1) | (next_d0 << 63);
    let bad_pos = qt_mask & !(starts ^ ends);
    let after_q = prefix_xor_u64(qt_mask) ^ *prev_in_q;
    *prev_delim = d >> 63;
    *prev_in_q = ((after_q as i64) >> 63) as u64;

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
    let mut m = cm_mask;
    let mut dst = cm_buf.as_mut_ptr().add(base_tail);
    let p32 = p as u32;
    while m != 0 {
        *dst = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(1) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(2) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(3) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(4) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(5) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(6) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(7) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        dst = dst.add(8);
    }

    let mut prev_done = 0u64;
    let lsp = *line_start_parity;
    let mut lb_cur = *line_bad;
    let mut lna_cur = *line_na;
    let mut ls = *line_start;
    let mut ch = *cm_head;
    let mut cur_lsp = lsp;

    while nl_mask != 0 {
        let nl_bit = nl_mask.trailing_zeros();
        let line_end = p + nl_bit as usize;
        let nl_flag = 1u64 << nl_bit;
        let before_nl = nl_flag - 1;
        let seg = before_nl & !prev_done;
        let seg_inc = (before_nl | nl_flag) & !prev_done;
        let line_cm_end = base_tail + (cm_mask & before_nl).count_ones() as usize;
        let n_commas = line_cm_end - ch;
        let bad_d = (after_q ^ cur_lsp) & (d & seg_inc);
        let bad = lb_cur | (bad_pos & seg) | bad_d;
        let lna = lna_cur | (na_mask & seg);
        if line_end > ls
            && n_commas == K - 1
            && bad == 0
            && (lna == 0
                || std::str::from_utf8(padded_buf.get_unchecked(ls..line_end)).is_ok())
        {
            on_line(padded_buf, ls, line_end, cm_buf.as_ptr().add(ch));
        }
        ls = line_end + 1;
        ch = line_cm_end;
        cur_lsp = 0u64.wrapping_sub((after_q >> nl_bit) & 1);
        lb_cur = 0;
        lna_cur = 0;
        prev_done = before_nl | nl_flag;
        nl_mask &= nl_mask - 1;
    }

    *line_start = ls;
    *cm_head = ch;
    *cm_tail = base_tail + block_cm;
    *line_start_parity = cur_lsp;
    let rem_mask = !prev_done;
    *line_bad = lb_cur | (bad_pos & rem_mask) | ((after_q ^ cur_lsp) & (d & rem_mask));
    *line_na = lna_cur | (na_mask & rem_mask);
}

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
pub fn scan_lines_direct_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_line: impl FnMut(&[u8], usize, usize, *const u32),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    if valid_len == 0 {
        return;
    }
    let mut line_start = 0usize;
    let mut cm_buf = [0u32; 576];
    let mut cm_head = 0usize;
    let mut cm_tail = 0usize;
    let mut prev_delim = 1u64;
    let mut prev_in_q = 0u64;
    let mut line_start_parity = 0u64;
    let mut line_bad = 0u64;
    let mut line_na = 0u64;
    let mut p = 0usize;

    unsafe {
        use std::arch::x86_64::*;
        let v_nl = _mm256_set1_epi8(b'\n' as i8);
        let v_cm = _mm256_set1_epi8(b',' as i8);
        let v_qt = _mm256_set1_epi8(b'"' as i8);
        let base = padded_buf.as_ptr();

        while p + 64 < valid_len {
            let v0 = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let v1 = _mm256_loadu_si256(base.add(p + 32) as *const __m256i);
            let nl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_nl)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_nl)) as u32 as u64) << 32);
            let cm_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_cm)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_cm)) as u32 as u64) << 32);
            let qt_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_qt)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_qt)) as u32 as u64) << 32);
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                (_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32)
            };
            let nb = *base.add(p + 64);
            let next_d0 = u64::from((nb == b',') | (nb == b'\n'));
            scan_direct_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                cm_mask | nl_mask,
                next_d0,
                &mut prev_delim,
                &mut prev_in_q,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut line_start_parity,
                &mut line_bad,
                &mut line_na,
                &mut on_line,
            );
            p += 64;
        }

        if p < valid_len {
            let rem = valid_len - p;
            let valid_mask = if rem == 64 { !0u64 } else { (1u64 << rem) - 1 };
            let eof_bit = if rem < 64 { 1u64 << rem } else { 0u64 };
            let tail_next_d0 = u64::from(rem == 64);
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
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                ((_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32))
                    & valid_mask
            };
            scan_direct_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                cm_mask | nl_mask | eof_bit,
                tail_next_d0,
                &mut prev_delim,
                &mut prev_in_q,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut line_start_parity,
                &mut line_bad,
                &mut line_na,
                &mut on_line,
            );
        }

        if line_start < valid_len
            && (cm_tail - cm_head) == K - 1
            && line_bad == 0
            && prev_in_q == line_start_parity
            && (line_na == 0
                || std::str::from_utf8(padded_buf.get_unchecked(line_start..valid_len)).is_ok())
        {
            on_line(padded_buf, line_start, valid_len, cm_buf.as_ptr().add(cm_head));
        }
    }
}

#[cfg(all(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
pub fn scan_lines_direct_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_line: impl FnMut(&[u8], usize, usize, *const u32),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    let data = &padded_buf[..valid_len];
    let base = padded_buf.as_ptr() as usize;
    let mut commas = [0u32; K];
    for_each_line_fields_slice::<K>(data, |fields| {
        let raw_0 = (fields[0].as_ptr() as usize) - base;
        let line_start = if raw_0 > 0 && padded_buf[raw_0 - 1] == b'"' {
            raw_0 - 1
        } else {
            raw_0
        };
        let mut prev_raw_e = 0usize;
        let mut line_end = 0usize;
        for i in 0..K {
            let f_s = (fields[i].as_ptr() as usize) - base;
            let f_e = f_s + fields[i].len();
            let is_q = if i == 0 {
                f_s > line_start
            } else {
                f_s > prev_raw_e + 1
            };
            let raw_e = f_e + usize::from(is_q);
            if i + 1 < K {
                commas[i] = raw_e as u32;
                prev_raw_e = raw_e;
            } else {
                line_end = raw_e;
            }
        }
        on_line(padded_buf, line_start, line_end, commas.as_ptr());
    });
}

const DIRECT_BATCH_LEN: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct DirectLine<const K: usize> {
    pub ls: u32,
    pub commas_end: [u32; K],
}

impl<const K: usize> DirectLine<K> {
    pub const ZERO: Self = Self {
        ls: 0,
        commas_end: [0; K],
    };
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn scan_direct_batched_step64<const K: usize>(
    padded_buf: &[u8],
    p: usize,
    mut nl_mask: u64,
    cm_mask: u64,
    qt_mask: u64,
    na_mask: u64,
    d_for_ends: u64,
    next_d0: u64,
    prev_delim: &mut u64,
    prev_in_q: &mut u64,
    line_start: &mut usize,
    cm_buf: &mut [u32; 576],
    cm_head: &mut usize,
    cm_tail: &mut usize,
    line_start_parity: &mut u64,
    line_bad: &mut u64,
    line_na: &mut u64,
    batch: &mut [DirectLine<K>; DIRECT_BATCH_LEN],
    batch_len: &mut usize,
    on_batch: &mut impl FnMut(&[u8], &[DirectLine<K>]),
) {
    let d = cm_mask | nl_mask;
    let starts = (d << 1) | *prev_delim;
    let ends = (d_for_ends >> 1) | (next_d0 << 63);
    let bad_pos = qt_mask & !(starts ^ ends);
    let after_q = prefix_xor_u64(qt_mask) ^ *prev_in_q;
    *prev_delim = d >> 63;
    *prev_in_q = ((after_q as i64) >> 63) as u64;

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
    let mut m = cm_mask;
    let mut dst = cm_buf.as_mut_ptr().add(base_tail);
    let p32 = p as u32;
    while m != 0 {
        *dst = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(1) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(2) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(3) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(4) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(5) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(6) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        *dst.add(7) = p32.wrapping_add(m.trailing_zeros());
        m &= m.wrapping_sub(1);
        dst = dst.add(8);
    }

    let mut prev_done = 0u64;
    let lsp = *line_start_parity;
    let mut lb_cur = *line_bad;
    let mut lna_cur = *line_na;
    let mut ls = *line_start;
    let mut ch = *cm_head;
    let mut cur_lsp = lsp;

    while nl_mask != 0 {
        let nl_bit = nl_mask.trailing_zeros();
        let line_end = p + nl_bit as usize;
        let nl_flag = 1u64 << nl_bit;
        let before_nl = nl_flag - 1;
        let seg = before_nl & !prev_done;
        let seg_inc = (before_nl | nl_flag) & !prev_done;
        let line_cm_end = base_tail + (cm_mask & before_nl).count_ones() as usize;
        let n_commas = line_cm_end - ch;
        let bad_d = (after_q ^ cur_lsp) & (d & seg_inc);
        let bad = lb_cur | (bad_pos & seg) | bad_d;
        let lna = lna_cur | (na_mask & seg);
        if line_end > ls
            && n_commas == K - 1
            && bad == 0
            && (lna == 0
                || std::str::from_utf8(padded_buf.get_unchecked(ls..line_end)).is_ok())
        {
            let bl = *batch_len;
            let dl = batch.get_unchecked_mut(bl);
            dl.ls = ls as u32;
            std::ptr::copy_nonoverlapping(
                cm_buf.as_ptr().add(ch),
                dl.commas_end.as_mut_ptr(),
                K - 1,
            );
            *dl.commas_end.get_unchecked_mut(K - 1) = line_end as u32;
            let new_bl = bl + 1;
            if new_bl == DIRECT_BATCH_LEN {
                on_batch(padded_buf, batch);
                *batch_len = 0;
            } else {
                *batch_len = new_bl;
            }
        }
        ls = line_end + 1;
        ch = line_cm_end;
        cur_lsp = 0u64.wrapping_sub((after_q >> nl_bit) & 1);
        lb_cur = 0;
        lna_cur = 0;
        prev_done = before_nl | nl_flag;
        nl_mask &= nl_mask - 1;
    }

    *line_start = ls;
    *cm_head = ch;
    *cm_tail = base_tail + block_cm;
    *line_start_parity = cur_lsp;
    let rem_mask = !prev_done;
    *line_bad = lb_cur | (bad_pos & rem_mask) | ((after_q ^ cur_lsp) & (d & rem_mask));
    *line_na = lna_cur | (na_mask & rem_mask);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
pub fn scan_lines_direct_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_batch: impl FnMut(&[u8], &[DirectLine<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    if valid_len == 0 {
        return;
    }
    let mut line_start = 0usize;
    let mut cm_buf = [0u32; 576];
    let mut cm_head = 0usize;
    let mut cm_tail = 0usize;
    let mut prev_delim = 1u64;
    let mut prev_in_q = 0u64;
    let mut line_start_parity = 0u64;
    let mut line_bad = 0u64;
    let mut line_na = 0u64;
    let mut batch = [DirectLine::<K>::ZERO; DIRECT_BATCH_LEN];
    let mut batch_len = 0usize;
    let mut p = 0usize;

    unsafe {
        use std::arch::x86_64::*;
        let v_nl = _mm256_set1_epi8(b'\n' as i8);
        let v_cm = _mm256_set1_epi8(b',' as i8);
        let v_qt = _mm256_set1_epi8(b'"' as i8);
        let base = padded_buf.as_ptr();

        while p + 64 < valid_len {
            let v0 = _mm256_loadu_si256(base.add(p) as *const __m256i);
            let v1 = _mm256_loadu_si256(base.add(p + 32) as *const __m256i);
            let nl_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_nl)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_nl)) as u32 as u64) << 32);
            let cm_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_cm)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_cm)) as u32 as u64) << 32);
            let qt_mask = (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v0, v_qt)) as u32 as u64)
                | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, v_qt)) as u32 as u64) << 32);
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                (_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32)
            };
            let nb = *base.add(p + 64);
            let next_d0 = u64::from((nb == b',') | (nb == b'\n'));
            scan_direct_batched_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                cm_mask | nl_mask,
                next_d0,
                &mut prev_delim,
                &mut prev_in_q,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut line_start_parity,
                &mut line_bad,
                &mut line_na,
                &mut batch,
                &mut batch_len,
                &mut on_batch,
            );
            p += 64;
        }

        if p < valid_len {
            let rem = valid_len - p;
            let valid_mask = if rem == 64 { !0u64 } else { (1u64 << rem) - 1 };
            let eof_bit = if rem < 64 { 1u64 << rem } else { 0u64 };
            let tail_next_d0 = u64::from(rem == 64);
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
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                ((_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32))
                    & valid_mask
            };
            scan_direct_batched_step64::<K>(
                padded_buf,
                p,
                nl_mask,
                cm_mask,
                qt_mask,
                na_mask,
                cm_mask | nl_mask | eof_bit,
                tail_next_d0,
                &mut prev_delim,
                &mut prev_in_q,
                &mut line_start,
                &mut cm_buf,
                &mut cm_head,
                &mut cm_tail,
                &mut line_start_parity,
                &mut line_bad,
                &mut line_na,
                &mut batch,
                &mut batch_len,
                &mut on_batch,
            );
        }

        if line_start < valid_len
            && (cm_tail - cm_head) == K - 1
            && line_bad == 0
            && prev_in_q == line_start_parity
            && (line_na == 0
                || std::str::from_utf8(padded_buf.get_unchecked(line_start..valid_len)).is_ok())
        {
            let dl = batch.get_unchecked_mut(batch_len);
            dl.ls = line_start as u32;
            std::ptr::copy_nonoverlapping(
                cm_buf.as_ptr().add(cm_head),
                dl.commas_end.as_mut_ptr(),
                K - 1,
            );
            *dl.commas_end.get_unchecked_mut(K - 1) = valid_len as u32;
            batch_len += 1;
        }
        if batch_len > 0 {
            on_batch(padded_buf, &batch[..batch_len]);
        }
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
pub fn scan_lines_direct_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_batch: impl FnMut(&[u8], &[DirectLine<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    let data = &padded_buf[..valid_len];
    let base = padded_buf.as_ptr() as usize;
    let mut batch = [DirectLine::<K>::ZERO; DIRECT_BATCH_LEN];
    let mut batch_len = 0usize;
    for_each_line_fields_slice::<K>(data, |fields| {
        let raw_0 = (fields[0].as_ptr() as usize) - base;
        let ls = if raw_0 > 0 && padded_buf[raw_0 - 1] == b'"' {
            raw_0 - 1
        } else {
            raw_0
        };
        let mut dl = DirectLine::<K>::ZERO;
        dl.ls = ls as u32;
        let mut prev_raw_e = 0usize;
        for i in 0..K {
            let f_s = (fields[i].as_ptr() as usize) - base;
            let f_e = f_s + fields[i].len();
            let is_q = if i == 0 {
                f_s > ls
            } else {
                f_s > prev_raw_e + 1
            };
            let raw_e = f_e + usize::from(is_q);
            dl.commas_end[i] = raw_e as u32;
            prev_raw_e = raw_e;
        }
        batch[batch_len] = dl;
        batch_len += 1;
        if batch_len == DIRECT_BATCH_LEN {
            on_batch(padded_buf, &batch);
            batch_len = 0;
        }
    });
    if batch_len > 0 {
        on_batch(padded_buf, &batch[..batch_len]);
    }
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

#[cfg(test)]
#[derive(Clone, Copy)]
pub struct LineBounds<const K: usize> {
    pub line_start: u32,
    pub commas_and_end: [u32; K],
}

#[cfg(test)]
impl<const K: usize> LineBounds<K> {
    pub const ZERO: Self = Self {
        line_start: 0,
        commas_and_end: [0; K],
    };

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

#[inline(always)]
pub unsafe fn field_span(base: *const u8, s: usize, e: usize) -> (usize, usize) {
    let q = usize::from(*base.add(s) == b'"');
    (s + q, e - q)
}

#[inline(always)]
fn prefix_xor_u64(mut x: u64) -> u64 {
    x ^= x << 1;
    x ^= x << 2;
    x ^= x << 4;
    x ^= x << 8;
    x ^= x << 16;
    x ^= x << 32;
    x
}

#[cfg(test)]
const BATCH_SCAN_FLUSH: usize = 512;

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
fn push_line_bounds_if_valid<const K: usize>(
    padded_buf: &[u8],
    line_start: usize,
    line_end: usize,
    commas: &[u32; K],
    n_commas: usize,
    total_quotes: u32,
    non_ascii: u32,
    batch: &mut Vec<LineBounds<K>>,
) {
    if line_end <= line_start || n_commas != K - 1 {
        return;
    }
    if non_ascii != 0 && std::str::from_utf8(&padded_buf[line_start..line_end]).is_err() {
        return;
    }
    let ptr = padded_buf.as_ptr();
    let mut commas_and_end = [0u32; K];
    let mut prev = line_start;
    let mut expected_quotes = 0u32;
    let mut i = 0usize;
    while i < K {
        let end = if i < K - 1 {
            commas[i] as usize
        } else {
            line_end
        };
        let last = if end > prev { end - 1 } else { prev };
        let is_q = usize::from(
            (end.wrapping_sub(prev) >= 2)
                & (unsafe { *ptr.add(prev) } == b'"')
                & (unsafe { *ptr.add(last) } == b'"'),
        );
        commas_and_end[i] = (end as u32) | ((is_q as u32) << 31);
        expected_quotes += (is_q as u32) << 1;
        prev = end + 1;
        i += 1;
    }
    if expected_quotes == total_quotes {
        batch.push(LineBounds {
            line_start: line_start as u32,
            commas_and_end,
        });
    }
}

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn scan_avx2_step64<const K: usize>(
    padded_buf: &[u8],
    p: usize,
    mut nl_mask: u64,
    mut cm_mask: u64,
    mut qt_mask: u64,
    mut na_mask: u64,
    line_start: &mut usize,
    commas: &mut [u32; K],
    n_commas: &mut usize,
    total_quotes: &mut u32,
    non_ascii: &mut u32,
    batch: &mut Vec<LineBounds<K>>,
) {
    while nl_mask != 0 {
        let nl_bit = nl_mask.trailing_zeros();
        let line_end = p + nl_bit as usize;
        let nl_flag = 1u64 << nl_bit;
        let before_nl = nl_flag - 1;
        let mut line_cm = cm_mask & before_nl;
        while line_cm != 0 {
            let cbit = line_cm.trailing_zeros() as usize;
            *commas.get_unchecked_mut((*n_commas).min(K - 1)) = (p + cbit) as u32;
            *n_commas += 1;
            line_cm &= line_cm - 1;
        }
        *total_quotes += (qt_mask & before_nl).count_ones();
        *non_ascii |= ((na_mask & before_nl) != 0) as u32;

        push_line_bounds_if_valid::<K>(
            padded_buf,
            *line_start,
            line_end,
            commas,
            *n_commas,
            *total_quotes,
            *non_ascii,
            batch,
        );

        *line_start = line_end + 1;
        *n_commas = 0;
        *total_quotes = 0;
        *non_ascii = 0;

        let keep_after = !(before_nl | nl_flag);
        nl_mask &= keep_after;
        cm_mask &= keep_after;
        qt_mask &= keep_after;
        na_mask &= keep_after;
    }

    while cm_mask != 0 {
        let cbit = cm_mask.trailing_zeros() as usize;
        *commas.get_unchecked_mut((*n_commas).min(K - 1)) = (p + cbit) as u32;
        *n_commas += 1;
        cm_mask &= cm_mask - 1;
    }
    *total_quotes += qt_mask.count_ones();
    *non_ascii |= (na_mask != 0) as u32;
}

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
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
    let mut commas = [0u32; K];
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
            scan_avx2_step64::<K>(
                padded_buf,
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
            scan_avx2_step64::<K>(
                padded_buf,
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
                batch,
            );
        }
    }

    if line_start < valid_len {
        push_line_bounds_if_valid::<K>(
            padded_buf,
            line_start,
            valid_len,
            &commas,
            n_commas,
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

#[cfg(all(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
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

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn push_lb_l1<const K: usize>(
    padded_buf: &[u8],
    line_start: usize,
    line_end: usize,
    commas_ptr: *const u32,
    n_commas: usize,
    total_quotes: u32,
    non_ascii: u32,
    batch: &mut [LineBounds<K>; 64],
    batch_len: &mut usize,
    on_batch: &mut impl FnMut(&[u8], &[LineBounds<K>]),
) {
    if line_end <= line_start || n_commas != K - 1 || (total_quotes & 1) != 0 {
        return;
    }
    if non_ascii != 0 && std::str::from_utf8(&padded_buf[line_start..line_end]).is_err() {
        return;
    }
    let ptr = padded_buf.as_ptr();
    let mut commas_and_end = [0u32; K];
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
        *commas_and_end.get_unchecked_mut(i) = (end as u32) | ((is_q as u32) << 31);
        expected_quotes += (is_q as u32) << 1;
        prev = end + 1;
        i += 1;
    }
    if expected_quotes == total_quotes {
        let len = *batch_len;
        *batch.get_unchecked_mut(len) = LineBounds {
            line_start: line_start as u32,
            commas_and_end,
        };
        let new_len = len + 1;
        if new_len == 64 {
            on_batch(padded_buf, batch);
            *batch_len = 0;
        } else {
            *batch_len = new_len;
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn scan_step64_l1<const K: usize>(
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
    batch: &mut [LineBounds<K>; 64],
    batch_len: &mut usize,
    on_batch: &mut impl FnMut(&[u8], &[LineBounds<K>]),
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

        push_lb_l1::<K>(
            padded_buf,
            *line_start,
            line_end,
            cm_buf.as_ptr().add(*cm_head),
            n_commas,
            *total_quotes,
            *non_ascii,
            batch,
            batch_len,
            on_batch,
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

#[cfg(all(test, target_arch = "x86_64", target_feature = "avx2"))]
pub fn scan_lines_l1_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    if valid_len == 0 {
        return;
    }
    let mut line_start = 0usize;
    let mut cm_buf = [0u32; 576];
    let mut cm_head = 0usize;
    let mut cm_tail = 0usize;
    let mut total_quotes = 0u32;
    let mut non_ascii = 0u32;
    let mut batch = [LineBounds::<K>::ZERO; 64];
    let mut batch_len = 0usize;
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
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                (_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32)
            };
            scan_step64_l1::<K>(
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
                &mut batch,
                &mut batch_len,
                &mut on_batch,
            );
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
            let na_mask = if _mm256_movemask_epi8(_mm256_or_si256(v0, v1)) == 0 {
                0u64
            } else {
                ((_mm256_movemask_epi8(v0) as u32 as u64)
                    | ((_mm256_movemask_epi8(v1) as u32 as u64) << 32))
                    & valid_mask
            };
            scan_step64_l1::<K>(
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
                &mut batch,
                &mut batch_len,
                &mut on_batch,
            );
        }

        if line_start < valid_len {
            push_lb_l1::<K>(
                padded_buf,
                line_start,
                valid_len,
                cm_buf.as_ptr().add(cm_head),
                cm_tail - cm_head,
                total_quotes,
                non_ascii,
                &mut batch,
                &mut batch_len,
                &mut on_batch,
            );
        }
        if batch_len > 0 {
            on_batch(padded_buf, &batch[..batch_len]);
        }
    }
}

#[cfg(all(test, not(all(target_arch = "x86_64", target_feature = "avx2"))))]
pub fn scan_lines_l1_batched_avx2<const K: usize>(
    padded_buf: &[u8],
    valid_len: usize,
    mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
) {
    assert!(K >= 2);
    assert!(valid_len < (1 << 31));
    assert!(padded_buf.len() >= valid_len + 64);
    let data = &padded_buf[..valid_len];
    let base = padded_buf.as_ptr() as usize;
    let mut batch = [LineBounds::<K>::ZERO; 64];
    let mut batch_len = 0usize;
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
        batch[batch_len] = LineBounds {
            line_start: line_start as u32,
            commas_and_end,
        };
        batch_len += 1;
        if batch_len == 64 {
            on_batch(padded_buf, &batch);
            batch_len = 0;
        }
    });
    if batch_len > 0 {
        on_batch(padded_buf, &batch[..batch_len]);
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

#[cfg(unix)]
#[inline]
fn fadvise_sequential(file: &File, len: usize) {
    if len == 0 {
        return;
    }
    use std::os::raw::c_int;
    use std::os::unix::io::AsRawFd;
    const POSIX_FADV_SEQUENTIAL: c_int = 2;
    extern "C" {
        fn posix_fadvise(fd: c_int, offset: i64, len: i64, advice: c_int) -> c_int;
    }
    unsafe {
        let _ = posix_fadvise(file.as_raw_fd(), 0, 0, POSIX_FADV_SEQUENTIAL);
    }
}

impl CsvSource {
    pub fn open(paths: &[PathBuf]) -> io::Result<Self> {
        let mut files = Vec::with_capacity(paths.len());
        let mut lens = Vec::with_capacity(paths.len());
        let mut total_bytes = 0usize;
        for path in paths {
            let file = File::open(path)?;
            let len = file.metadata()?.len() as usize;
            #[cfg(unix)]
            fadvise_sequential(&file, len);
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
                    let start = nl + 1;
                    if start < n {
                        if let Some(rel_last_nl) = memrchr(b'\n', &buf[start..n]) {
                            let process_len = rel_last_nl + 1;
                            feed(&buf[start..], process_len);
                            let abs_end = start + process_len;
                            buf.copy_within(abs_end..n, 0);
                            carry = n - abs_end;
                        } else {
                            buf.copy_within(start..n, 0);
                            carry = n - start;
                        }
                    }
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

    #[inline(always)]
    pub fn for_each_chunk_direct_batched<const K: usize>(
        &self,
        task: ChunkTask,
        buf: &mut Vec<u8>,
        mut on_batch: impl FnMut(&[u8], &[DirectLine<K>]),
    ) -> io::Result<()> {
        self.for_each_chunk_blocks(task, buf, 64, |padded, valid_len| {
            scan_lines_direct_batched_avx2::<K>(padded, valid_len, &mut on_batch);
        })
    }

    #[cfg(test)]
    pub fn for_each_chunk_batch<const K: usize>(
        &self,
        task: ChunkTask,
        buf: &mut Vec<u8>,
        batch: &mut Vec<LineBounds<K>>,
        mut on_batch: impl FnMut(&[u8], &[LineBounds<K>]),
    ) -> io::Result<()> {
        self.for_each_chunk_blocks(task, buf, 64, |padded, valid_len| {
            scan_lines_batched_avx2::<K>(padded, valid_len, batch, &mut on_batch);
        })
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
    fn test_scan_lines_fused_edge_cases() {
        let mut data = Vec::new();
        for i in 0..150 {
            data.extend_from_slice(format!("a{i},b{i}\n").as_bytes());
        }
        let rem = (64 - (data.len() % 64)) % 64;
        for _ in 0..rem {
            data.push(b'\n');
        }
        assert_eq!(data.len() % 64, 0);
        // 63 payload bytes + \n at exact offset 63
        data.extend_from_slice(&[b'x'; 58]);
        data.extend_from_slice(b",yyyy\n");
        assert_eq!(data.len() % 64, 0);
        // Odd quotes (malformed)
        data.extend_from_slice(b"\"a,b\n");
        data.extend_from_slice(b"a\",b\n");
        data.extend_from_slice(b"\"\"\"a,b\n");
        // >600 commas malformed line followed by valid line
        for _ in 0..700 {
            data.push(b',');
        }
        data.push(b'\n');
        data.extend_from_slice(b"after700,ok700\n");
        for _ in 0..520 {
            data.push(b',');
        }
        data.push(b'\n');
        data.extend_from_slice(b"tail_k1,tail_k2");

        let mut padded = data.clone();
        padded.resize(data.len() + 64, 0);
        let mut fused_got = Vec::new();
        let mut batch_sizes = Vec::new();
        scan_lines_l1_batched_avx2::<2>(&padded, data.len(), |d, lines| {
            batch_sizes.push(lines.len());
            for lb in lines {
                let (s0, e0) = lb.span(0);
                let (s1, e1) = lb.span(1);
                fused_got.push((d[s0..e0].to_vec(), d[s1..e1].to_vec()));
            }
        });
        assert!(batch_sizes.len() >= 3 && batch_sizes[0] == 64 && batch_sizes[1] == 64);
        let mut scalar_expected = Vec::new();
        for_each_line_fields_slice::<2>(&data, |f| {
            scalar_expected.push((f[0].to_vec(), f[1].to_vec()));
        });
        assert_eq!(fused_got, scalar_expected);

        // K=7 events schema including 8+ commas in a 64B chunk and quoted/empty fields
        let mut ev_data = Vec::new();
        ev_data.extend_from_slice(b"e1,u1,2026-10-03T10:00:00Z,2026-10-03T10:01:00Z,view,p1,\n");
        ev_data.extend_from_slice(b"bad,,,,,,,,,,,,,,,,\n");
        ev_data.extend_from_slice(b"\"e2\",\"u2\",2026-10-03T10:05:00Z,2026-10-03T10:06:00Z,cart,p2,\n");
        ev_data.extend_from_slice(b"e3,u3,2026-10-03T10:10:00Z,2026-10-03T10:11:00Z,purchase,p3,500");
        let mut ev_pad = ev_data.clone();
        ev_pad.resize(ev_data.len() + 64, 0);
        let mut ev_fused = Vec::new();
        scan_lines_l1_batched_avx2::<7>(&ev_pad, ev_data.len(), |d, lines| {
            for lb in lines {
                let row: Vec<Vec<u8>> = (0..7)
                    .map(|k| {
                        let (s, e) = lb.span(k);
                        d[s..e].to_vec()
                    })
                    .collect();
                ev_fused.push(row);
            }
        });
        let mut ev_scalar = Vec::new();
        for_each_line_fields_slice::<7>(&ev_data, |f| {
            ev_scalar.push(f.iter().map(|x| x.to_vec()).collect::<Vec<_>>());
        });
        assert_eq!(ev_fused, ev_scalar);

        // Compare scan_lines_direct_avx2 against scalar across all tricky 64B quote/comma/EOF boundaries
        let mut dir_data = data.clone();
        dir_data.extend_from_slice(b"\n");
        let pad_to_63 = (64 - (dir_data.len() % 64)) % 64;
        for _ in 0..pad_to_63 {
            dir_data.push(b'\n');
        }
        // Quote right at byte 63 followed by comma at byte 64, and another at 64-byte aligned start
        let b63_line = format!("\"{}\",\"ok\"\n", "a".repeat(61));
        dir_data.extend_from_slice(b63_line.as_bytes()); // length = 68 (63+1+1+2+1) -> crosses 64B boundary right after closing quote!
        let b63_exact = format!("{},\"b\"\n", "x".repeat(63));
        dir_data.extend_from_slice(b63_exact.as_bytes()); // comma at byte 63, opening quote at next block byte 0!
        // Unpaired quote line followed by valid quoted line, plus lone 1-byte quote field
        dir_data.extend_from_slice(b"\"odd_unclosed,x\n\"good\",\"line\"\n\",ok\nok,\"\n");
        // Empty trailing field without newline at EOF, 64B-aligned EOF without newline, and trailing empty after comma
        for tail_case in [b"last0,last1".as_slice(), b"last_empty,".as_slice(), b"\"q0\",\"\"".as_slice()] {
            let mut full = dir_data.clone();
            full.extend_from_slice(tail_case);
            let mut tpad = full.clone();
            tpad.resize(full.len() + 64, 0);
            let mut got_dir = Vec::new();
            scan_lines_direct_avx2::<2>(&tpad, full.len(), |p, ls, le, cp| unsafe {
                let base = p.as_ptr();
                let c0 = *cp.add(0) as usize;
                let (s0, e0) = field_span(base, ls, c0);
                let (s1, e1) = field_span(base, c0 + 1, le);
                got_dir.push((p[s0..e0].to_vec(), p[s1..e1].to_vec()));
            });
            let mut exp_dir = Vec::new();
            for_each_line_fields_slice::<2>(&full, |f| {
                exp_dir.push((f[0].to_vec(), f[1].to_vec()));
            });
            assert_eq!(got_dir, exp_dir, "direct scanner mismatch on tail {:?}", String::from_utf8_lossy(tail_case));
        }
        // Test exact multiple-of-64 EOF without trailing newline
        let exact64_line = format!("{},end", "k".repeat(60));
        assert_eq!(exact64_line.len(), 64);
        let mut tpad64 = exact64_line.as_bytes().to_vec();
        tpad64.resize(128, 0);
        let mut got64 = Vec::new();
        scan_lines_direct_avx2::<2>(&tpad64, 64, |p, ls, le, cp| unsafe {
            let base = p.as_ptr();
            let c0 = *cp.add(0) as usize;
            let (s0, e0) = field_span(base, ls, c0);
            let (s1, e1) = field_span(base, c0 + 1, le);
            got64.push((p[s0..e0].to_vec(), p[s1..e1].to_vec()));
        });
        assert_eq!(
            got64,
            vec![(b"k".repeat(60), b"end".to_vec())],
            "exact 64B EOF direct scan mismatch"
        );

        // Verify scan_lines_direct_batched_avx2 matches scan_lines_direct_avx2 across >200 lines & K=7
        let mut batched_dir = Vec::new();
        let mut batched_sizes = Vec::new();
        scan_lines_direct_batched_avx2::<2>(&padded, data.len(), |p, lines| {
            batched_sizes.push(lines.len());
            let base = p.as_ptr();
            for dl in lines {
                let ls = dl.ls as usize;
                let c0 = dl.commas_end[0] as usize;
                let le = dl.commas_end[1] as usize;
                let (s0, e0) = unsafe { field_span(base, ls, c0) };
                let (s1, e1) = unsafe { field_span(base, c0 + 1, le) };
                batched_dir.push((p[s0..e0].to_vec(), p[s1..e1].to_vec()));
            }
        });
        assert!(batched_sizes.len() >= 3 && batched_sizes[0] == 64 && batched_sizes[1] == 64);
        assert_eq!(batched_dir, scalar_expected);

        let mut ev_batched_dir = Vec::new();
        scan_lines_direct_batched_avx2::<7>(&ev_pad, ev_data.len(), |p, lines| {
            let base = p.as_ptr();
            for dl in lines {
                let mut row = Vec::with_capacity(7);
                let mut prev = dl.ls as usize;
                for k in 0..7 {
                    let end = dl.commas_end[k] as usize;
                    let (s, e) = unsafe { field_span(base, prev, end) };
                    row.push(p[s..e].to_vec());
                    prev = end + 1;
                }
                ev_batched_dir.push(row);
            }
        });
        assert_eq!(ev_batched_dir, ev_scalar);
    }

    #[test]
    fn test_b37_sse_pair_matches_single() {
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            rng
        };
        let alphabet: Vec<u8> = (0u8..=255).collect();
        let make_field = |len: usize, pfx: u8, r: u64, force_valid: bool| -> [u8; 32] {
            let mut buf = [b'!'; 32];
            if len > 0 {
                buf[0] = if force_valid {
                    pfx
                } else {
                    alphabet[((r >> 56) as usize) % 256]
                };
            }
            for i in 1..len.min(16) {
                let x = ((r >> ((i * 7) % 48)) as usize) + i * 13;
                if force_valid {
                    let v = x % 36;
                    buf[i] = if v < 10 { b'0' + v as u8 } else { b'a' + (v - 10) as u8 };
                } else {
                    let edge = [b'0' - 1, b'9' + 1, b'a' - 1, b'z' + 1, 0x80, 0xFF, b'0', b'a'];
                    buf[i] = edge[x % edge.len()];
                }
            }
            buf
        };
        for l0 in 0..=11 {
            for l1 in 0..=11 {
                for valid0 in [true, false] {
                    for valid1 in [true, false] {
                        let b0 = make_field(l0, b'e', next(), valid0);
                        let b1 = make_field(l1, b'u', next(), valid1);
                        let mut pad = [0u8; 80];
                        pad[3..3 + l0.max(1)].copy_from_slice(&b0[..l0.max(1)]);
                        pad[30..30 + l1.max(1)].copy_from_slice(&b1[..l1.max(1)]);
                        let s0 = encode_b37_padded(&pad, 3, l0, b'e');
                        let s1 = encode_b37_padded(&pad, 30, l1, b'u');
                        let pair = encode_b37_pair_padded(&pad, 3, l0, b'e', 30, l1, b'u');
                        let exp = match (s0, s1) {
                            (Some(a), Some(b)) => Some((a, b)),
                            _ => None,
                        };
                        assert_eq!(pair, exp, "pair mismatch l0={l0} l1={l1} v0={valid0} v1={valid1}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_b37_sse_biject42_roundtrip_order_and_all_bytes() {
        let mut buf = [0u8; 10];
        let samples: &[&[u8]] = &[
            b"u0",
            b"u1",
            b"u10",
            b"u1a",
            b"u2",
            b"u9z",
            b"u00000000",
            b"u12345678",
            b"uzzzzzzzz",
            b"u82u2orgh",
            b"u9jhbmnn4",
        ];
        for &s in samples {
            let mut pad = vec![0xFFu8; 4 + s.len() + 32];
            pad[4..4 + s.len()].copy_from_slice(s);
            let v = encode_b37_padded(&pad, 4, s.len(), b'u').unwrap();
            assert!(v > 0 && v <= B37_MASK42);
            let h = biject42(v);
            assert!(h > 0 && h <= B37_MASK42);
            assert_eq!(inv_biject42(h), v);
            let n = decode_b37(v, b'u', &mut buf);
            assert_eq!(&buf[..n], s, "roundtrip failed for {s:?}");
        }

        // Exhaustive lexicographical ordering check across variable lengths & digits/letters
        let mut sorted: Vec<&[u8]> = samples.to_vec();
        sorted.sort();
        for w in sorted.windows(2) {
            let mut pa = vec![0u8; 32];
            let mut pb = vec![0u8; 32];
            pa[..w[0].len()].copy_from_slice(w[0]);
            pb[..w[1].len()].copy_from_slice(w[1]);
            let va = encode_b37_padded(&pa, 0, w[0].len(), b'u').unwrap();
            let vb = encode_b37_padded(&pb, 0, w[1].len(), b'u').unwrap();
            assert_eq!(va.cmp(&vb), w[0].cmp(w[1]), "order {:?} vs {:?}", w[0], w[1]);
        }

        // Exhaustive check across ALL 256 byte values in EVERY tail lane 0..8 and len 2..=9
        for len in 2..=9 {
            for pos in 1..len {
                for b in 0u8..=255 {
                    let mut pad = [b'x'; 32];
                    pad[0] = b'e';
                    for k in 1..len {
                        pad[k] = b'0';
                    }
                    pad[pos] = b;
                    let ok = b.is_ascii_digit() || (b'a'..=b'z').contains(&b);
                    let res = encode_b37_padded(&pad, 0, len, b'e');
                    assert_eq!(res.is_some(), ok, "len={len} pos={pos} byte={b}");
                    if let Some(v) = res {
                        assert_eq!(inv_biject42(biject42(v)), v);
                        let n = decode_b37(v, b'e', &mut buf);
                        assert_eq!(&buf[..n], &pad[..len]);
                    }
                }
            }
        }
        // Check invalid prefixes, lengths, and disjoint CompactKey64 tag ranges
        let mut p10 = [b'0'; 32];
        p10[0] = b'u';
        assert!(encode_b37_padded(&p10, 0, 0, b'u').is_none());
        assert!(encode_b37_padded(&p10, 0, 1, b'u').is_none());
        assert!(encode_b37_padded(&p10, 0, 10, b'u').is_none());
        assert!(encode_b37_padded(&p10, 0, 5, b'e').is_none());

        let ku = CompactKey64::encode_user_inline(b"u82u2orgh").unwrap();
        let kk = CompactKey64::from_kb37(encode_b37_padded(b"k34avidd4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0, 9, b'k').unwrap());
        let kh = CompactKey64::from_uh42(biject42(ku.ub37_val()));
        let kp = CompactKey64::encode_raw_inline(b"\x01abc").unwrap();
        let kc = CompactKey64::from_comp(u32::MAX);
        assert!(ku.is_ub37() && !ku.is_inline() && !ku.is_comp() && !ku.is_ref());
        assert!(kk.is_kb37() && !kk.is_ub37() && !kk.is_inline());
        assert!(kh.is_uh42() && !kh.is_ub37() && !kh.is_inline());
        assert!(kp.is_inline() && !kp.is_ub37() && !kp.is_uh42() && !kp.is_kb37());
        assert!(kc.is_comp() && !kc.is_kb37() && !kc.is_ub37() && !kc.is_inline());
        let arenas: [LongArena; 0] = [];
        assert_eq!(cmp_raw_keys(ku, CompactKey64::encode_raw_inline(b"u82u2orgh").unwrap(), &arenas, &arenas), Ordering::Equal);
        assert_eq!(cmp_raw_keys(kp, ku, &arenas, &arenas), Ordering::Less);
    }
}
