use serde::Deserialize;

pub const MS_SECOND: i64 = 1_000;
pub const MS_DAY: i64 = 86_400_000;
pub const MS_SESSION_GAP: i64 = 1_800_000;
pub const MS_CLICK_REACH: i64 = 604_800_000;

#[derive(Deserialize)]
pub struct Manifest {
    pub window_start: String,
    pub window_end: String,
}

#[inline(always)]
pub fn is_leap_year(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

#[inline(always)]
pub fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

#[inline(always)]
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    era * 146_097 + year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year - 719_468
}

#[inline(always)]
fn d2(a: u8, b: u8) -> Option<i64> {
    let x = a.wrapping_sub(b'0');
    let y = b.wrapping_sub(b'0');
    if x < 10 && y < 10 {
        Some((x as i64) * 10 + (y as i64))
    } else {
        None
    }
}

#[inline(always)]
fn d4(b: &[u8]) -> Option<i64> {
    let a = b[0].wrapping_sub(b'0');
    let c = b[1].wrapping_sub(b'0');
    let d = b[2].wrapping_sub(b'0');
    let e = b[3].wrapping_sub(b'0');
    if a < 10 && c < 10 && d < 10 && e < 10 {
        Some((a as i64) * 1000 + (c as i64) * 100 + (d as i64) * 10 + (e as i64))
    } else {
        None
    }
}

#[inline(always)]
fn is_8_ascii_digits(v: u64) -> bool {
    let hi_bad = (v & 0xF0F0_F0F0_F0F0_F0F0) ^ 0x3030_3030_3030_3030;
    let lo_bad =
        ((v & 0x0F0F_0F0F_0F0F_0F0F).wrapping_add(0x0606_0606_0606_0606)) & 0xF0F0_F0F0_F0F0_F0F0;
    (hi_bad | lo_bad) == 0
}

#[inline(always)]
fn parse_8_ascii_digits(v: u64) -> u64 {
    let mut x = v & 0x0F0F_0F0F_0F0F_0F0F;
    x = (x & 0x00FF_00FF_00FF_00FF).wrapping_mul(10) + ((x >> 8) & 0x00FF_00FF_00FF_00FF);
    x = (x & 0x0000_FFFF_0000_FFFF).wrapping_mul(100) + ((x >> 16) & 0x0000_FFFF_0000_FFFF);
    (x & 0x0000_0000_FFFF_FFFF).wrapping_mul(10_000) + (x >> 32)
}

#[inline(always)]
fn parse_hms_sec_u64(t8: u64) -> (i64, bool) {
    let colons_ok = (t8 & 0x0000_FF00_00FF_0000) == 0x0000_3A00_003A_0000;
    let zeroed = t8 ^ 0x0000_0A00_000A_0000;
    let digits_ok = is_8_ascii_digits(zeroed);
    let d = zeroed & 0x0F0F_0F0F_0F0F_0F0F;
    let h = ((d & 0xFF) * 10 + ((d >> 8) & 0xFF)) as i64;
    let m = (((d >> 24) & 0xFF) * 10 + ((d >> 32) & 0xFF)) as i64;
    let s = (((d >> 48) & 0xFF) * 10 + ((d >> 56) & 0xFF)) as i64;
    let ok = colons_ok & digits_ok & (h <= 23) & (m <= 59) & (s <= 59);
    (h * 3_600 + m * 60 + s, ok)
}

#[inline(always)]
fn parse_hms_sec(b: &[u8]) -> Option<i64> {
    let t8 = u64::from_le_bytes(b[11..19].try_into().unwrap());
    let (sec, ok) = parse_hms_sec_u64(t8);
    if ok {
        Some(sec)
    } else {
        None
    }
}

#[inline(always)]
fn parse_hms_swar(b: &[u8]) -> Option<i64> {
    Some(parse_hms_sec(b)? * MS_SECOND)
}

#[inline(always)]
fn parse_civil_datetime_19(b: &[u8]) -> Option<i64> {
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let year = d4(&b[0..4])?;
    let month = d2(b[5], b[6])?;
    let day = d2(b[8], b[9])?;
    let dim = days_in_month(year, month);
    if day < 1 || day > dim {
        return None;
    }
    let hms_ms = parse_hms_swar(b)?;
    Some(days_from_civil(year, month, day) * MS_DAY + hms_ms)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct DateCacheEntry {
    hi: u64,
    day_sec: i64,
    lo: u16,
    _pad: [u16; 3],
}

const _: () = assert!(std::mem::size_of::<DateCacheEntry>() == 24);

#[derive(Clone)]
pub struct DateCache {
    entries: [DateCacheEntry; 64],
}

impl DateCache {
    pub fn new() -> Self {
        Self {
            entries: [DateCacheEntry {
                hi: u64::MAX,
                day_sec: 0,
                lo: 0,
                _pad: [0; 3],
            }; 64],
        }
    }

    #[inline(always)]
    fn parse_civil_date_sec(&mut self, b: &[u8]) -> Option<(i64, u64, u16)> {
        if b[10] != b'T' {
            return None;
        }
        let hi = u64::from_ne_bytes(b[0..8].try_into().unwrap());
        let lo = u16::from_ne_bytes(b[8..10].try_into().unwrap());
        let idx = (((lo as usize & 3) << 4) + (((lo >> 8) as usize) & 15)) & 63;
        let e = &mut self.entries[idx];
        let day_sec = if e.hi == hi && e.lo == lo {
            e.day_sec
        } else {
            if b[4] != b'-' || b[7] != b'-' {
                return None;
            }
            let year = d4(&b[0..4])?;
            let month = d2(b[5], b[6])?;
            let day = d2(b[8], b[9])?;
            let dim = days_in_month(year, month);
            if day < 1 || day > dim {
                return None;
            }
            let ds = days_from_civil(year, month, day) * 86_400;
            e.hi = hi;
            e.lo = lo;
            e.day_sec = ds;
            ds
        };
        Some((day_sec, hi, lo))
    }

    #[inline(always)]
    fn parse_civil_datetime_19_sec(&mut self, b: &[u8]) -> Option<i64> {
        let (day_sec, _, _) = self.parse_civil_date_sec(b)?;
        let hms_sec = parse_hms_sec(b)?;
        Some(day_sec + hms_sec)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn parse_f1_sec_with_date(&mut self, b: &[u8]) -> Option<(i64, u64, u16, i64)> {
        if b.len() == 20 && b[19] == b'Z' {
            let (day_sec, hi, lo) = self.parse_civil_date_sec(b)?;
            let hms_sec = parse_hms_sec(b)?;
            Some((day_sec + hms_sec, hi, lo, day_sec))
        } else {
            None
        }
    }

    #[cold]
    #[inline(never)]
    fn parse_f1_sec_hint_slow(
        &mut self,
        b: &[u8],
        hms_sec: i64,
    ) -> Option<(i64, u64, u16, i64)> {
        let (day_sec, hi, lo) = self.parse_civil_date_sec(b)?;
        Some((day_sec + hms_sec, hi, lo, day_sec))
    }

    #[inline(always)]
    pub fn parse_f1_sec_padded_with_hint(
        &mut self,
        padded: &[u8],
        start: usize,
        len: usize,
    ) -> Option<(i64, u64, u16, i64)> {
        debug_assert!(padded.len() >= start + 32);
        if len != 20 {
            return None;
        }
        let ptr = unsafe { padded.as_ptr().add(start) };
        let w0_ne = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
        let lo2 = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
        let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };
        let sep_ok = (unsafe { *ptr.add(10) } == b'T') & (unsafe { *ptr.add(19) } == b'Z');
        let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
        let idx = (((lo2 as usize & 3) << 4) + (((lo2 >> 8) as usize) & 15)) & 63;
        let e = unsafe { *self.entries.get_unchecked(idx) };
        if (e.hi == w0_ne) & (e.lo == lo2) & sep_ok & hms_ok {
            return Some((e.day_sec + hms_sec, w0_ne, lo2, e.day_sec));
        }
        if !sep_ok || !hms_ok {
            return None;
        }
        let s = unsafe { padded.get_unchecked(start..start + 20) };
        self.parse_f1_sec_hint_slow(s, hms_sec)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn parse_f1_ms(&mut self, b: &[u8]) -> Option<i64> {
        self.parse_f1_sec_with_date(b).map(|(s, _, _, _)| s * MS_SECOND)
    }

    #[inline(always)]
    fn parse_ts_ms_inner<const HAS_HINT: bool>(
        &mut self,
        b: &[u8],
        hint_hi: u64,
        hint_lo: u16,
        hint_day_sec: i64,
    ) -> Option<i64> {
        let len = b.len();
        if len == 20 && b[19] == b'Z' {
            if HAS_HINT {
                if b[10] != b'T' {
                    return None;
                }
                let ptr = b.as_ptr();
                let hi = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
                let lo = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
                let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };
                let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
                if !hms_ok {
                    return None;
                }
                let day_sec = if hi == hint_hi && lo == hint_lo {
                    hint_day_sec
                } else {
                    let (ds, _, _) = self.parse_civil_date_sec(b)?;
                    ds
                };
                return Some((day_sec + hms_sec) * MS_SECOND);
            }
            let sec = self.parse_civil_datetime_19_sec(b)?;
            return Some(sec * MS_SECOND);
        }
        if len == 13 {
            let ptr = b.as_ptr();
            let hi8 = unsafe { u64::from_le_bytes(*(ptr as *const [u8; 8])) };
            let lo8 = unsafe { u64::from_le_bytes(*(ptr.add(5) as *const [u8; 8])) };
            if is_8_ascii_digits(hi8) && is_8_ascii_digits(lo8) {
                let tail5 = parse_8_ascii_digits((lo8 & 0xFFFF_FFFF_FF00_0000) | 0x0030_3030);
                return Some(parse_8_ascii_digits(hi8) as i64 * 100_000 + tail5 as i64);
            }
            return None;
        }
        if len == 25 && (b[19] == b'+' || b[19] == b'-') && b[22] == b':' {
            let ptr = b.as_ptr();
            if b[10] != b'T' {
                return None;
            }
            let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };
            let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
            if !hms_ok {
                return None;
            }
            let day_sec = if HAS_HINT {
                let hi = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
                let lo = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
                if hi == hint_hi && lo == hint_lo {
                    hint_day_sec
                } else {
                    let (ds, _, _) = self.parse_civil_date_sec(b)?;
                    ds
                }
            } else {
                let (ds, _, _) = self.parse_civil_date_sec(b)?;
                ds
            };
            let oh = d2(b[20], b[21])?;
            let om = d2(b[23], b[24])?;
            if oh > 23 || om > 59 {
                return None;
            }
            let base = (day_sec + hms_sec) * MS_SECOND;
            let off_ms = (oh * 3_600 + om * 60) * MS_SECOND;
            return Some(if b[19] == b'+' {
                base - off_ms
            } else {
                base + off_ms
            });
        }
        if len == 0 {
            return None;
        }
        parse_f3_ms(b)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn parse_ts_ms(&mut self, b: &[u8]) -> Option<i64> {
        self.parse_ts_ms_inner::<false>(b, 0, 0, 0)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn parse_ts_ms_with_hint(
        &mut self,
        b: &[u8],
        hint_hi: u64,
        hint_lo: u16,
        hint_day_sec: i64,
    ) -> Option<i64> {
        self.parse_ts_ms_inner::<true>(b, hint_hi, hint_lo, hint_day_sec)
    }

    #[cold]
    #[inline(never)]
    fn parse_ts_ms_with_hint_slow(
        &mut self,
        b: &[u8],
        hint_hi: u64,
        hint_lo: u16,
        hint_day_sec: i64,
    ) -> Option<i64> {
        self.parse_ts_ms_inner::<true>(b, hint_hi, hint_lo, hint_day_sec)
    }

    #[inline(always)]
    pub fn parse_ts_ms_padded_hint(
        &mut self,
        padded: &[u8],
        start: usize,
        len: usize,
        hint_hi: u64,
        hint_lo: u16,
        hint_day_sec: i64,
    ) -> Option<i64> {
        debug_assert!(padded.len() >= start + 32);
        let ptr = unsafe { padded.as_ptr().add(start) };
        let is_f1 = (len == 20) & (unsafe { *ptr.add(19) } == b'Z');
        let is_f3 = len == 13;
        if is_f1 | is_f3 {
            let w0 = unsafe { u64::from_le_bytes(*(ptr as *const [u8; 8])) };
            let w0_ne = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
            let w5 = unsafe { u64::from_le_bytes(*(ptr.add(5) as *const [u8; 8])) };
            let lo2 = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
            let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };

            let f3_ok = is_8_ascii_digits(w0) & is_8_ascii_digits(w5);
            let f3_ms = (parse_8_ascii_digits(w0) as i64)
                .wrapping_mul(100_000)
                .wrapping_add(
                    parse_8_ascii_digits((w5 & 0xFFFF_FFFF_FF00_0000) | 0x0030_3030) as i64,
                );

            let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
            let f1_ok =
                (w0_ne == hint_hi) & (lo2 == hint_lo) & (unsafe { *ptr.add(10) } == b'T') & hms_ok;
            let f1_ms = hint_day_sec.wrapping_add(hms_sec).wrapping_mul(MS_SECOND);

            let fast_ok = if is_f1 { f1_ok } else { f3_ok };
            if fast_ok {
                return Some(if is_f1 { f1_ms } else { f3_ms });
            }
        }
        let s = unsafe { padded.get_unchecked(start..start + len) };
        self.parse_ts_ms_with_hint_slow(s, hint_hi, hint_lo, hint_day_sec)
    }

    #[cold]
    #[inline(never)]
    fn parse_ts_ms_slow(&mut self, b: &[u8]) -> Option<i64> {
        self.parse_ts_ms_inner::<false>(b, 0, 0, 0)
    }

    #[inline(always)]
    pub fn parse_ts_ms_padded_dc(
        &mut self,
        padded: &[u8],
        start: usize,
        len: usize,
    ) -> Option<i64> {
        debug_assert!(padded.len() >= start + 32);
        let ptr = unsafe { padded.as_ptr().add(start) };
        let is_f1 = (len == 20) & (unsafe { *ptr.add(19) } == b'Z');
        let is_f3 = len == 13;
        if is_f1 | is_f3 {
            let w0 = unsafe { u64::from_le_bytes(*(ptr as *const [u8; 8])) };
            let w0_ne = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
            let w5 = unsafe { u64::from_le_bytes(*(ptr.add(5) as *const [u8; 8])) };
            let lo2 = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
            let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };

            let f3_ok = is_8_ascii_digits(w0) & is_8_ascii_digits(w5);
            let f3_ms = (parse_8_ascii_digits(w0) as i64)
                .wrapping_mul(100_000)
                .wrapping_add(
                    parse_8_ascii_digits((w5 & 0xFFFF_FFFF_FF00_0000) | 0x0030_3030) as i64,
                );

            let idx = (((lo2 as usize & 3) << 4) + (((lo2 >> 8) as usize) & 15)) & 63;
            let e = unsafe { *self.entries.get_unchecked(idx) };
            let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
            let f1_ok =
                (e.hi == w0_ne) & (e.lo == lo2) & (unsafe { *ptr.add(10) } == b'T') & hms_ok;
            let f1_ms = e.day_sec.wrapping_add(hms_sec).wrapping_mul(MS_SECOND);

            let fast_ok = if is_f1 { f1_ok } else { f3_ok };
            if fast_ok {
                return Some(if is_f1 { f1_ms } else { f3_ms });
            }
        }
        let s = unsafe { padded.get_unchecked(start..start + len) };
        self.parse_ts_ms_slow(s)
    }

    #[cfg(test)]
    #[inline(always)]
    pub fn parse_ts_ms_cached(
        &mut self,
        b: &[u8],
        last_hi: &mut u64,
        last_lo: &mut u16,
        last_day_sec: &mut i64,
    ) -> Option<i64> {
        let len = b.len();
        if len == 20 && b[19] == b'Z' {
            if b[10] != b'T' {
                return None;
            }
            let ptr = b.as_ptr();
            let hi = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
            let lo = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
            let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };
            let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
            if !hms_ok {
                return None;
            }
            let day_sec = if hi == *last_hi && lo == *last_lo {
                *last_day_sec
            } else {
                let (ds, d_hi, d_lo) = self.parse_civil_date_sec(b)?;
                *last_hi = d_hi;
                *last_lo = d_lo;
                *last_day_sec = ds;
                ds
            };
            return Some((day_sec + hms_sec) * MS_SECOND);
        }
        if len == 13 {
            let ptr = b.as_ptr();
            let hi8 = unsafe { u64::from_le_bytes(*(ptr as *const [u8; 8])) };
            let lo8 = unsafe { u64::from_le_bytes(*(ptr.add(5) as *const [u8; 8])) };
            if is_8_ascii_digits(hi8) && is_8_ascii_digits(lo8) {
                let tail5 = parse_8_ascii_digits((lo8 & 0xFFFF_FFFF_FF00_0000) | 0x0030_3030);
                return Some(parse_8_ascii_digits(hi8) as i64 * 100_000 + tail5 as i64);
            }
            return None;
        }
        if len == 25 && (b[19] == b'+' || b[19] == b'-') && b[22] == b':' {
            if b[10] != b'T' {
                return None;
            }
            let ptr = b.as_ptr();
            let hi = unsafe { u64::from_ne_bytes(*(ptr as *const [u8; 8])) };
            let lo = unsafe { u16::from_ne_bytes(*(ptr.add(8) as *const [u8; 2])) };
            let w11 = unsafe { u64::from_le_bytes(*(ptr.add(11) as *const [u8; 8])) };
            let (hms_sec, hms_ok) = parse_hms_sec_u64(w11);
            if !hms_ok {
                return None;
            }
            let oh = d2(b[20], b[21])?;
            let om = d2(b[23], b[24])?;
            if oh > 23 || om > 59 {
                return None;
            }
            let day_sec = if hi == *last_hi && lo == *last_lo {
                *last_day_sec
            } else {
                let (ds, d_hi, d_lo) = self.parse_civil_date_sec(b)?;
                *last_hi = d_hi;
                *last_lo = d_lo;
                *last_day_sec = ds;
                ds
            };
            let base = (day_sec + hms_sec) * MS_SECOND;
            let off_ms = (oh * 3_600 + om * 60) * MS_SECOND;
            return Some(if b[19] == b'+' {
                base - off_ms
            } else {
                base + off_ms
            });
        }
        if len == 0 {
            return None;
        }
        parse_f3_ms(b)
    }
}

#[inline(always)]
fn parse_f3_ms(b: &[u8]) -> Option<i64> {
    let len = b.len();
    if len <= 18 {
        let mut acc: i64 = 0;
        for &ch in b {
            let d = ch.wrapping_sub(b'0');
            if d >= 10 {
                return None;
            }
            acc = acc * 10 + d as i64;
        }
        return Some(acc);
    }
    let mut acc: i64 = 0;
    let mut overflow = false;
    for &ch in b {
        let d = ch.wrapping_sub(b'0');
        if d >= 10 {
            return None;
        }
        if !overflow {
            match acc.checked_mul(10).and_then(|v| v.checked_add(d as i64)) {
                Some(v) => acc = v,
                None => overflow = true,
            }
        }
    }
    if overflow {
        None
    } else {
        Some(acc)
    }
}

#[inline(always)]
pub fn parse_ts_ms(b: &[u8]) -> Option<i64> {
    let len = b.len();
    if len == 0 {
        return None;
    }
    if len == 20 && b[19] == b'Z' {
        return parse_civil_datetime_19(b);
    }
    if len == 13 {
        let hi8 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let lo8 = u64::from_le_bytes(b[5..13].try_into().unwrap());
        if is_8_ascii_digits(hi8) && is_8_ascii_digits(lo8) {
            let tail5 = parse_8_ascii_digits((lo8 & 0xFFFF_FFFF_FF00_0000) | 0x0030_3030);
            return Some(parse_8_ascii_digits(hi8) as i64 * 100_000 + tail5 as i64);
        }
        return None;
    }
    if len == 25 && (b[19] == b'+' || b[19] == b'-') && b[22] == b':' {
        let base = parse_civil_datetime_19(b)?;
        let oh = d2(b[20], b[21])?;
        let om = d2(b[23], b[24])?;
        if oh > 23 || om > 59 {
            return None;
        }
        let off_ms = (oh * 3_600 + om * 60) * MS_SECOND;
        return Some(if b[19] == b'+' {
            base - off_ms
        } else {
            base + off_ms
        });
    }
    parse_f3_ms(b)
}

#[inline(always)]
pub fn parse_price_cents(b: &[u8]) -> Option<u32> {
    if b.is_empty() {
        return None;
    }
    if b.len() <= 8 {
        let mut acc: u32 = 0;
        for &ch in b {
            let d = ch.wrapping_sub(b'0');
            if d >= 10 {
                return None;
            }
            acc = acc * 10 + d as u32;
        }
        if (1..=10_000_000).contains(&acc) {
            return Some(acc);
        }
        return None;
    }
    let mut acc: u64 = 0;
    let mut over = false;
    for &ch in b {
        let d = ch.wrapping_sub(b'0');
        if d >= 10 {
            return None;
        }
        if !over {
            acc = acc * 10 + d as u64;
            if acc > 10_000_000 {
                over = true;
            }
        }
    }
    if !over && (1..=10_000_000).contains(&acc) {
        Some(acc as u32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline(always)]
    fn parse_f1_ms(b: &[u8]) -> Option<i64> {
        if b.len() == 20 && b[19] == b'Z' {
            parse_civil_datetime_19(b)
        } else {
            None
        }
    }

    #[test]
    fn test_f1_f2_f3_timestamps() {
        let expected = parse_f1_ms(b"2026-10-03T23:58:10Z").unwrap();
        assert_eq!(expected, 1_791_071_890_000);
        assert_eq!(parse_ts_ms(b"2026-10-03T23:58:10Z"), Some(expected));
        assert_eq!(parse_ts_ms(b"2026-10-03T19:58:10-04:00"), Some(expected));
        assert_eq!(parse_ts_ms(b"2026-10-04T01:28:10+01:30"), Some(expected));
        assert_eq!(parse_ts_ms(b"1791071890000"), Some(expected));
        assert_eq!(parse_ts_ms(b"2026-10-03T23:58:10-00:00"), Some(expected));

        // Leap years
        assert!(parse_f1_ms(b"2028-02-29T00:00:00Z").is_some());
        assert!(parse_f1_ms(b"2024-02-29T23:59:59Z").is_some());
        assert!(parse_f1_ms(b"2000-02-29T00:00:00Z").is_some());
        assert!(parse_f1_ms(b"2027-02-29T00:00:00Z").is_none());
        assert!(parse_f1_ms(b"1900-02-29T00:00:00Z").is_none());

        for bad in [
            b"".as_slice(),
            b"2026-10-03T23:58:10.000Z",
            b"2026-10-03T23:58:10z",
            b"2026-10-03t23:58:10Z",
            b"2026-10-03 23:58:10Z",
            b"2026-10-03T23:58:10",
            b"2026-13-03T23:58:10Z",
            b"2026-02-30T23:58:10Z",
            b"2026-10-03T24:00:00Z",
            b"2026-10-03T23:58:60Z",
            b"2026-10-03T23:58:10+24:00",
            b"2026-10-03T23:58:10+05:60",
            b"2026-10-03T23:58:10+0200",
            b"1791071890000.0",
            b"1.79e12",
            b"-5",
            b"2026-10-03T23:58:10Z\r",
            b"179107189000a",
            b"179107189000:",
            "٢٥٠".as_bytes(),
        ] {
            assert_eq!(
                parse_ts_ms(bad),
                None,
                "expected None for {:?}",
                String::from_utf8_lossy(bad)
            );
        }

        let mut zeros = vec![b'0'; 300];
        zeros.extend_from_slice(b"1791021600000");
        assert_eq!(parse_ts_ms(&zeros), Some(1_791_021_600_000));
        let huge = vec![b'9'; 500];
        assert_eq!(parse_ts_ms(&huge), None);
        assert_eq!(parse_ts_ms(&vec![b'0'; 300]), Some(0));

        // Exhaustive check of SWAR is_8_ascii_digits across all 256 byte values in every lane
        for lane in 0..8 {
            for b in 0u8..=255 {
                let mut arr = [b'0'; 8];
                arr[lane] = b;
                let expected_ok = (b'0'..=b'9').contains(&b);
                assert_eq!(is_8_ascii_digits(u64::from_le_bytes(arr)), expected_ok);
            }
        }

        let mut cache = DateCache::new();
        let samples: &[&[u8]] = &[
            b"2026-10-03T23:58:10Z",
            b"2026-10-03T12:00:00Z",
            b"2026-10-03t12:00:00Z",
            b"2026-10-03T24:00:00Z",
            b"2026-10-03T19:58:10-04:00",
            b"2028-02-29T00:00:00Z",
            b"2028-02-29T23:59:59+02:00",
            b"2027-02-29T00:00:00Z",
            b"2026-02-30T01:02:03Z",
            b"2026-13-01T01:02:03Z",
            b"2028-02-29T23:59:60Z",
            b"1969-12-31T23:59:59Z",
            b"0000-01-01T00:00:00Z",
            b"1791071890000",
            b"179107189000/",
            b"2026-10-03T00:00:00Z",
            b"2026-10-03T00:00:00+24:00",
        ];
        for _pass in 0..3 {
            for &s in samples {
                assert_eq!(
                    cache.parse_ts_ms(s),
                    parse_ts_ms(s),
                    "mismatch on {:?}",
                    String::from_utf8_lossy(s)
                );
                assert_eq!(
                    cache.parse_f1_ms(s),
                    parse_f1_ms(s),
                    "f1 mismatch on {:?}",
                    String::from_utf8_lossy(s)
                );
                assert_eq!(
                    cache.parse_f1_sec_with_date(s).map(|v| v.0 * MS_SECOND),
                    parse_f1_ms(s),
                    "f1_sec mismatch on {:?}",
                    String::from_utf8_lossy(s)
                );
                let mut pad = vec![0xAAu8; 4 + s.len() + 40];
                pad[4..4 + s.len()].copy_from_slice(s);
                if let Some((_, h_hi, h_lo, h_day_sec)) =
                    cache.parse_f1_sec_with_date(b"2026-10-03T12:00:00Z")
                {
                    assert_eq!(
                        cache.parse_ts_ms_with_hint(s, h_hi, h_lo, h_day_sec),
                        parse_ts_ms(s),
                        "hint mismatch on {:?}",
                        String::from_utf8_lossy(s)
                    );
                    assert_eq!(
                        cache.parse_ts_ms_padded_hint(&pad, 4, s.len(), h_hi, h_lo, h_day_sec),
                        parse_ts_ms(s),
                        "padded hint mismatch on {:?}",
                        String::from_utf8_lossy(s)
                    );
                }
                assert_eq!(
                    cache.parse_ts_ms_padded_dc(&pad, 4, s.len()),
                    parse_ts_ms(s),
                    "padded dc mismatch on {:?}",
                    String::from_utf8_lossy(s)
                );
                let mut l_hi = u64::MAX;
                let mut l_lo = 0u16;
                let mut l_day_sec = 0i64;
                assert_eq!(
                    cache.parse_ts_ms_cached(s, &mut l_hi, &mut l_lo, &mut l_day_sec),
                    parse_ts_ms(s),
                    "cached click mismatch on {:?}",
                    String::from_utf8_lossy(s)
                );
            }
        }
        // Repeated F1/F2 hits on cached clicks + padded_dc (exercise fast paths + day transitions)
        let mut l_hi = u64::MAX;
        let mut l_lo = 0u16;
        let mut l_day_sec = 0i64;
        for s in [
            b"2026-10-03T01:02:03Z".as_slice(),
            b"2026-10-03T23:59:59Z".as_slice(),
            b"2026-10-03T19:58:10-04:00".as_slice(),
            b"1791071890000".as_slice(),
            b"2026-10-03T12:00:00Z".as_slice(),
            b"2026-10-04T00:00:01Z".as_slice(),
            b"2026-10-04T05:06:07Z".as_slice(),
            b"2026-10-04T05:06:07Q".as_slice(),
            b"2026-02-29T00:00:00Z".as_slice(),
            b"short".as_slice(),
            b"2027-03-15T12:34:56+00:00".as_slice(),
            b"2027-03-15T12:34:56-00:00".as_slice(),
            b"2027-03-15T12:34:56+23:59".as_slice(),
            b"2027-03-15T12:34:56-23:59".as_slice(),
            b"2027-03-15T12:34:56+24:00".as_slice(),
            b"2027-03-15T12:34:56+05:60".as_slice(),
            b"2027-03-15T12:34:56+0200".as_slice(),
            b"2027-03-15T12:34:56+0a:00".as_slice(),
            b"2027-03-15T12:34:56+\xef\xbc\x90\xef\xbc\x95:00".as_slice(),
        ] {
            let expected = parse_ts_ms(s);
            assert_eq!(
                cache.parse_ts_ms_cached(s, &mut l_hi, &mut l_lo, &mut l_day_sec),
                expected
            );
            let mut pad = vec![0x5Au8; 4 + s.len() + 40];
            pad[4..4 + s.len()].copy_from_slice(s);
            assert_eq!(
                cache.parse_ts_ms_padded_dc(&pad, 4, s.len()),
                expected
            );
            let expected_f1_sec = if s.len() == 20 && s[19] == b'Z' {
                expected.map(|ms| ms / MS_SECOND)
            } else {
                None
            };
            assert_eq!(
                cache.parse_f1_sec_padded_with_hint(&pad, 4, s.len()).map(|v| v.0),
                expected_f1_sec
            );
        }
        // Cold DateCache miss -> warm DateCache hit on F2 timestamps + padded_hint cross-midnight miss
        let mut f2_cache = DateCache::new();
        for s in [
            b"2027-07-04T01:02:03+05:30".as_slice(),
            b"2027-07-04T23:59:59-04:00".as_slice(),
        ] {
            let mut pad = vec![0x5Au8; 4 + s.len() + 40];
            pad[4..4 + s.len()].copy_from_slice(s);
            assert_eq!(f2_cache.parse_ts_ms_padded_dc(&pad, 4, s.len()), parse_ts_ms(s));
        }
        let ing = b"2026-10-03T00:05:00Z";
        let mut ing_pad = vec![0x5Au8; 4 + ing.len() + 40];
        ing_pad[4..4 + ing.len()].copy_from_slice(ing);
        let (_, h_hi, h_lo, h_day_sec) = f2_cache
            .parse_f1_sec_padded_with_hint(&ing_pad, 4, ing.len())
            .unwrap();
        for ev_s in [
            b"2026-10-03T00:01:00Z".as_slice(),       // same-day hint hit
            b"2026-10-02T23:59:59Z".as_slice(),       // cross-midnight hint miss
            b"2026-10-02T20:01:00-04:00".as_slice(),  // F2 offset
            b"2026-10-03T01:31:00+01:30".as_slice(),  // F2 offset
            b"1791071890000".as_slice(),              // F3 13 digits
            b"bad_ts".as_slice(),                     // invalid
            b"2026-10-02T25:00:00Z".as_slice(),       // invalid hour
        ] {
            let mut ev_pad = vec![0x5Au8; 4 + ev_s.len() + 40];
            ev_pad[4..4 + ev_s.len()].copy_from_slice(ev_s);
            assert_eq!(
                f2_cache.parse_ts_ms_padded_hint(&ev_pad, 4, ev_s.len(), h_hi, h_lo, h_day_sec),
                parse_ts_ms(ev_s)
            );
            assert_eq!(
                f2_cache.parse_ts_ms_padded_dc(&ev_pad, 4, ev_s.len()),
                parse_ts_ms(ev_s)
            );
        }
    }

    #[test]
    fn test_price_cents() {
        assert_eq!(parse_price_cents(b"1"), Some(1));
        assert_eq!(parse_price_cents(b"0250"), Some(250));
        assert_eq!(parse_price_cents(b"10000000"), Some(10_000_000));

        let mut leading = vec![b'0'; 300];
        leading.extend_from_slice(b"250");
        assert_eq!(parse_price_cents(&leading), Some(250));

        assert_eq!(parse_price_cents(b"0"), None);
        assert_eq!(parse_price_cents(b"00"), None);
        assert_eq!(parse_price_cents(b"10000001"), None);
        assert_eq!(parse_price_cents(b"-5"), None);
        assert_eq!(parse_price_cents(b"19.99"), None);
        assert_eq!(parse_price_cents(b"900\r"), None);
        assert_eq!(parse_price_cents(&vec![b'9'; 500]), None);
    }
}
