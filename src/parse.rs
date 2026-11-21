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
fn parse_hms_sec(b: &[u8]) -> Option<i64> {
    let t8 = u64::from_le_bytes(b[11..19].try_into().unwrap());
    if (t8 & 0x0000_FF00_00FF_0000) != 0x0000_3A00_003A_0000 {
        return None;
    }
    let zeroed = t8 ^ 0x0000_0A00_000A_0000;
    if !is_8_ascii_digits(zeroed) {
        return None;
    }
    let d = zeroed & 0x0F0F_0F0F_0F0F_0F0F;
    let h = ((d & 0xFF) * 10 + ((d >> 8) & 0xFF)) as i64;
    let m = (((d >> 24) & 0xFF) * 10 + ((d >> 32) & 0xFF)) as i64;
    let s = (((d >> 48) & 0xFF) * 10 + ((d >> 56) & 0xFF)) as i64;
    if (h > 23) | (m > 59) | (s > 59) {
        return None;
    }
    Some(h * 3_600 + m * 60 + s)
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
#[repr(C, align(16))]
struct DateCacheEntry {
    hi: u64,
    day_days: i32,
    lo: u16,
    _pad: u16,
}

const _: () = assert!(std::mem::size_of::<DateCacheEntry>() == 16);

#[derive(Clone)]
pub struct DateCache {
    entries: [DateCacheEntry; 64],
}

impl DateCache {
    pub fn new() -> Self {
        Self {
            entries: [DateCacheEntry {
                hi: u64::MAX,
                day_days: 0,
                lo: 0,
                _pad: 0,
            }; 64],
        }
    }

    #[inline(always)]
    fn parse_civil_date_days(&mut self, b: &[u8]) -> Option<(i32, u64, u16)> {
        if b[10] != b'T' {
            return None;
        }
        let hi = u64::from_ne_bytes(b[0..8].try_into().unwrap());
        let lo = u16::from_ne_bytes(b[8..10].try_into().unwrap());
        let idx = (((b[8] as usize & 3) * 10 + (b[9] as usize & 15))
            ^ ((b[6] as usize & 1) << 5))
            & 63;
        let e = &mut self.entries[idx];
        let dd = if e.hi == hi && e.lo == lo {
            e.day_days
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
            let dd = days_from_civil(year, month, day) as i32;
            e.hi = hi;
            e.lo = lo;
            e.day_days = dd;
            dd
        };
        Some((dd, hi, lo))
    }

    #[inline(always)]
    fn parse_civil_datetime_19_sec(&mut self, b: &[u8]) -> Option<i64> {
        let (day_days, _, _) = self.parse_civil_date_days(b)?;
        let hms_sec = parse_hms_sec(b)?;
        Some((day_days as i64) * 86_400 + hms_sec)
    }

    #[inline(always)]
    fn parse_civil_datetime_19_sec_hint(
        &mut self,
        b: &[u8],
        hint_hi: u64,
        hint_lo: u16,
        hint_dd: i32,
    ) -> Option<i64> {
        if b[10] != b'T' {
            return None;
        }
        let hi = u64::from_ne_bytes(b[0..8].try_into().unwrap());
        let lo = u16::from_ne_bytes(b[8..10].try_into().unwrap());
        let dd = if hi == hint_hi && lo == hint_lo {
            hint_dd
        } else {
            let (d, _, _) = self.parse_civil_date_days(b)?;
            d
        };
        let hms_sec = parse_hms_sec(b)?;
        Some((dd as i64) * 86_400 + hms_sec)
    }

    #[inline(always)]
    pub fn parse_f1_sec_with_date(&mut self, b: &[u8]) -> Option<(i64, u64, u16, i32)> {
        if b.len() == 20 && b[19] == b'Z' {
            let (dd, hi, lo) = self.parse_civil_date_days(b)?;
            let hms_sec = parse_hms_sec(b)?;
            Some(((dd as i64) * 86_400 + hms_sec, hi, lo, dd))
        } else {
            None
        }
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
        hint_dd: i32,
    ) -> Option<i64> {
        let len = b.len();
        if len == 0 {
            return None;
        }
        if len == 20 && b[19] == b'Z' {
            let sec = if HAS_HINT {
                self.parse_civil_datetime_19_sec_hint(b, hint_hi, hint_lo, hint_dd)?
            } else {
                self.parse_civil_datetime_19_sec(b)?
            };
            return Some(sec * MS_SECOND);
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
            let base = if HAS_HINT {
                self.parse_civil_datetime_19_sec_hint(b, hint_hi, hint_lo, hint_dd)? * MS_SECOND
            } else {
                self.parse_civil_datetime_19_sec(b)? * MS_SECOND
            };
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
    pub fn parse_ts_ms(&mut self, b: &[u8]) -> Option<i64> {
        self.parse_ts_ms_inner::<false>(b, 0, 0, 0)
    }

    #[inline(always)]
    pub fn parse_ts_ms_with_hint(
        &mut self,
        b: &[u8],
        hint_hi: u64,
        hint_lo: u16,
        hint_dd: i32,
    ) -> Option<i64> {
        self.parse_ts_ms_inner::<true>(b, hint_hi, hint_lo, hint_dd)
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
                if let Some((_, h_hi, h_lo, h_dd)) =
                    cache.parse_f1_sec_with_date(b"2026-10-03T12:00:00Z")
                {
                    assert_eq!(
                        cache.parse_ts_ms_with_hint(s, h_hi, h_lo, h_dd),
                        parse_ts_ms(s),
                        "hint mismatch on {:?}",
                        String::from_utf8_lossy(s)
                    );
                }
            }
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
