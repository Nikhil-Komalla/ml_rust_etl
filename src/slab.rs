use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::{self, NonNull};

pub const USE_MADV_HUGEPAGE: bool = true;
const HUGE_SLAB_BYTES: usize = 4 * 1024 * 1024;

#[cfg(unix)]
mod os_mem {
    use std::os::raw::{c_int, c_void};

    pub const PROT_READ: c_int = 1;
    pub const PROT_WRITE: c_int = 2;
    pub const MAP_PRIVATE: c_int = 2;
    #[cfg(target_os = "linux")]
    pub const MAP_ANONYMOUS: c_int = 0x20;
    #[cfg(not(target_os = "linux"))]
    pub const MAP_ANONYMOUS: c_int = 0x1000;
    pub const MADV_HUGEPAGE: c_int = 14;
    pub const MAP_FAILED: *mut c_void = !0usize as *mut c_void;

    extern "C" {
        pub fn mmap(
            addr: *mut c_void,
            len: usize,
            prot: c_int,
            flags: c_int,
            fd: c_int,
            offset: i64,
        ) -> *mut c_void;
        pub fn munmap(addr: *mut c_void, len: usize) -> c_int;
        pub fn madvise(addr: *mut c_void, len: usize, advice: c_int) -> c_int;
    }
}

enum SlabBacking {
    #[cfg(unix)]
    Mmap(*mut u8, usize),
    Heap(#[allow(dead_code)] Vec<u8>),
}

impl Drop for SlabBacking {
    fn drop(&mut self) {
        match *self {
            #[cfg(unix)]
            SlabBacking::Mmap(ptr, len) => unsafe {
                let _ = os_mem::munmap(ptr as *mut std::os::raw::c_void, len);
            },
            SlabBacking::Heap(_) => {}
        }
    }
}

pub struct MutChunkRef<T: Copy> {
    pub ptr: *mut T,
    pub len: usize,
}

unsafe impl<T: Copy + Send> Send for MutChunkRef<T> {}
unsafe impl<T: Copy + Sync> Sync for MutChunkRef<T> {}

impl<T: Copy> MutChunkRef<T> {
    #[inline(always)]
    pub unsafe fn as_slice(&self) -> &[T] {
        std::slice::from_raw_parts(self.ptr, self.len)
    }
}

pub const HUGE_BUF_MIN_BYTES: usize = 512 * 1024;
const HUGE_PAGE_ALIGN: usize = 2 * 1024 * 1024;

pub unsafe trait Zeroable: Copy {}
unsafe impl Zeroable for u32 {}
unsafe impl Zeroable for u64 {}

enum HugeBacking<T: Copy> {
    #[cfg(unix)]
    Mmap(*mut T, usize, usize),
    Heap(Vec<T>),
}

pub struct HugeBuf<T: Copy> {
    backing: HugeBacking<T>,
}

unsafe impl<T: Copy + Send> Send for HugeBuf<T> {}
unsafe impl<T: Copy + Sync> Sync for HugeBuf<T> {}

impl<T: Copy> Default for HugeBuf<T> {
    fn default() -> Self {
        Self {
            backing: HugeBacking::Heap(Vec::new()),
        }
    }
}

impl<T: Copy> Drop for HugeBuf<T> {
    fn drop(&mut self) {
        if let HugeBacking::Mmap(ptr, _, mmap_bytes) = self.backing {
            #[cfg(unix)]
            unsafe {
                let _ = os_mem::munmap(ptr as *mut std::os::raw::c_void, mmap_bytes);
            }
        }
    }
}

impl<T: Copy> HugeBuf<T> {
    pub fn new_zeroed(len: usize) -> Self
    where
        T: Zeroable,
    {
        assert!(size_of::<T>() > 0 && align_of::<T>() <= 4096);
        if len == 0 {
            return Self::default();
        }
        let bytes = len.checked_mul(size_of::<T>()).expect("HugeBuf size overflow");
        #[cfg(unix)]
        if bytes >= HUGE_BUF_MIN_BYTES {
            let aligned_len = (bytes + HUGE_PAGE_ALIGN - 1) & !(HUGE_PAGE_ALIGN - 1);
            unsafe {
                let p = os_mem::mmap(
                    ptr::null_mut(),
                    aligned_len,
                    os_mem::PROT_READ | os_mem::PROT_WRITE,
                    os_mem::MAP_PRIVATE | os_mem::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p != os_mem::MAP_FAILED && !p.is_null() {
                    if USE_MADV_HUGEPAGE {
                        #[cfg(target_os = "linux")]
                        let _ = os_mem::madvise(p, aligned_len, os_mem::MADV_HUGEPAGE);
                    }
                    return Self {
                        backing: HugeBacking::Mmap(p as *mut T, len, aligned_len),
                    };
                }
            }
        }
        Self {
            backing: HugeBacking::Heap(vec![unsafe { std::mem::zeroed() }; len]),
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        match &self.backing {
            #[cfg(unix)]
            HugeBacking::Mmap(_, len, _) => *len,
            HugeBacking::Heap(v) => v.len(),
        }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const T {
        match &self.backing {
            #[cfg(unix)]
            HugeBacking::Mmap(ptr, _, _) => *ptr as *const T,
            HugeBacking::Heap(v) => v.as_ptr(),
        }
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        match &mut self.backing {
            #[cfg(unix)]
            HugeBacking::Mmap(ptr, _, _) => *ptr,
            HugeBacking::Heap(v) => v.as_mut_ptr(),
        }
    }
}

impl<T: Copy> std::ops::Deref for HugeBuf<T> {
    type Target = [T];

    #[inline(always)]
    fn deref(&self) -> &[T] {
        match &self.backing {
            #[cfg(unix)]
            HugeBacking::Mmap(ptr, len, _) => unsafe { std::slice::from_raw_parts(*ptr, *len) },
            HugeBacking::Heap(v) => v.as_slice(),
        }
    }
}

impl<T: Copy> std::ops::DerefMut for HugeBuf<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [T] {
        match &mut self.backing {
            #[cfg(unix)]
            HugeBacking::Mmap(ptr, len, _) => unsafe {
                std::slice::from_raw_parts_mut(*ptr, *len)
            },
            HugeBacking::Heap(v) => v.as_mut_slice(),
        }
    }
}

pub struct SlabArena {
    slabs: Vec<SlabBacking>,
    cur_ptr: *mut u8,
    cur_end: *mut u8,
    use_huge_from_start: bool,
}

unsafe impl Send for SlabArena {}
unsafe impl Sync for SlabArena {}

impl SlabArena {
    pub fn new(hint_bytes: usize) -> Self {
        Self {
            slabs: Vec::new(),
            cur_ptr: ptr::null_mut(),
            cur_end: ptr::null_mut(),
            use_huge_from_start: hint_bytes >= 512 * 1024,
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, min_bytes: usize) {
        let step_bytes = if self.use_huge_from_start || self.slabs.len() >= 2 {
            HUGE_SLAB_BYTES
        } else if self.slabs.len() == 1 {
            256 * 1024
        } else {
            64 * 1024
        };
        let need = min_bytes.max(step_bytes);

        #[cfg(unix)]
        if self.use_huge_from_start || need >= HUGE_SLAB_BYTES {
            let aligned_len = (need + HUGE_SLAB_BYTES - 1) & !(HUGE_SLAB_BYTES - 1);
            unsafe {
                let p = os_mem::mmap(
                    ptr::null_mut(),
                    aligned_len,
                    os_mem::PROT_READ | os_mem::PROT_WRITE,
                    os_mem::MAP_PRIVATE | os_mem::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if p != os_mem::MAP_FAILED && !p.is_null() {
                    if USE_MADV_HUGEPAGE {
                        #[cfg(target_os = "linux")]
                        let _ = os_mem::madvise(p, aligned_len, os_mem::MADV_HUGEPAGE);
                    }
                    let base = p as *mut u8;
                    self.slabs.push(SlabBacking::Mmap(base, aligned_len));
                    self.cur_ptr = base;
                    self.cur_end = base.add(aligned_len);
                    return;
                }
            }
        }

        let mut buf = vec![0u8; need + 64];
        let raw = buf.as_mut_ptr() as usize;
        let aligned = (raw + 63) & !63;
        let base = aligned as *mut u8;
        let usable = (raw + buf.len()) - aligned;
        self.slabs.push(SlabBacking::Heap(buf));
        self.cur_ptr = base;
        self.cur_end = unsafe { base.add(usable) };
    }

    #[inline(always)]
    pub fn alloc_aligned_64(&mut self, bytes: usize) -> NonNull<u8> {
        let bytes = (bytes + 63) & !63;
        let cur = self.cur_ptr as usize;
        let aligned = (cur + 63) & !63;
        let end = self.cur_end as usize;
        if aligned != 0 && aligned.saturating_add(bytes) <= end {
            self.cur_ptr = (aligned + bytes) as *mut u8;
            return unsafe { NonNull::new_unchecked(aligned as *mut u8) };
        }
        self.grow(bytes);
        let a = ((self.cur_ptr as usize) + 63) & !63;
        self.cur_ptr = (a + bytes) as *mut u8;
        unsafe { NonNull::new_unchecked(a as *mut u8) }
    }
}

pub struct SlabBuckets<T: Copy, const P: usize, const CHUNK: usize, const SWCB_W: usize = 4> {
    arena: SlabArena,
    swcb: *mut T,
    swcb_cnt: [u8; P],
    cur_ptrs: [*mut T; P],
    cur_lens: [u16; P],
    completed: Vec<Vec<MutChunkRef<T>>>,
    _marker: PhantomData<T>,
}

unsafe impl<T: Copy + Send, const P: usize, const CHUNK: usize, const SWCB_W: usize> Send
    for SlabBuckets<T, P, CHUNK, SWCB_W>
{
}

impl<T: Copy, const P: usize, const CHUNK: usize, const SWCB_W: usize>
    SlabBuckets<T, P, CHUNK, SWCB_W>
{
    pub fn new(hint_bytes: usize) -> Self {
        assert!(P > 0 && P.is_power_of_two());
        assert!(
            SWCB_W > 0
                && SWCB_W <= 255
                && CHUNK >= SWCB_W
                && CHUNK.is_power_of_two()
                && CHUNK <= u16::MAX as usize
        );
        assert!(align_of::<T>() <= 64);
        assert!(size_of::<T>() > 0);
        let mut arena = SlabArena::new(hint_bytes);
        let swcb_bytes = P * SWCB_W * size_of::<T>();
        let swcb = arena.alloc_aligned_64(swcb_bytes).as_ptr() as *mut T;
        let completed = (0..P).map(|_| Vec::new()).collect();
        Self {
            arena,
            swcb,
            swcb_cnt: [0u8; P],
            cur_ptrs: [ptr::null_mut(); P],
            cur_lens: [CHUNK as u16; P],
            completed,
            _marker: PhantomData,
        }
    }

    #[cold]
    #[inline(never)]
    fn alloc_next_chunk(&mut self, shard: usize, old_ptr: *mut T, old_len: usize) -> *mut T {
        if !old_ptr.is_null() {
            unsafe {
                self.completed.get_unchecked_mut(shard).push(MutChunkRef {
                    ptr: old_ptr,
                    len: old_len,
                });
            }
        }
        let chunk_bytes = CHUNK * size_of::<T>();
        let new_ptr = self.arena.alloc_aligned_64(chunk_bytes).as_ptr() as *mut T;
        unsafe {
            *self.cur_ptrs.get_unchecked_mut(shard) = new_ptr;
        }
        new_ptr
    }

    #[inline(always)]
    pub fn push(&mut self, shard: usize, val: T) {
        let base = shard * SWCB_W;
        let c = unsafe { *self.swcb_cnt.get_unchecked(shard) } as usize;
        unsafe {
            *self.swcb.add(base + c) = val;
        }
        let nc = c + 1;
        if nc < SWCB_W {
            unsafe {
                *self.swcb_cnt.get_unchecked_mut(shard) = nc as u8;
            }
        } else {
            self.flush_full_swcb(shard, base);
        }
    }

    #[inline(always)]
    fn flush_full_swcb(&mut self, shard: usize, base: usize) {
        let mut cur_ptr = unsafe { *self.cur_ptrs.get_unchecked(shard) };
        let mut cur_len = unsafe { *self.cur_lens.get_unchecked(shard) } as usize;
        if cur_len >= CHUNK {
            cur_ptr = self.alloc_next_chunk(shard, cur_ptr, cur_len);
            cur_len = 0;
        }

        let dst = unsafe { cur_ptr.add(cur_len) };
        let src = unsafe { self.swcb.add(base) };
        let bytes = SWCB_W * size_of::<T>();
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        if (bytes & 31) == 0 && ((dst as usize) & 31) == 0 {
            unsafe {
                use std::arch::x86_64::*;
                let src_b = src as *const u8;
                let dst_b = dst as *mut u8;
                let mut off = 0usize;
                while off < bytes {
                    let v = _mm256_load_si256(src_b.add(off) as *const __m256i);
                    _mm256_stream_si256(dst_b.add(off) as *mut __m256i, v);
                    off += 32;
                }
            }
            unsafe {
                *self.cur_lens.get_unchecked_mut(shard) = (cur_len + SWCB_W) as u16;
                *self.swcb_cnt.get_unchecked_mut(shard) = 0;
            }
            return;
        }
        unsafe {
            ptr::copy_nonoverlapping(src, dst, SWCB_W);
            *self.cur_lens.get_unchecked_mut(shard) = (cur_len + SWCB_W) as u16;
            *self.swcb_cnt.get_unchecked_mut(shard) = 0;
        }
    }

    pub fn finish(mut self) -> (SlabArena, Vec<Vec<MutChunkRef<T>>>) {
        for shard in 0..P {
            let cnt = self.swcb_cnt[shard] as usize;
            let cur_ptr = self.cur_ptrs[shard];
            let cur_len = self.cur_lens[shard] as usize;
            if cnt > 0 {
                let mut ptr = cur_ptr;
                let mut len = cur_len;
                if ptr.is_null() {
                    ptr = self.arena.alloc_aligned_64(cnt * size_of::<T>()).as_ptr() as *mut T;
                    len = 0;
                } else if len + cnt > CHUNK {
                    self.completed[shard].push(MutChunkRef { ptr, len });
                    ptr = self.arena.alloc_aligned_64(cnt * size_of::<T>()).as_ptr() as *mut T;
                    len = 0;
                }
                unsafe {
                    ptr::copy_nonoverlapping(self.swcb.add(shard * SWCB_W), ptr.add(len), cnt);
                }
                self.completed[shard].push(MutChunkRef {
                    ptr,
                    len: len + cnt,
                });
            } else if !cur_ptr.is_null() && cur_len > 0 {
                self.completed[shard].push(MutChunkRef {
                    ptr: cur_ptr,
                    len: cur_len,
                });
            }
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        unsafe {
            std::arch::x86_64::_mm_sfence();
        }
        (self.arena, self.completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huge_buf_and_slab_buckets() {
        let empty = HugeBuf::<u64>::new_zeroed(0);
        assert!(empty.is_empty());

        let mut small = HugeBuf::<u64>::new_zeroed(64);
        assert_eq!(small.len(), 64);
        assert!(small.iter().all(|&x| x == 0));
        small[0] = 42;
        small[63] = 99;
        assert_eq!(small[0] + small[63], 141);

        // >= HUGE_BUF_MIN_BYTES (1 MiB) exercises mmap + madvise path on Unix
        let mut large = HugeBuf::<u64>::new_zeroed(131_072);
        assert_eq!(large.len(), 131_072);
        assert_eq!(large[0], 0);
        assert_eq!(large[131_071], 0);
        large[1234] = 0xDEAD_BEEF;
        assert_eq!(large[1234], 0xDEAD_BEEF);

        // SlabBuckets across 0 (shard 0), partial (3), exact chunk (8), multi-chunk (19)
        let mut sb = SlabBuckets::<u64, 4, 8>::new(64 * 1024);
        for v in 1..=3u64 {
            sb.push(1, v);
        }
        for v in 10..18u64 {
            sb.push(2, v);
        }
        for v in 100..119u64 {
            sb.push(3, v);
        }
        let (_arena, chunks) = sb.finish();
        assert!(chunks[0].is_empty());
        let collect_shard = |s: usize| -> Vec<u64> {
            let mut out = Vec::new();
            for c in &chunks[s] {
                out.extend_from_slice(unsafe { c.as_slice() });
            }
            out
        };
        assert_eq!(collect_shard(1), vec![1, 2, 3]);
        assert_eq!(collect_shard(2), (10..18).collect::<Vec<u64>>());
        assert_eq!(collect_shard(3), (100..119).collect::<Vec<u64>>());

        // SlabBuckets with SWCB_W = 8 on 8B items (exercise 64B NT stream flushes & partial tail)
        let mut sb8 = SlabBuckets::<u64, 4, 16, 8>::new(64 * 1024);
        for v in 1..=7u64 {
            sb8.push(0, v);
        }
        for v in 10..26u64 {
            sb8.push(1, v);
        }
        for v in 100..137u64 {
            sb8.push(2, v);
        }
        let (_arena8, chunks8) = sb8.finish();
        let collect_shard8 = |s: usize| -> Vec<u64> {
            let mut out = Vec::new();
            for c in &chunks8[s] {
                out.extend_from_slice(unsafe { c.as_slice() });
            }
            out
        };
        assert_eq!(collect_shard8(0), (1..=7).collect::<Vec<u64>>());
        assert_eq!(collect_shard8(1), (10..26).collect::<Vec<u64>>());
        assert_eq!(collect_shard8(2), (100..137).collect::<Vec<u64>>());
        assert!(chunks8[3].is_empty());
    }
}
