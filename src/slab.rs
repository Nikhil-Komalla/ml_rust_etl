use std::marker::PhantomData;
use std::mem::{align_of, size_of};
use std::ptr::{self, NonNull};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

pub const USE_MADV_HUGEPAGE: bool = true;
const HUGE_SLAB_BYTES: usize = 4 * 1024 * 1024;

static RECYCLE_SLABS: AtomicBool = AtomicBool::new(false);

struct PoolEntry {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for PoolEntry {}

static DIRTY_SLAB_POOL: Mutex<Vec<PoolEntry>> = Mutex::new(Vec::new());

/// Enables or disables process-wide recycling of freed `mmap` slabs and huge buffers.
pub fn set_slab_recycling(enable: bool) {
    RECYCLE_SLABS.store(enable, Ordering::Release);
    if !enable {
        #[cfg(unix)]
        {
            let entries: Vec<PoolEntry> = {
                let mut pool = DIRTY_SLAB_POOL.lock().unwrap();
                std::mem::take(&mut *pool)
            };
            for e in entries {
                unsafe {
                    let _ = os_mem::munmap(e.ptr as *mut std::os::raw::c_void, e.len);
                }
            }
        }
    }
}

#[cfg(unix)]
#[inline]
fn recycle_or_munmap_raw(ptr: *mut u8, len: usize) {
    if RECYCLE_SLABS.load(Ordering::Acquire) {
        DIRTY_SLAB_POOL.lock().unwrap().push(PoolEntry { ptr, len });
    } else {
        unsafe {
            let _ = os_mem::munmap(ptr as *mut std::os::raw::c_void, len);
        }
    }
}

#[cfg(unix)]
#[inline]
fn pop_pooled_slab(min_bytes: usize) -> Option<PoolEntry> {
    if !RECYCLE_SLABS.load(Ordering::Acquire) {
        return None;
    }
    let mut pool = DIRTY_SLAB_POOL.lock().unwrap();
    let mut best_idx: Option<usize> = None;
    let mut best_len = 0usize;
    for (i, e) in pool.iter().enumerate() {
        if e.len >= min_bytes && e.len > best_len {
            best_len = e.len;
            best_idx = Some(i);
        }
    }
    best_idx.map(|i| pool.swap_remove(i))
}

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
            SlabBacking::Mmap(ptr, len) => recycle_or_munmap_raw(ptr, len),
            SlabBacking::Heap(_) => {}
        }
    }
}

#[derive(Clone, Copy)]
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
            recycle_or_munmap_raw(ptr as *mut u8, mmap_bytes);
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
    init_slab_bytes: usize,
}

unsafe impl Send for SlabArena {}
unsafe impl Sync for SlabArena {}

impl SlabArena {
    pub fn new(hint_bytes: usize) -> Self {
        let init_slab_bytes = if hint_bytes >= 2 * 1024 * 1024 {
            let rounded = (hint_bytes + HUGE_PAGE_ALIGN - 1) & !(HUGE_PAGE_ALIGN - 1);
            rounded.clamp(HUGE_SLAB_BYTES, 128 * 1024 * 1024)
        } else {
            HUGE_SLAB_BYTES
        };
        Self {
            slabs: Vec::new(),
            cur_ptr: ptr::null_mut(),
            cur_end: ptr::null_mut(),
            use_huge_from_start: hint_bytes >= 512 * 1024,
            init_slab_bytes,
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, min_bytes: usize) {
        let step_bytes = if self.slabs.is_empty() && self.use_huge_from_start {
            self.init_slab_bytes
        } else if self.use_huge_from_start || self.slabs.len() >= 2 {
            HUGE_SLAB_BYTES
                .max(self.init_slab_bytes / 2)
                .min(64 * 1024 * 1024)
        } else if self.slabs.len() == 1 {
            256 * 1024
        } else {
            64 * 1024
        };
        let need = min_bytes.max(step_bytes);

        #[cfg(unix)]
        if self.use_huge_from_start || need >= HUGE_SLAB_BYTES {
            let min_recycle = min_bytes.max(HUGE_PAGE_ALIGN);
            if let Some(entry) = pop_pooled_slab(min_recycle) {
                self.slabs.push(SlabBacking::Mmap(entry.ptr, entry.len));
                self.cur_ptr = entry.ptr;
                self.cur_end = unsafe { entry.ptr.add(entry.len) };
                return;
            }
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

#[derive(Clone, Copy)]
#[repr(C)]
struct BucketHead<T> {
    cur: *mut T,
    end: *mut T,
}

pub struct SlabBuckets<T: Copy, const P: usize, const CHUNK: usize, const SWCB_W: usize = 4> {
    arena: SlabArena,
    swcb: *mut T,
    swcb_cnt: [u8; P],
    heads: [BucketHead<T>; P],
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
                && CHUNK % SWCB_W == 0
                && CHUNK <= u16::MAX as usize
        );
        assert!(align_of::<T>() <= 64);
        assert!(size_of::<T>() > 0);
        let mut arena = SlabArena::new(hint_bytes);
        let swcb = if SWCB_W == 1 {
            ptr::null_mut()
        } else {
            let swcb_bytes = P * SWCB_W * size_of::<T>();
            arena.alloc_aligned_64(swcb_bytes).as_ptr() as *mut T
        };
        let completed = (0..P).map(|_| Vec::new()).collect();
        Self {
            arena,
            swcb,
            swcb_cnt: [0u8; P],
            heads: [BucketHead {
                cur: ptr::null_mut(),
                end: ptr::null_mut(),
            }; P],
            completed,
            _marker: PhantomData,
        }
    }

    #[cold]
    #[inline(never)]
    fn alloc_next_chunk(&mut self, shard: usize) -> *mut T {
        let old_end = unsafe { (*self.heads.get_unchecked(shard)).end };
        if !old_end.is_null() {
            unsafe {
                let base = old_end.sub(CHUNK);
                self.completed.get_unchecked_mut(shard).push(MutChunkRef {
                    ptr: base,
                    len: CHUNK,
                });
            }
        }
        let chunk_bytes = CHUNK * size_of::<T>();
        let new_ptr = self.arena.alloc_aligned_64(chunk_bytes).as_ptr() as *mut T;
        unsafe {
            let h = self.heads.get_unchecked_mut(shard);
            h.cur = new_ptr;
            h.end = new_ptr.add(CHUNK);
        }
        new_ptr
    }

    #[inline(always)]
    pub fn push(&mut self, shard: usize, val: T) {
        if SWCB_W == 1 {
            let h = unsafe { self.heads.get_unchecked_mut(shard) };
            let mut cur = h.cur;
            if cur == h.end {
                cur = self.alloc_next_chunk(shard);
            }
            unsafe {
                *cur = val;
                (*self.heads.get_unchecked_mut(shard)).cur = cur.add(1);
            }
            return;
        }
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
        let h = unsafe { self.heads.get_unchecked_mut(shard) };
        let mut dst = h.cur;
        if dst == h.end {
            dst = self.alloc_next_chunk(shard);
        }

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
                (*self.heads.get_unchecked_mut(shard)).cur = dst.add(SWCB_W);
                *self.swcb_cnt.get_unchecked_mut(shard) = 0;
            }
            return;
        }
        unsafe {
            ptr::copy_nonoverlapping(src, dst, SWCB_W);
            (*self.heads.get_unchecked_mut(shard)).cur = dst.add(SWCB_W);
            *self.swcb_cnt.get_unchecked_mut(shard) = 0;
        }
    }

    pub fn finish(mut self) -> (SlabArena, Vec<Vec<MutChunkRef<T>>>) {
        if SWCB_W == 1 {
            for shard in 0..P {
                let h = self.heads[shard];
                if !h.end.is_null() {
                    let base = unsafe { h.end.sub(CHUNK) };
                    let len = unsafe { h.cur.offset_from(base) as usize };
                    if len > 0 {
                        self.completed[shard].push(MutChunkRef { ptr: base, len });
                    }
                }
            }
            return (self.arena, self.completed);
        }
        for shard in 0..P {
            let cnt = self.swcb_cnt[shard] as usize;
            let h = self.heads[shard];
            if cnt > 0 {
                let mut cur = h.cur;
                let mut base = if h.end.is_null() {
                    ptr::null_mut()
                } else {
                    unsafe { h.end.sub(CHUNK) }
                };
                if cur == h.end {
                    if !base.is_null() {
                        self.completed[shard].push(MutChunkRef { ptr: base, len: CHUNK });
                    }
                    cur = self.arena.alloc_aligned_64(cnt * size_of::<T>()).as_ptr() as *mut T;
                    base = cur;
                }
                unsafe {
                    ptr::copy_nonoverlapping(self.swcb.add(shard * SWCB_W), cur, cnt);
                    cur = cur.add(cnt);
                    let len = cur.offset_from(base) as usize;
                    self.completed[shard].push(MutChunkRef { ptr: base, len });
                }
            } else if !h.end.is_null() {
                let base = unsafe { h.end.sub(CHUNK) };
                let len = unsafe { h.cur.offset_from(base) as usize };
                if len > 0 {
                    self.completed[shard].push(MutChunkRef { ptr: base, len });
                }
            }
        }
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
        unsafe {
            std::arch::x86_64::_mm_sfence();
        }
        (self.arena, self.completed)
    }
}

/// Reusable 2MB-hugepage-backed scratch bump allocator for per-shard Stage 5 CSR buffers.
pub struct HugeScratch {
    ptr: *mut u8,
    cap: usize,
    off: usize,
    is_mmap: bool,
    overflow: Vec<(*mut u8, usize, bool)>,
    heap_fallback: Vec<Vec<u8>>,
}

unsafe impl Send for HugeScratch {}
unsafe impl Sync for HugeScratch {}

impl HugeScratch {
    fn alloc_slab(
        min_bytes: usize,
        heap_fallback: &mut Vec<Vec<u8>>,
    ) -> (*mut u8, usize, bool) {
        let aligned_len = ((min_bytes.max(HUGE_PAGE_ALIGN) + HUGE_PAGE_ALIGN - 1)
            & !(HUGE_PAGE_ALIGN - 1))
        .max(HUGE_PAGE_ALIGN);
        #[cfg(unix)]
        {
            if let Some(entry) = pop_pooled_slab(aligned_len) {
                return (entry.ptr, entry.len, true);
            }
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
                    return (p as *mut u8, aligned_len, true);
                }
            }
        }
        let mut buf = vec![0u8; aligned_len + 64];
        let raw = buf.as_mut_ptr() as usize;
        let aligned = (raw + 63) & !63;
        let usable = (raw + buf.len()) - aligned;
        heap_fallback.push(buf);
        (aligned as *mut u8, usable, false)
    }

    pub fn with_capacity(min_bytes: usize) -> Self {
        let mut heap_fallback = Vec::new();
        let (ptr, cap, is_mmap) = Self::alloc_slab(min_bytes, &mut heap_fallback);
        Self {
            ptr,
            cap,
            off: 0,
            is_mmap,
            overflow: Vec::new(),
            heap_fallback,
        }
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        self.off = 0;
        if !self.overflow.is_empty() {
            for (p, l, is_mmap) in self.overflow.drain(..) {
                #[cfg(unix)]
                if is_mmap {
                    recycle_or_munmap_raw(p, l);
                }
                #[cfg(not(unix))]
                let _ = (p, l, is_mmap);
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn grow_and_alloc(&mut self, bytes: usize) -> *mut u8 {
        if self.cap > 0 {
            self.overflow.push((self.ptr, self.cap, self.is_mmap));
        }
        let need = bytes.max(self.cap.saturating_mul(2)).max(HUGE_SLAB_BYTES);
        let (ptr, cap, is_mmap) = Self::alloc_slab(need, &mut self.heap_fallback);
        self.ptr = ptr;
        self.cap = cap;
        self.is_mmap = is_mmap;
        self.off = bytes;
        ptr
    }

    #[inline(always)]
    pub fn alloc_uninit_ptr<T: Copy>(&mut self, len: usize) -> *mut T {
        if len == 0 {
            return NonNull::<T>::dangling().as_ptr();
        }
        let align = align_of::<T>().max(64);
        let bytes = len
            .checked_mul(size_of::<T>())
            .expect("HugeScratch size overflow");
        let aligned_off = (self.off + align - 1) & !(align - 1);
        if aligned_off.saturating_add(bytes) <= self.cap {
            self.off = aligned_off + bytes;
            unsafe { self.ptr.add(aligned_off) as *mut T }
        } else {
            self.grow_and_alloc(bytes) as *mut T
        }
    }

    #[inline(always)]
    pub fn alloc_zeroed_ptr<T: Zeroable>(&mut self, len: usize) -> *mut T {
        let p = self.alloc_uninit_ptr::<T>(len);
        if len > 0 {
            unsafe {
                ptr::write_bytes(p, 0, len);
            }
        }
        p
    }
}

impl Drop for HugeScratch {
    fn drop(&mut self) {
        if self.is_mmap && self.cap > 0 {
            #[cfg(unix)]
            recycle_or_munmap_raw(self.ptr, self.cap);
        }
        for (p, l, is_mmap) in self.overflow.drain(..) {
            #[cfg(unix)]
            if is_mmap {
                recycle_or_munmap_raw(p, l);
            }
            #[cfg(not(unix))]
            let _ = (p, l, is_mmap);
        }
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

        // Direct temporal mode (SWCB_W = 1) across 0, partial, exact chunk, multi-chunk
        let mut sb1 = SlabBuckets::<u64, 4, 8, 1>::new(64 * 1024);
        for v in 1..=3u64 {
            sb1.push(0, v);
        }
        for v in 10..18u64 {
            sb1.push(1, v);
        }
        for v in 100..121u64 {
            sb1.push(2, v);
        }
        let (_arena1, chunks1) = sb1.finish();
        let collect_shard1 = |s: usize| -> Vec<u64> {
            let mut out = Vec::new();
            for c in &chunks1[s] {
                out.extend_from_slice(unsafe { c.as_slice() });
            }
            out
        };
        assert_eq!(collect_shard1(0), vec![1, 2, 3]);
        assert_eq!(collect_shard1(1), (10..18).collect::<Vec<u64>>());
        assert_eq!(collect_shard1(2), (100..121).collect::<Vec<u64>>());
        assert!(chunks1[3].is_empty());

        // HugeScratch bump, zeroing, overflow growth, reset & slab recycling lifecycle
        set_slab_recycling(true);
        {
            let mut hs = HugeScratch::with_capacity(2 * 1024 * 1024);
            let z = hs.alloc_zeroed_ptr::<u64>(1024);
            assert!(unsafe { std::slice::from_raw_parts(z, 1024) }.iter().all(|&x| x == 0));
            let u = hs.alloc_uninit_ptr::<u32>(300);
            unsafe {
                *u = 7;
                *u.add(299) = 99;
            }
            // Trigger overflow growth past 2 MiB
            let big = hs.alloc_zeroed_ptr::<u64>(600_000);
            unsafe {
                assert_eq!(*big, 0);
                assert_eq!(*big.add(599_999), 0);
                *big.add(12345) = 0xCAFE_BABE;
                assert_eq!(*big.add(12345), 0xCAFE_BABE);
            }
            hs.reset();
            let z2 = hs.alloc_zeroed_ptr::<u32>(128);
            assert!(unsafe { std::slice::from_raw_parts(z2, 128) }.iter().all(|&x| x == 0));
        }
        set_slab_recycling(false);
    }
}
