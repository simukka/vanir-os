//! Physical frames and user page mappings.
//!
//! Frames come from a free list of returned frames, or else a bump allocator over Limine's usable
//! regions. Physical memory is reached through Limine's higher-half direct map (HHDM).
//!
//! Each process gets its own page-table tree (`AddressSpace`). The kernel half (top-level entries
//! 256-511) is copied from the tables Limine built, so every address space shares the same kernel
//! page tables and the kernel works whichever one is loaded in CR3.

use limine::memory_map::{Entry, EntryType};
use spin::Mutex;
use x86_64::registers::control::{Cr3, Cr3Flags};
use x86_64::structures::paging::PhysFrame;
use x86_64::PhysAddr;

use crate::cpu;

pub const PAGE_SIZE: u64 = 4096;

/// First non-canonical address; everything below is the user half.
pub const USER_END: u64 = 0x0000_8000_0000_0000;

const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const HUGE: u64 = 1 << 7;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

struct FrameAllocator {
    regions: &'static [&'static Entry],
    region: usize,
    next: u64,
    /// Head of the list of freed frames (0 = empty); each free frame's first word links the next.
    free: u64,
    in_use: u64,
}

static FRAMES: Mutex<FrameAllocator> =
    Mutex::new(FrameAllocator { regions: &[], region: 0, next: 0, free: 0, in_use: 0 });
static mut HHDM_OFFSET: u64 = 0;
/// Limine's top-level table: the source of the kernel half for every address space.
static mut KERNEL_PML4: u64 = 0;

pub fn init(hhdm_offset: u64, memmap: &'static [&'static Entry]) {
    unsafe {
        HHDM_OFFSET = hhdm_offset;
        KERNEL_PML4 = Cr3::read().0.start_address().as_u64();
    }
    *FRAMES.lock() = FrameAllocator { regions: memmap, region: 0, next: 0, free: 0, in_use: 0 };
}

pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (unsafe { HHDM_OFFSET } + phys) as *mut u8
}

/// Allocate one zeroed 4 KiB frame and return its physical address.
pub fn alloc_frame() -> u64 {
    let mut a = FRAMES.lock();
    a.in_use += 1;
    if a.free != 0 {
        let frame = a.free;
        a.free = unsafe { *(phys_to_virt(frame) as *const u64) };
        unsafe { phys_to_virt(frame).write_bytes(0, PAGE_SIZE as usize) };
        return frame;
    }
    let frame = loop {
        let Some(entry) = a.regions.get(a.region) else { panic!("out of physical memory") };
        if entry.entry_type == EntryType::USABLE {
            let start = entry.base.next_multiple_of(PAGE_SIZE);
            let next = a.next.max(start);
            if next + PAGE_SIZE <= entry.base + entry.length {
                a.next = next + PAGE_SIZE;
                break next;
            }
        }
        a.region += 1;
    };
    unsafe { phys_to_virt(frame).write_bytes(0, PAGE_SIZE as usize) };
    frame
}

/// Return a frame to the allocator. It must no longer be mapped anywhere.
pub fn free_frame(frame: u64) {
    let mut a = FRAMES.lock();
    unsafe { *(phys_to_virt(frame) as *mut u64) = a.free };
    a.free = frame;
    a.in_use -= 1;
}

pub fn frames_in_use() -> u64 {
    FRAMES.lock().in_use
}

fn table(phys: u64) -> &'static mut [u64; 512] {
    unsafe { &mut *(phys_to_virt(phys) as *mut [u64; 512]) }
}

/// A process's page-table tree.
pub struct AddressSpace {
    pml4: u64,
}

impl AddressSpace {
    /// A new address space with an empty user half and the shared kernel half.
    pub fn new() -> AddressSpace {
        let pml4 = alloc_frame();
        let kernel = table(unsafe { KERNEL_PML4 });
        table(pml4)[256..].copy_from_slice(&kernel[256..]);
        AddressSpace { pml4 }
    }

    /// Load this address space into CR3 (which also flushes the TLB's non-global entries).
    pub fn activate(&self) {
        let frame = PhysFrame::from_start_address(PhysAddr::new(self.pml4)).unwrap();
        unsafe { Cr3::write(frame, Cr3Flags::empty()) };
    }

    /// Map the 4 KiB page at `virt` to a fresh zeroed frame, user-accessible. Returns the frame.
    /// Non-executable pages get the NX bit (when the CPU supports it).
    pub fn map_user_page(&self, virt: u64, writable: bool, executable: bool) -> u64 {
        assert!(virt % PAGE_SIZE == 0 && virt < USER_END, "bad user address {virt:#x}");
        let nx = if !executable && cpu::nx_enabled() { NO_EXECUTE } else { 0 };
        let flags = PRESENT | USER | nx | if writable { WRITABLE } else { 0 };
        // USER must be set at every level for ring 3 to reach the page; the leaf decides W and NX.
        let leaf = walk(self.pml4, virt, PRESENT | WRITABLE | USER);
        assert!(*leaf & PRESENT == 0, "user page {virt:#x} already mapped");
        let frame = alloc_frame();
        *leaf = frame | flags;
        frame
    }
}

impl AddressSpace {
    /// Physical address behind user address `virt`, if it is mapped user-accessible (and
    /// writable, when `write`). Walks this tree, so it works whichever tree is in CR3.
    fn translate(&self, virt: u64, write: bool) -> Option<u64> {
        if virt >= USER_END {
            return None;
        }
        let mut table_phys = self.pml4;
        for level in (0..=3).rev() {
            let entry = table(table_phys)[((virt >> (12 + 9 * level)) & 0x1ff) as usize];
            let needed = PRESENT | USER | if write { WRITABLE } else { 0 };
            if entry & needed != needed || (level != 0 && entry & HUGE != 0) {
                return None;
            }
            table_phys = entry & ADDR_MASK;
        }
        Some(table_phys + (virt & (PAGE_SIZE - 1)))
    }

    /// True if every byte of `[virt, virt + len)` is mapped user-accessible (and writable).
    pub fn check_range(&self, virt: u64, len: u64, write: bool) -> bool {
        let Some(end) = virt.checked_add(len) else { return false };
        if len == 0 {
            return true;
        }
        let mut page = virt & !(PAGE_SIZE - 1);
        while page < end {
            if self.translate(page.max(virt), write).is_none() {
                return false;
            }
            page += PAGE_SIZE;
        }
        true
    }
}

/// Copy `len` bytes from user address `src` in `from` to user address `dst` in `to`, through the
/// direct map. Both ranges are checked (readable, writable) before any byte moves, so it either
/// copies everything or nothing. No user page is touched through its user mapping, so the copy
/// can neither fault nor trip SMAP, and the two address spaces need not be the one in CR3.
pub fn copy_between(from: &AddressSpace, src: u64, to: &AddressSpace, dst: u64, len: u64) -> Result<(), BadAddress> {
    if !from.check_range(src, len, false) || !to.check_range(dst, len, true) {
        return Err(BadAddress);
    }
    let mut done = 0;
    while done < len {
        let (s, d) = (src + done, dst + done);
        let chunk = (len - done).min(PAGE_SIZE - (s & (PAGE_SIZE - 1))).min(PAGE_SIZE - (d & (PAGE_SIZE - 1)));
        let s_phys = from.translate(s, false).unwrap();
        let d_phys = to.translate(d, true).unwrap();
        unsafe { core::ptr::copy(phys_to_virt(s_phys), phys_to_virt(d_phys), chunk as usize) };
        done += chunk;
    }
    Ok(())
}

/// Copy kernel bytes to user address `dst` in `to`, through the direct map. All or nothing.
pub fn copy_to_user_space(to: &AddressSpace, dst: u64, src: &[u8]) -> Result<(), BadAddress> {
    let len = src.len() as u64;
    if !to.check_range(dst, len, true) {
        return Err(BadAddress);
    }
    let mut done = 0;
    while done < len {
        let d = dst + done;
        let chunk = (len - done).min(PAGE_SIZE - (d & (PAGE_SIZE - 1)));
        let phys = to.translate(d, true).unwrap();
        let bytes = &src[done as usize..(done + chunk) as usize];
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(phys), bytes.len()) };
        done += chunk;
    }
    Ok(())
}

#[derive(Debug)]
pub struct BadAddress;

impl Drop for AddressSpace {
    /// Free every user page and user page table, then the top-level table. The kernel half's
    /// tables are shared and are never freed.
    fn drop(&mut self) {
        if Cr3::read().0.start_address().as_u64() == self.pml4 {
            // Never free the tables the CPU is using: fall back to the kernel-only tree.
            let kernel = PhysFrame::from_start_address(PhysAddr::new(unsafe { KERNEL_PML4 })).unwrap();
            unsafe { Cr3::write(kernel, Cr3Flags::empty()) };
        }
        free_tables(self.pml4, 4, 0..256);
    }
}

/// Free the tree under the table at `phys` (a level-`level` table; 4 = PML4), limited to
/// `entries` at the top level, then the table itself.
fn free_tables(phys: u64, level: u32, entries: core::ops::Range<usize>) {
    for &entry in &table(phys)[entries] {
        if entry & PRESENT == 0 {
            continue;
        }
        let child = entry & ADDR_MASK;
        if level == 1 {
            free_frame(child); // a user page
        } else {
            assert!(entry & HUGE == 0, "huge page in a user address space");
            free_tables(child, level - 1, 0..512);
        }
    }
    free_frame(phys);
}

/// Map one page of device registers into the kernel half: uncached, non-executable, kernel-only.
/// Shared by every address space because the kernel half's lower-level tables are shared.
pub fn map_kernel_mmio(virt: u64, phys: u64) {
    let leaf = walk(unsafe { KERNEL_PML4 }, virt, PRESENT | WRITABLE);
    assert!(*leaf & PRESENT == 0, "kernel page {virt:#x} already mapped");
    let nx = if cpu::nx_enabled() { NO_EXECUTE } else { 0 };
    *leaf = phys | PRESENT | WRITABLE | WRITE_THROUGH | CACHE_DISABLE | nx;
}

/// Walk PML4 -> PDPT -> PD to the page-table entry for `virt`, creating missing tables with
/// `table_flags`. Returns the leaf entry.
fn walk(pml4: u64, virt: u64, table_flags: u64) -> &'static mut u64 {
    let mut table_phys = pml4;
    for level in (1..=3).rev() {
        let index = ((virt >> (12 + 9 * level)) & 0x1ff) as usize;
        let entry = &mut table(table_phys)[index];
        if *entry & PRESENT == 0 {
            // A new top-level kernel entry would exist only in this tree, not in the copies
            // already made for each process, so the kernel half must never grow one.
            assert!(level != 3 || virt < USER_END, "new top-level kernel mapping at {virt:#x}");
            *entry = alloc_frame() | table_flags;
        }
        assert!(*entry & HUGE == 0, "huge page in the way at {virt:#x}");
        table_phys = *entry & ADDR_MASK;
    }
    &mut table(table_phys)[((virt >> 12) & 0x1ff) as usize]
}
