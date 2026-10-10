//! Physical frames and user page mappings.
//!
//! Frames come from a bump allocator over Limine's usable regions and are never freed. Physical
//! memory is reached through Limine's higher-half direct map (HHDM).
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
const NO_EXECUTE: u64 = 1 << 63;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

struct FrameAllocator {
    regions: &'static [&'static Entry],
    region: usize,
    next: u64,
}

static FRAMES: Mutex<FrameAllocator> = Mutex::new(FrameAllocator { regions: &[], region: 0, next: 0 });
static mut HHDM_OFFSET: u64 = 0;
/// Limine's top-level table: the source of the kernel half for every address space.
static mut KERNEL_PML4: u64 = 0;

pub fn init(hhdm_offset: u64, memmap: &'static [&'static Entry]) {
    unsafe {
        HHDM_OFFSET = hhdm_offset;
        KERNEL_PML4 = Cr3::read().0.start_address().as_u64();
    }
    *FRAMES.lock() = FrameAllocator { regions: memmap, region: 0, next: 0 };
}

pub fn phys_to_virt(phys: u64) -> *mut u8 {
    (unsafe { HHDM_OFFSET } + phys) as *mut u8
}

/// Allocate one zeroed 4 KiB frame and return its physical address.
pub fn alloc_frame() -> u64 {
    let mut a = FRAMES.lock();
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

/// Walk PML4 -> PDPT -> PD to the page-table entry for `virt`, creating missing tables with
/// `table_flags` (OR-ed into existing entries too). Returns the leaf entry.
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
        *entry |= table_flags;
        table_phys = *entry & ADDR_MASK;
    }
    &mut table(table_phys)[((virt >> 12) & 0x1ff) as usize]
}
