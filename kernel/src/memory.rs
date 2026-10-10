//! Physical frames and user page mappings.
//!
//! Frames come from a bump allocator over Limine's usable regions and are never freed. Physical
//! memory is reached through Limine's higher-half direct map (HHDM). User pages are added to the
//! page tables Limine built, so the kernel stays mapped (supervisor-only) above the user half.

use limine::memory_map::{Entry, EntryType};
use spin::Mutex;
use x86_64::registers::control::Cr3;

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

pub fn init(hhdm_offset: u64, memmap: &'static [&'static Entry]) {
    unsafe { HHDM_OFFSET = hhdm_offset };
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

/// Map the 4 KiB page at `virt` to a fresh zeroed frame, user-accessible. Returns the frame.
/// Non-executable pages get the NX bit (when the CPU supports it).
pub fn map_user_page(virt: u64, writable: bool, executable: bool) -> u64 {
    assert!(virt % PAGE_SIZE == 0 && virt < USER_END, "bad user address {virt:#x}");

    let (pml4, _) = Cr3::read();
    let mut table_phys = pml4.start_address().as_u64();
    // Walk PML4 -> PDPT -> PD, creating tables as needed. USER must be set at every level
    // for ring 3 to reach the final page; the leaf entry decides writability and NX.
    for level in (1..=3).rev() {
        let index = ((virt >> (12 + 9 * level)) & 0x1ff) as usize;
        let entry = &mut table(table_phys)[index];
        if *entry & PRESENT == 0 {
            *entry = alloc_frame() | PRESENT | WRITABLE | USER;
        }
        assert!(*entry & HUGE == 0, "huge page in user range at {virt:#x}");
        *entry |= USER | WRITABLE;
        table_phys = *entry & ADDR_MASK;
    }

    let index = ((virt >> 12) & 0x1ff) as usize;
    let leaf = &mut table(table_phys)[index];
    assert!(*leaf & PRESENT == 0, "user page {virt:#x} already mapped");
    let frame = alloc_frame();
    let nx = if !executable && cpu::nx_enabled() { NO_EXECUTE } else { 0 };
    *leaf = frame | PRESENT | USER | nx | if writable { WRITABLE } else { 0 };
    frame
}
