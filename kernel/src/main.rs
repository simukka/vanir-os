//! vanir-os: a minimal x86-64 kernel that runs isolated ring-3 processes.
//!
//! Limine puts us in 64-bit long mode with paging on. We then add: serial output, a GDT with
//! user segments and a TSS, an IDT, a page-table tree per process, an ELF loader, `int 0x80`
//! syscalls, and a static task table run by a round-robin scheduler. No heap or filesystem.

#![no_std]
#![no_main]

#[macro_use]
mod serial;
mod apic;
mod cpu;
mod elf;
mod events;
mod gdt;
mod interrupts;
mod irq;
mod memory;
mod modules;
mod pci;
mod process;
mod syscall;
mod usercopy;
mod verify;

use core::panic::PanicInfo;
use limine::BaseRevision;
use limine::request::{HhdmRequest, MemoryMapRequest, ModuleRequest, RequestsEndMarker, RequestsStartMarker};
use x86_64::instructions::{hlt, interrupts as cpu_interrupts, port::Port};

// Base revision 3 is supported by Limine v8 and later.
#[used]
#[unsafe(link_section = ".limine_requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(3);

#[used]
#[unsafe(link_section = ".limine_requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MEMMAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests")]
static MODULE_REQUEST: ModuleRequest = ModuleRequest::new();

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static _START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static _END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[unsafe(no_mangle)]
extern "C" fn kmain() -> ! {
    serial::init();
    println!("[kernel] vanir-os booting");
    assert!(BASE_REVISION.is_supported(), "Limine base revision 3 not supported");

    cpu::enable_protections();
    gdt::init();
    interrupts::init();
    println!("[kernel] GDT, TSS and IDT loaded");

    let hhdm = HHDM_REQUEST.get_response().expect("no HHDM response");
    let memmap = MEMMAP_REQUEST.get_response().expect("no memory map response");
    modules::init(MODULE_REQUEST.get_response().map_or(&[], |r| r.modules()));
    memory::init(hhdm.offset(), memmap.entries());
    apic::init();
    pci::init();

    process::start()
}

/// Stop the machine. Under QEMU with `isa-debug-exit`, `code` becomes the exit status
/// `(code << 1) | 1`; on real hardware the port write is ignored and we halt forever.
pub fn halt(code: u8) -> ! {
    unsafe { Port::<u32>::new(0xf4).write(code as u32) };
    cpu_interrupts::disable();
    loop {
        hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial::print_unlocked(format_args!("\n[kernel] PANIC: {}\n", info));
    halt(3)
}
