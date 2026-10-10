//! vanir-os: the minimal layer needed to run one isolated ring-3 process on x86-64.
//!
//! Limine puts us in 64-bit long mode with paging on. We then add: serial output, a GDT with
//! user segments and a TSS, an IDT, user page mappings, an `iretq` into ring 3, and `int 0x80`
//! syscalls. No scheduler, timer, heap, or filesystem.

#![no_std]
#![no_main]

#[macro_use]
mod serial;
mod cpu;
mod gdt;
mod interrupts;
mod memory;
mod process;
mod syscall;

use core::panic::PanicInfo;
use limine::BaseRevision;
use limine::request::{HhdmRequest, MemoryMapRequest, RequestsEndMarker, RequestsStartMarker};
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
    mask_legacy_pic();
    gdt::init();
    interrupts::init();
    println!("[kernel] GDT, TSS and IDT loaded");

    let hhdm = HHDM_REQUEST.get_response().expect("no HHDM response");
    let memmap = MEMMAP_REQUEST.get_response().expect("no memory map response");
    memory::init(hhdm.offset(), memmap.entries());

    process::run_hello()
}

/// We install no IRQ handlers, so keep the 8259 PICs fully masked before user code sets IF=1.
fn mask_legacy_pic() {
    unsafe {
        Port::<u8>::new(0x21).write(0xff);
        Port::<u8>::new(0xa1).write(0xff);
    }
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
