//! CPU protection features, enabled once at boot.
//!
//! - SMEP: the kernel faults if it executes a user page.
//! - SMAP: the kernel faults if it touches a user page outside a `stac`/`clac` window.
//! - NX:   page-table bit 63 makes a page non-executable.
//! - CR0.WP: the kernel respects read-only pages too.

use core::arch::asm;
use core::arch::x86_64::__cpuid_count;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};
use x86_64::registers::model_specific::{Efer, EferFlags};

static SMAP: AtomicBool = AtomicBool::new(false);
static NX: AtomicBool = AtomicBool::new(false);

pub fn enable_protections() {
    let max_leaf = __cpuid_count(0, 0).eax;
    let leaf7_ebx = if max_leaf >= 7 { __cpuid_count(7, 0).ebx } else { 0 };
    let smep = leaf7_ebx & (1 << 7) != 0;
    let smap = leaf7_ebx & (1 << 20) != 0;
    let nx = __cpuid_count(0x8000_0001, 0).edx & (1 << 20) != 0;
    let nx_from_limine = Efer::read().contains(EferFlags::NO_EXECUTE_ENABLE);

    unsafe {
        Cr0::update(|f| f.insert(Cr0Flags::WRITE_PROTECT));
        if nx {
            Efer::update(|f| f.insert(EferFlags::NO_EXECUTE_ENABLE));
        }
        Cr4::update(|f| {
            f.set(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION, smep);
            f.set(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION, smap);
        });
    }
    SMAP.store(smap, Ordering::Relaxed);
    NX.store(nx, Ordering::Relaxed);

    let state = |on: bool| if on { "on" } else { "UNAVAILABLE" };
    println!(
        "[kernel] SMEP {}, SMAP {}, NX {}{}, WP on",
        state(smep),
        state(smap),
        state(nx),
        if nx_from_limine { " (already set by Limine)" } else { "" }
    );
}

#[allow(dead_code)] // used by the ELF loader
pub fn nx_enabled() -> bool {
    NX.load(Ordering::Relaxed)
}

/// Close the SMAP window. Called on every trap entry, because user code can set RFLAGS.AC and
/// the CPU does not clear it when delivering an interrupt. `clac` is #UD without SMAP.
pub fn clac() {
    if SMAP.load(Ordering::Relaxed) {
        unsafe { asm!("clac", options(nomem, nostack)) };
    }
}

/// Open the SMAP window so the kernel may access user pages.
pub fn stac() {
    if SMAP.load(Ordering::Relaxed) {
        unsafe { asm!("stac", options(nomem, nostack)) };
    }
}
