//! Device interrupts, delivered to driver tasks as notifications.
//!
//! The kernel programs each granted device's MSI-X table to raise one vector from
//! `DEVICE_VECTORS`. When it fires, the kernel sets a bit in the owning task's pending mask; the
//! task sees it in `recv` as sender 0, op `NOTIFY_IRQ`, with the bits (one per granted device,
//! in manifest order). Everything here is lock-free, because device interrupts also arrive while
//! the kernel idles with the process table held.

use core::ops::Range;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::process::MAX_PROCESSES;

pub const DEVICE_VECTORS: Range<u64> = 0x50..0x60;
const NO_ROUTE: u64 = u64::MAX;

/// For each device vector: owner slot << 8 | bit, or NO_ROUTE. Written at boot only.
static ROUTES: [AtomicU64; 16] = [const { AtomicU64::new(NO_ROUTE) }; 16];
static PENDING: [AtomicU64; MAX_PROCESSES] = [const { AtomicU64::new(0) }; MAX_PROCESSES];
static COUNT: AtomicU64 = AtomicU64::new(0);

/// Send interrupts on `vector` to task `slot` as pending bit `bit`.
pub fn route(vector: u64, slot: usize, bit: usize) {
    ROUTES[(vector - DEVICE_VECTORS.start) as usize].store((slot as u64) << 8 | bit as u64, Ordering::Relaxed);
}

/// A device interrupt arrived on `vector`.
pub fn raise(vector: u64) {
    COUNT.fetch_add(1, Ordering::Relaxed);
    let route = ROUTES[(vector - DEVICE_VECTORS.start) as usize].load(Ordering::Relaxed);
    if route != NO_ROUTE {
        PENDING[(route >> 8) as usize].fetch_or(1 << (route & 0xff), Ordering::AcqRel);
    }
}

/// Take (and clear) the slot's pending bits.
pub fn take(slot: usize) -> u64 {
    PENDING[slot].swap(0, Ordering::AcqRel)
}

pub fn pending(slot: usize) -> bool {
    PENDING[slot].load(Ordering::Acquire) != 0
}

/// Device interrupts since boot.
pub fn count() -> u64 {
    COUNT.load(Ordering::Relaxed)
}
