//! Virtio 1.x over PCI for driver tasks: find the device's configuration structures through
//! its PCI capabilities, negotiate features, and run split virtqueues in the task's DMA region.
//!
//! Everything a device reads or writes lives in the DMA region, because the device needs
//! physical addresses; `Dma` hands out pieces of it and translates addresses.

#![no_std]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use vanir_user::{device_bar, dma_info, pci_config_read};

pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_FAILED: u8 = 128;

/// "No MSI-X vector" in the common configuration.
const NO_VECTOR: u16 = 0xffff;

// Common configuration structure offsets.
const DEVICE_FEATURE_SELECT: u64 = 0x00;
const DEVICE_FEATURE: u64 = 0x04;
const DRIVER_FEATURE_SELECT: u64 = 0x08;
const DRIVER_FEATURE: u64 = 0x0c;
const MSIX_CONFIG: u64 = 0x10;
const DEVICE_STATUS: u64 = 0x14;
const QUEUE_SELECT: u64 = 0x16;
const QUEUE_SIZE: u64 = 0x18;
const QUEUE_MSIX_VECTOR: u64 = 0x1a;
const QUEUE_ENABLE: u64 = 0x1c;
const QUEUE_NOTIFY_OFF: u64 = 0x1e;
const QUEUE_DESC: u64 = 0x20;
const QUEUE_DRIVER: u64 = 0x28;
const QUEUE_DEVICE: u64 = 0x30;

#[derive(Debug)]
pub enum Error {
    NoDevice,
    MissingCapability(&'static str),
    FeaturesRejected,
    QueueUnavailable(u16),
    NoVector,
    OutOfDma,
}

/// The task's DMA region, handed out front to back.
pub struct Dma {
    va: u64,
    pa: u64,
    len: u64,
    next: u64,
}

impl Dma {
    pub fn new() -> Result<Dma, Error> {
        let (va, pa, len) = dma_info().map_err(|_| Error::OutOfDma)?;
        Ok(Dma { va, pa, len, next: 0 })
    }

    /// `size` bytes aligned to `align`: (address, physical address).
    pub fn alloc(&mut self, size: u64, align: u64) -> Result<(u64, u64), Error> {
        let start = self.next.next_multiple_of(align);
        if start + size > self.len {
            return Err(Error::OutOfDma);
        }
        self.next = start + size;
        Ok((self.va + start, self.pa + start))
    }

    /// Physical address of an address inside the region.
    pub fn phys(&self, va: u64) -> u64 {
        debug_assert!(va >= self.va && va < self.va + self.len);
        self.pa + (va - self.va)
    }
}

fn mmio_read<T>(addr: u64) -> T {
    unsafe { read_volatile(addr as *const T) }
}

fn mmio_write<T>(addr: u64, value: T) {
    unsafe { write_volatile(addr as *mut T, value) }
}

/// A virtio PCI device's configuration structures, as mapped into this task.
pub struct Transport {
    common: u64,
    notify: u64,
    notify_multiplier: u32,
    /// Device-specific configuration (e.g. virtio-blk capacity).
    pub device_config: Option<u64>,
}

impl Transport {
    /// Find granted device `device`'s virtio structures through its PCI capabilities.
    pub fn new(device: u64) -> Result<Transport, Error> {
        let config = |offset: u32| pci_config_read(device, offset as u64).map_err(|_| Error::NoDevice);
        let mut common = None;
        let mut notify = None;
        let mut device_config = None;
        let mut cap = config(0x34)? & 0xfc;
        while cap != 0 {
            let header = config(cap)?;
            if header & 0xff == 0x09 {
                let cfg_type = (header >> 24) & 0xff;
                let bar = config(cap + 4)? & 0xff;
                let offset = config(cap + 8)? as u64;
                let base = device_bar(device, bar as u64).map(|(addr, _)| addr + offset).ok();
                match cfg_type {
                    1 => common = base,
                    2 => notify = base.map(|b| (b, config(cap + 16).unwrap_or(0))),
                    4 => device_config = base,
                    _ => {}
                }
            }
            cap = (header >> 8) & 0xfc;
        }
        let common = common.ok_or(Error::MissingCapability("common"))?;
        let (notify, notify_multiplier) = notify.ok_or(Error::MissingCapability("notify"))?;
        Ok(Transport { common, notify, notify_multiplier, device_config })
    }

    /// Reset the device and negotiate features: `VIRTIO_F_VERSION_1` plus whatever of `wanted`
    /// the device offers. Returns the negotiated set. Queues are set up next, then `driver_ok`.
    pub fn start(&self, wanted: u64) -> Result<u64, Error> {
        mmio_write::<u8>(self.common + DEVICE_STATUS, 0);
        while mmio_read::<u8>(self.common + DEVICE_STATUS) != 0 {
            core::hint::spin_loop();
        }
        self.set_status(STATUS_ACKNOWLEDGE);
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        let mut offered = 0u64;
        for half in 0..2u32 {
            mmio_write(self.common + DEVICE_FEATURE_SELECT, half);
            offered |= (mmio_read::<u32>(self.common + DEVICE_FEATURE) as u64) << (32 * half);
        }
        let features = offered & (wanted | VIRTIO_F_VERSION_1);
        if features & VIRTIO_F_VERSION_1 == 0 {
            self.set_status(STATUS_FAILED);
            return Err(Error::FeaturesRejected);
        }
        for half in 0..2u32 {
            mmio_write(self.common + DRIVER_FEATURE_SELECT, half);
            mmio_write(self.common + DRIVER_FEATURE, (features >> (32 * half)) as u32);
        }
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        if mmio_read::<u8>(self.common + DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            self.set_status(STATUS_FAILED);
            return Err(Error::FeaturesRejected);
        }
        // Configuration-change interrupts are not used.
        mmio_write(self.common + MSIX_CONFIG, NO_VECTOR);
        Ok(features)
    }

    /// Set up queue `index` with up to `max_size` entries, interrupting on MSI-X entry 0.
    pub fn queue(&self, index: u16, max_size: u16, dma: &mut Dma) -> Result<Queue, Error> {
        mmio_write(self.common + QUEUE_SELECT, index);
        let device_max = mmio_read::<u16>(self.common + QUEUE_SIZE);
        if device_max == 0 {
            return Err(Error::QueueUnavailable(index));
        }
        let size = max_size.min(device_max);
        let size = 1u16 << (15 - size.leading_zeros()); // a power of two
        mmio_write(self.common + QUEUE_SIZE, size);

        let n = size as u64;
        let (desc, desc_pa) = dma.alloc(16 * n, 16)?;
        let (avail, avail_pa) = dma.alloc(6 + 2 * n, 2)?;
        let (used, used_pa) = dma.alloc(6 + 8 * n, 4)?;
        // The region is zeroed at (re)start, but a device still running from before the reset
        // may have written into it since. Start the rings from a clean slate.
        for (addr, len) in [(desc, 16 * n), (avail, 6 + 2 * n), (used, 6 + 8 * n)] {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, len as usize) };
        }
        mmio_write(self.common + QUEUE_DESC, desc_pa);
        mmio_write(self.common + QUEUE_DRIVER, avail_pa);
        mmio_write(self.common + QUEUE_DEVICE, used_pa);
        mmio_write(self.common + QUEUE_MSIX_VECTOR, 0u16);
        if mmio_read::<u16>(self.common + QUEUE_MSIX_VECTOR) == NO_VECTOR {
            return Err(Error::NoVector);
        }
        let notify_off = mmio_read::<u16>(self.common + QUEUE_NOTIFY_OFF) as u64;
        mmio_write(self.common + QUEUE_ENABLE, 1u16);

        // Chain all descriptors into a free list.
        for i in 0..size {
            mmio_write(desc + 16 * i as u64 + 14, (i + 1) % size);
        }
        Ok(Queue {
            index,
            size,
            desc,
            avail,
            used,
            notify: self.notify + notify_off * self.notify_multiplier as u64,
            free_head: 0,
            free_count: size,
            last_used: 0,
        })
    }

    /// All queues are set up: the device may start.
    pub fn driver_ok(&self) {
        self.set_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    fn set_status(&self, status: u8) {
        mmio_write(self.common + DEVICE_STATUS, status);
    }
}

/// One buffer of a request: physical address, length, and whether the device writes it.
#[derive(Clone, Copy)]
pub struct Buffer {
    pub phys: u64,
    pub len: u32,
    pub device_writes: bool,
}

/// A split virtqueue.
pub struct Queue {
    index: u16,
    size: u16,
    desc: u64,
    avail: u64,
    used: u64,
    notify: u64,
    free_head: u16,
    free_count: u16,
    last_used: u16,
}

const DESC_NEXT: u16 = 1;
const DESC_WRITE: u16 = 2;

impl Queue {
    /// Post a request made of `buffers` and tell the device. Returns the request's id (its
    /// first descriptor), or None if the queue is full.
    pub fn submit(&mut self, buffers: &[Buffer]) -> Option<u16> {
        if buffers.is_empty() || buffers.len() > self.free_count as usize {
            return None;
        }
        let head = self.free_head;
        let mut i = head;
        for (n, b) in buffers.iter().enumerate() {
            let d = self.desc + 16 * i as u64;
            let next = mmio_read::<u16>(d + 14);
            let last = n == buffers.len() - 1;
            mmio_write(d, b.phys);
            mmio_write(d + 8, b.len);
            let flags = if b.device_writes { DESC_WRITE } else { 0 } | if last { 0 } else { DESC_NEXT };
            mmio_write(d + 12, flags);
            if last {
                self.free_head = next;
            } else {
                i = next;
            }
        }
        self.free_count -= buffers.len() as u16;

        let idx = mmio_read::<u16>(self.avail + 2);
        mmio_write(self.avail + 4 + 2 * (idx % self.size) as u64, head);
        fence(Ordering::SeqCst); // the ring entry before the index the device reads
        mmio_write(self.avail + 2, idx.wrapping_add(1));
        fence(Ordering::SeqCst);
        mmio_write(self.notify, self.index);
        Some(head)
    }

    /// A completed request: (id from `submit`, bytes the device wrote). Its descriptors return
    /// to the free list.
    pub fn take_used(&mut self) -> Option<(u16, u32)> {
        fence(Ordering::SeqCst);
        if mmio_read::<u16>(self.used + 2) == self.last_used {
            return None;
        }
        let slot = self.used + 4 + 8 * (self.last_used % self.size) as u64;
        let id = mmio_read::<u32>(slot) as u16;
        let len = mmio_read::<u32>(slot + 4);
        self.last_used = self.last_used.wrapping_add(1);

        // Return the chain to the free list.
        let mut i = id;
        let mut freed = 1;
        while mmio_read::<u16>(self.desc + 16 * i as u64 + 12) & DESC_NEXT != 0 {
            i = mmio_read::<u16>(self.desc + 16 * i as u64 + 14);
            freed += 1;
        }
        mmio_write(self.desc + 16 * i as u64 + 14, self.free_head);
        self.free_head = id;
        self.free_count += freed;
        Some((id, len))
    }
}
