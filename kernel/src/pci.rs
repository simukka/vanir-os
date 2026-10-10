//! PCI discovery through the legacy configuration ports (0xCF8/0xCFC), which q35 provides.
//!
//! The kernel finds every device at boot and keeps control of each one's configuration space:
//! it turns on memory decoding and bus mastering, and it alone programs interrupt routing
//! (MSI-X). A driver task is granted a device in the app manifest and gets its register BARs
//! mapped, minus any BAR that holds the MSI-X table.

use spin::Once;
use x86_64::instructions::port::Port;

pub const MAX_DEVICES: usize = 32;

include!("pci_kinds.rs");

#[derive(Clone, Copy, Debug, Default)]
pub struct Bar {
    pub phys: u64,
    pub size: u64,
    /// Holds the MSI-X table or pending-bit array: never mapped into a task.
    pub msix: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Device {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    /// Index into `KINDS`, if it is a device a manifest can name.
    pub kind: Option<usize>,
    pub bars: [Bar; 6],
    /// Config-space offset of the MSI-X capability.
    pub msix_cap: Option<u8>,
}

struct Devices {
    list: [Option<Device>; MAX_DEVICES],
}

static DEVICES: Once<Devices> = Once::new();

fn address(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000 | (bus as u32) << 16 | (dev as u32) << 11 | (func as u32) << 8 | (offset as u32 & 0xfc)
}

pub fn config_read(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        Port::<u32>::new(0xcf8).write(address(bus, dev, func, offset));
        Port::<u32>::new(0xcfc).read()
    }
}

pub fn config_write(bus: u8, dev: u8, func: u8, offset: u8, value: u32) {
    unsafe {
        Port::<u32>::new(0xcf8).write(address(bus, dev, func, offset));
        Port::<u32>::new(0xcfc).write(value);
    }
}

impl Device {
    pub fn read(&self, offset: u8) -> u32 {
        config_read(self.bus, self.dev, self.func, offset)
    }

    pub fn write(&self, offset: u8, value: u32) {
        config_write(self.bus, self.dev, self.func, offset, value)
    }

    pub fn kind_name(&self) -> &'static str {
        self.kind.map_or("-", |k| KINDS[k].0)
    }
}

/// Scan every bus reachable from bus 0 and set up each device found.
pub fn init() {
    DEVICES.call_once(|| {
        let mut devices = Devices { list: [None; MAX_DEVICES] };
        let mut count = 0;
        scan_bus(0, &mut devices, &mut count);
        devices
    });
}

fn scan_bus(bus: u8, devices: &mut Devices, count: &mut usize) {
    for dev in 0..32 {
        for func in 0..8 {
            let id = config_read(bus, dev, func, 0);
            if id & 0xffff == 0xffff {
                if func == 0 {
                    break; // no device here
                }
                continue;
            }
            let header = (config_read(bus, dev, func, 0x0c) >> 16) as u8;
            if header & 0x7f == 1 {
                // PCI-to-PCI bridge: its devices are on its secondary bus.
                let secondary = (config_read(bus, dev, func, 0x18) >> 8) as u8;
                if secondary > bus {
                    scan_bus(secondary, devices, count);
                }
            } else if header & 0x7f == 0 && *count < MAX_DEVICES {
                let d = probe(bus, dev, func, id);
                println!(
                    "[kernel] pci {:02x}:{:02x}.{} {:04x}:{:04x} {}",
                    bus, dev, func, d.vendor, d.device, d.kind_name()
                );
                devices.list[*count] = Some(d);
                *count += 1;
            }
            if func == 0 && header & 0x80 == 0 {
                break; // single-function device
            }
        }
    }
}

fn probe(bus: u8, dev: u8, func: u8, id: u32) -> Device {
    let (vendor, device) = (id as u16, (id >> 16) as u16);
    let kind = KINDS.iter().position(|(_, v, ids)| *v == vendor && ids.contains(&device));
    let mut d = Device { bus, dev, func, vendor, device, kind, bars: [Bar::default(); 6], msix_cap: None };

    // Size the BARs with decoding off, so the all-ones probe never reaches the bus.
    let command = d.read(0x04);
    d.write(0x04, command & !0b11);
    let mut i = 0;
    while i < 6 {
        let offset = 0x10 + 4 * i as u8;
        let low = d.read(offset);
        if low & 1 != 0 {
            i += 1; // I/O-port BAR: drivers here use memory BARs only
            continue;
        }
        let is_64 = (low >> 1) & 0b11 == 0b10;
        d.write(offset, 0xffff_ffff);
        let mut size_mask = (d.read(offset) & !0xf) as u64;
        d.write(offset, low);
        let mut phys = (low & !0xf) as u64;
        if is_64 {
            let high = d.read(offset + 4);
            d.write(offset + 4, 0xffff_ffff);
            size_mask |= (d.read(offset + 4) as u64) << 32;
            d.write(offset + 4, high);
            phys |= (high as u64) << 32;
        } else {
            size_mask |= 0xffff_ffff_0000_0000;
        }
        let size = (!size_mask).wrapping_add(1);
        if size_mask != 0 && phys != 0 {
            d.bars[i] = Bar { phys, size, msix: false };
        }
        i += if is_64 { 2 } else { 1 };
    }

    // Capabilities list: find MSI-X and mark the BARs holding its table and pending bits.
    if d.read(0x04) >> 16 & 0x10 != 0 {
        let mut cap = (d.read(0x34) & 0xfc) as u8;
        while cap != 0 {
            let header = d.read(cap);
            if header as u8 == 0x11 {
                d.msix_cap = Some(cap);
                let table = d.read(cap + 4) as usize & 0b111;
                let pba = d.read(cap + 8) as usize & 0b111;
                d.bars[table].msix = true;
                d.bars[pba].msix = true;
            }
            cap = (header >> 8) as u8 & 0xfc;
        }
    }

    // Memory decoding and bus mastering on; legacy INTx off (interrupts will use MSI-X).
    d.write(0x04, (command | 0b110 | 1 << 10) & 0xffff);
    d
}

pub fn get(index: usize) -> Option<&'static Device> {
    DEVICES.get()?.list.get(index)?.as_ref()
}

/// Indices of devices of `kind`, in discovery order.
pub fn of_kind(kind: usize) -> impl Iterator<Item = usize> {
    (0..MAX_DEVICES).filter(move |&i| get(i).is_some_and(|d| d.kind == Some(kind)))
}
