//! Checks a device grant: reads the granted device's PCI identity and the virtio common
//! configuration through its mapped BAR. Without a grant, the kernel must refuse.

#![no_std]
#![no_main]

use core::ptr::read_volatile;
use vanir_user::{device_bar, err, pci_config_read, println};

vanir_user::entry!(main);

/// Virtio PCI capability: vendor-specific (0x09), cfg_type 1 = common configuration.
const CAP_VENDOR: u32 = 0x09;
const COMMON_CFG: u32 = 1;
/// `num_queues` in the common configuration structure.
const NUM_QUEUES: u64 = 0x12;

fn main() -> u64 {
    let id = match pci_config_read(0, 0) {
        Ok(id) => id,
        Err(e) => {
            println!("devprobe: no device granted: {}", err::name(e));
            // Nothing should be mapped where a device would be.
            return if device_bar(0, 4) == Err(err::BAD_ARGUMENT) { 0 } else { 1 };
        }
    };
    println!("devprobe: device {:04x}:{:04x}", id & 0xffff, id >> 16);

    #[cfg(feature = "poke-msix")]
    {
        let bar1 = vanir_user::DEVICE_BASE + vanir_user::BAR_STRIDE;
        println!("devprobe: BAR 1 (MSI-X) visible to us: {}", device_bar(0, 1).is_ok());
        println!("devprobe: reading where BAR 1 would be...");
        unsafe { read_volatile(bar1 as *const u32) };
        println!("devprobe: MSI-X TABLE WAS READABLE");
        return 1;
    }

    // Walk the capability list for the virtio common configuration.
    let mut cap = pci_config_read(0, 0x34).unwrap() & 0xfc;
    while cap != 0 {
        let header = pci_config_read(0, cap as u64).unwrap();
        if header & 0xff == CAP_VENDOR && (header >> 24) & 0xff == COMMON_CFG {
            let bar = pci_config_read(0, cap as u64 + 4).unwrap() & 0xff;
            let offset = pci_config_read(0, cap as u64 + 8).unwrap();
            let (base, size) = device_bar(0, bar as u64).expect("common config BAR not mapped");
            let num_queues = unsafe { read_volatile((base + offset as u64 + NUM_QUEUES) as *const u16) };
            println!(
                "devprobe: virtio common config in BAR {} ({} KiB at {:#x}), num_queues {}",
                bar,
                size / 1024,
                base,
                num_queues
            );
            return 0;
        }
        cap = (header >> 8) & 0xfc;
    }
    println!("devprobe: no virtio common config capability");
    1
}
