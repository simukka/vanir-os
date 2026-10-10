//! Checks the DMA region: present, page-aligned, readable and writable, and zeroed on each
//! start. The first run (generation 0) leaves a marker and crashes; after the supervisor
//! restarts it, the marker must be gone.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use vanir_user::{dma_info, err, getpid, println};

vanir_user::entry!(main);

const MARKER: u64 = 0x5eed_5eed_5eed_5eed;

fn main() -> u64 {
    let (addr, phys, len) = match dma_info() {
        Ok(info) => info,
        Err(e) => {
            println!("dmatest: no DMA region: {}", err::name(e));
            return 0;
        }
    };
    let generation = getpid() >> 16;
    let words = (len / 8) as usize;
    let region = addr as *mut u64;
    let all_zero = (0..words).all(|i| unsafe { read_volatile(region.add(i)) } == 0);
    println!(
        "dmatest: start {}: {} KiB at {:#x}, physical {:#x}, all zero: {}",
        generation,
        len / 1024,
        addr,
        phys,
        all_zero
    );
    if !all_zero || phys % 4096 != 0 {
        return 1;
    }
    for i in 0..words {
        unsafe { write_volatile(region.add(i), MARKER ^ i as u64) };
    }
    if (0..words).any(|i| unsafe { read_volatile(region.add(i)) } != MARKER ^ i as u64) {
        println!("dmatest: readback FAILED");
        return 1;
    }
    if generation == 0 {
        println!("dmatest: marked the region, now crashing");
        unsafe { read_volatile(0x10 as *const u8) };
    }
    println!("dmatest: region ok after restart");
    0
}
