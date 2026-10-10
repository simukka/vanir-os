//! The preemption clock: the local APIC timer, firing `TICK_HZ` times a second.
//!
//! The legacy 8259 PIC is remapped to vectors 0x20-0x2f and fully masked; any spurious interrupt
//! it raises lands on a harmless vector instead of looking like a CPU exception.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

use crate::memory;

pub const PIC_VECTORS: core::ops::Range<u64> = 0x20..0x30;
pub const TIMER_VECTOR: u8 = 0x40;
pub const SPURIOUS_VECTOR: u8 = 0xff;
pub const TICK_HZ: u32 = 100;

/// Where the APIC's registers are mapped (uncached), just below the kernel image.
const LAPIC_VIRT: u64 = 0xffff_ffff_7fff_f000;
const IA32_APIC_BASE: u32 = 0x1b;

const TPR: u64 = 0x80;
const EOI: u64 = 0xb0;
const SVR: u64 = 0xf0;
const LVT_TIMER: u64 = 0x320;
const INITIAL_COUNT: u64 = 0x380;
const CURRENT_COUNT: u64 = 0x390;
const DIVIDE: u64 = 0x3e0;

const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;
const SVR_ENABLE: u32 = 1 << 8;

fn read(reg: u64) -> u32 {
    unsafe { read_volatile((LAPIC_VIRT + reg) as *const u32) }
}

fn write(reg: u64, value: u32) {
    unsafe { write_volatile((LAPIC_VIRT + reg) as *mut u32, value) }
}

pub fn init() {
    remap_and_mask_pic();

    let base = unsafe { Msr::new(IA32_APIC_BASE).read() };
    assert!(base & (1 << 11) != 0, "local APIC is disabled");
    memory::map_kernel_mmio(LAPIC_VIRT, base & 0x000f_ffff_ffff_f000);

    write(TPR, 0); // accept every priority
    write(SVR, SVR_ENABLE | SPURIOUS_VECTOR as u32);
    write(DIVIDE, 0b0011); // count at bus clock / 16

    let per_tick = calibrate() * 100 / TICK_HZ;
    write(LVT_TIMER, LVT_PERIODIC | TIMER_VECTOR as u32);
    write(INITIAL_COUNT, per_tick);
    println!("[kernel] APIC timer: {} Hz ({} counts per tick)", TICK_HZ, per_tick);
}

/// Timer interrupts since boot. Updated without locks, because the timer can also fire while the
/// kernel is idle (halted inside the scheduler, holding the process table).
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Count a timer interrupt.
pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Timer ticks since boot (10 ms each).
pub fn now() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Acknowledge the current interrupt. Not sent for spurious interrupts.
pub fn eoi() {
    write(EOI, 0);
}

/// APIC timer counts in 10 ms, measured against PIT channel 2 (fixed 1.193182 MHz) in one-shot
/// mode: its OUT pin, readable in port 0x61 bit 5, goes high when the count reaches zero.
fn calibrate() -> u32 {
    const PIT_HZ: u32 = 1_193_182;
    let count = (PIT_HZ / 100) as u16;
    let mut gate = Port::<u8>::new(0x61);
    let mut command = Port::<u8>::new(0x43);
    let mut channel2 = Port::<u8>::new(0x42);
    unsafe {
        let g = gate.read() & !0b11; // channel 2 gate off, speaker off
        gate.write(g);
        command.write(0b1011_0000); // channel 2, low then high byte, mode 0, binary
        channel2.write(count as u8);
        channel2.write((count >> 8) as u8);

        write(LVT_TIMER, LVT_MASKED | TIMER_VECTOR as u32);
        write(INITIAL_COUNT, u32::MAX);
        gate.write(g | 1); // start PIT channel 2
        while gate.read() & 0x20 == 0 {}
        let elapsed = u32::MAX - read(CURRENT_COUNT);
        write(INITIAL_COUNT, 0);
        elapsed
    }
}

fn remap_and_mask_pic() {
    let mut master_cmd = Port::<u8>::new(0x20);
    let mut master_data = Port::<u8>::new(0x21);
    let mut slave_cmd = Port::<u8>::new(0xa0);
    let mut slave_data = Port::<u8>::new(0xa1);
    unsafe {
        master_cmd.write(0x11); // ICW1: initialise, expect ICW4
        slave_cmd.write(0x11);
        master_data.write(PIC_VECTORS.start as u8); // ICW2: vector base
        slave_data.write(PIC_VECTORS.start as u8 + 8);
        master_data.write(4); // ICW3: slave on IRQ2
        slave_data.write(2);
        master_data.write(1); // ICW4: 8086 mode
        slave_data.write(1);
        master_data.write(0xff); // mask everything
        slave_data.write(0xff);
    }
}
