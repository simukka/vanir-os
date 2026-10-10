//! COM1 (0x3F8) 16550 UART: the kernel's only output device.

use core::fmt::{self, Write};
use spin::Mutex;
use x86_64::instructions::port::Port;

const COM1: u16 = 0x3F8;

pub struct Serial;

static SERIAL: Mutex<Serial> = Mutex::new(Serial);

unsafe fn outb(port: u16, val: u8) {
    unsafe { Port::new(port).write(val) }
}

unsafe fn inb(port: u16) -> u8 {
    unsafe { Port::new(port).read() }
}

pub fn init() {
    unsafe {
        outb(COM1 + 1, 0x00); // disable UART interrupts
        outb(COM1 + 3, 0x80); // DLAB on
        outb(COM1, 0x01); // divisor 1 = 115200 baud
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xC7); // enable + clear FIFOs
        outb(COM1 + 4, 0x03); // DTR | RTS
    }
}

impl Serial {
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            unsafe {
                while inb(COM1 + 5) & 0x20 == 0 {} // wait for empty transmit register
                outb(COM1, b);
            }
        }
    }
}

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s.as_bytes());
        Ok(())
    }
}

pub fn write_bytes(bytes: &[u8]) {
    SERIAL.lock().write_bytes(bytes);
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _ = SERIAL.lock().write_fmt(args);
}

/// Print without taking the lock; for the panic path, which may run while it is held.
pub fn print_unlocked(args: fmt::Arguments) {
    let _ = Serial.write_fmt(args);
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::serial::_print(format_args!($($arg)*)) };
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}
