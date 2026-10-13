//! The test program: prints a greeting, then (with a test feature) attacks the kernel's isolation.

#![no_std]
#![no_main]

use vanir_user::{ERROR, write};

vanir_user::entry!(main);

fn main() -> u64 {
    write(b"hello world\n");

    #[cfg(feature = "bad-pointer")]
    {
        let unmapped = unsafe { core::slice::from_raw_parts(0x1000_0000 as *const u8, 16) };
        // Starts in the top stack page and runs off the end of the mapped stack.
        let straddling = unsafe { core::slice::from_raw_parts(0x7fff_ffff_eff0 as *const u8, 32) };
        let rejected = write(unmapped) == ERROR && write(straddling) == ERROR;
        write(if rejected { b"bad pointers rejected\n" } else { b"bad pointer ACCEPTED\n" });
        return if rejected { 0 } else { 1 };
    }

    #[cfg(feature = "abi-sizes")]
    {
        // A short buffer gets the record's start, a long one the whole record; the rest of the
        // buffer is untouched, and the result is always the record's whole size.
        use vanir_user::{SYS_TASK_LISTEN, getpid, println, syscall6};
        let size = core::mem::size_of::<vanir_user::ListenInfo>();
        let read = |cap: usize| {
            let mut buf = [0xaau8; 640];
            let (n, _, _) = syscall6(SYS_TASK_LISTEN, [getpid(), buf.as_mut_ptr() as u64, cap as u64, 0, 0, 0]);
            (n as usize, buf)
        };
        let (_, whole) = read(600);
        let mut ok = true;
        // 136: ListenInfo's size in ABI 1.0, before it grew.
        for cap in [64, 136, 600] {
            let (n, buf) = read(cap);
            let got = cap.min(n);
            let same = buf[..got] == whole[..got];
            let untouched = buf[got..].iter().all(|&b| b == 0xaa);
            println!("hello: task_listen into {} bytes: record {} bytes, {} copied, same start {}, rest untouched {}", cap, n, got, same, untouched);
            ok &= n == size && same && untouched;
        }
        return if ok { 0 } else { 1 };
    }

    #[cfg(feature = "exec-stack")]
    {
        let code = core::hint::black_box([0xc3u8]); // `ret`
        let f: extern "C" fn() = unsafe { core::mem::transmute(code.as_ptr()) };
        write(b"calling code on the stack...\n");
        f();
        write(b"NX BROKEN: executed code on the stack\n");
        return 1;
    }

    #[cfg(feature = "write-code")]
    {
        write(b"writing to our own code...\n");
        unsafe { core::ptr::write_volatile(main as *const () as *mut u8, 0xc3) };
        write(b"W^X BROKEN: code page was writable\n");
        return 1;
    }

    #[cfg(feature = "poke-kernel")]
    {
        write(b"reading kernel memory at 0xffffffff80000000...\n");
        let value = unsafe { core::ptr::read_volatile(0xffff_ffff_8000_0000 as *const u64) };
        // Only reached if isolation is broken.
        write(b"ISOLATION BROKEN: kernel memory was readable\n");
        let _ = value;
    }

    // The kernel rejects buffers outside the user half.
    if write(unsafe { core::slice::from_raw_parts(0xffff_ffff_8000_0000 as *const u8, 8) }) != ERROR {
        return 1;
    }

    0
}
