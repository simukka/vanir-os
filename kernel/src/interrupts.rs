//! IDT and the single trap path every exception and syscall goes through.
//!
//! Each vector has a tiny assembly stub that pushes a dummy error code (if the CPU didn't) and the
//! vector number, so every trap lands in `trap_common` with the same `TrapFrame` layout.

use core::arch::global_asm;
use core::mem::size_of;
use spin::Once;
use x86_64::VirtAddr;
use x86_64::instructions::tables::lidt;
use x86_64::registers::control::Cr2;
use x86_64::structures::DescriptorTablePointer;

use crate::{gdt, syscall};

pub const SYSCALL_VECTOR: u8 = 0x80;

/// Saved state at trap time, lowest address first (the reverse of push order).
#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error_code: u64,
    // Pushed by the CPU.
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }
}

global_asm!(
    r#"
.macro TRAP_NOERR n
trap_stub_\n:
    push 0
    push \n
    jmp trap_common
.endm

.macro TRAP_ERR n
trap_stub_\n:
    push \n
    jmp trap_common
.endm

.section .text
trap_common:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rdi, rsp
    cld
    call {handler}
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iretq

TRAP_NOERR 0
TRAP_NOERR 1
TRAP_NOERR 2
TRAP_NOERR 3
TRAP_NOERR 4
TRAP_NOERR 5
TRAP_NOERR 6
TRAP_NOERR 7
TRAP_ERR   8
TRAP_NOERR 9
TRAP_ERR   10
TRAP_ERR   11
TRAP_ERR   12
TRAP_ERR   13
TRAP_ERR   14
TRAP_NOERR 15
TRAP_NOERR 16
TRAP_ERR   17
TRAP_NOERR 18
TRAP_NOERR 19
TRAP_NOERR 20
TRAP_ERR   21
TRAP_NOERR 22
TRAP_NOERR 23
TRAP_NOERR 24
TRAP_NOERR 25
TRAP_NOERR 26
TRAP_NOERR 27
TRAP_NOERR 28
TRAP_ERR   29
TRAP_ERR   30
TRAP_NOERR 31
TRAP_NOERR 128

.section .rodata
.balign 8
.global trap_stub_table
trap_stub_table:
.irp n, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
    .quad trap_stub_\n
.endr
.global trap_stub_syscall
trap_stub_syscall:
    .quad trap_stub_128
"#,
    handler = sym trap_handler,
);

unsafe extern "C" {
    static trap_stub_table: [u64; 32];
    static trap_stub_syscall: u64;
}

/// A 64-bit IDT gate descriptor.
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl Gate {
    const MISSING: Gate = Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        flags: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    /// Interrupt gate (IF cleared on entry). `dpl` is the lowest ring allowed to `int` this vector.
    fn new(handler: u64, dpl: u8, ist: u8) -> Gate {
        Gate {
            offset_low: handler as u16,
            selector: gdt::selectors().kernel_code.0,
            ist,
            flags: 0x80 | (dpl << 5) | 0xE,
            offset_mid: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

static IDT: Once<[Gate; 256]> = Once::new();

pub fn init() {
    let idt = IDT.call_once(|| {
        let mut idt = [Gate::MISSING; 256];
        let stubs = unsafe { &trap_stub_table };
        for (vector, &stub) in stubs.iter().enumerate() {
            idt[vector] = Gate::new(stub, 0, 0);
        }
        // IST indices in the gate are 1-based; 0 means "no stack switch".
        idt[8] = Gate::new(stubs[8], 0, gdt::DOUBLE_FAULT_IST as u8 + 1);
        // DPL 3 so ring 3 may execute `int 0x80`; every other vector #GPs if user code tries.
        idt[SYSCALL_VECTOR as usize] = Gate::new(unsafe { trap_stub_syscall }, 3, 0);
        idt
    });

    unsafe {
        lidt(&DescriptorTablePointer {
            limit: (size_of::<[Gate; 256]>() - 1) as u16,
            base: VirtAddr::from_ptr(idt.as_ptr()),
        });
    }
}

const EXCEPTION_NAMES: [&str; 32] = [
    "#DE divide error",
    "#DB debug",
    "NMI",
    "#BP breakpoint",
    "#OF overflow",
    "#BR bound range",
    "#UD invalid opcode",
    "#NM device not available",
    "#DF double fault",
    "coprocessor segment overrun",
    "#TS invalid TSS",
    "#NP segment not present",
    "#SS stack fault",
    "#GP general protection",
    "#PF page fault",
    "reserved",
    "#MF x87 FP",
    "#AC alignment check",
    "#MC machine check",
    "#XM SIMD FP",
    "#VE virtualization",
    "#CP control protection",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "#HV hypervisor injection",
    "#VC VMM communication",
    "#SX security",
    "reserved",
];

extern "C" fn trap_handler(frame: &mut TrapFrame) {
    if frame.vector == SYSCALL_VECTOR as u64 {
        syscall::dispatch(frame);
        return;
    }

    let name = EXCEPTION_NAMES.get(frame.vector as usize).copied().unwrap_or("unknown");
    let ring = if frame.from_user() { "user" } else { "kernel" };
    println!("\n[kernel] {} in {} mode", name, ring);
    println!("  vector={} error={:#x} rip={:#x} rsp={:#x}", frame.vector, frame.error_code, frame.rip, frame.rsp);
    if frame.vector == 14 {
        println!("  cr2={:#x}", Cr2::read_raw());
    }
    // No scheduler: a faulting process (or kernel) ends the machine.
    crate::halt(if frame.from_user() { 2 } else { 3 });
}
