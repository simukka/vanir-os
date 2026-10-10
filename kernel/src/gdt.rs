//! GDT and TSS. The TSS's RSP0 is the stack the CPU switches to when ring 3 traps into the kernel.

use spin::Once;
use x86_64::VirtAddr;
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

/// IST slot (0-based, as stored in the TSS) used for #DF so it always runs on a known-good stack.
pub const DOUBLE_FAULT_IST: usize = 0;

const STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);

static mut KERNEL_STACK: Stack = Stack([0; STACK_SIZE]);
static mut DOUBLE_FAULT_STACK: Stack = Stack([0; STACK_SIZE]);

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_data: SegmentSelector,
    pub user_code: SegmentSelector,
    pub tss: SegmentSelector,
}

static TSS: Once<TaskStateSegment> = Once::new();
static GDT: Once<(GlobalDescriptorTable, Selectors)> = Once::new();

fn stack_top(stack: *const Stack) -> VirtAddr {
    VirtAddr::from_ptr(stack) + STACK_SIZE as u64
}

pub fn init() {
    let tss = TSS.call_once(|| {
        let mut tss = TaskStateSegment::new();
        tss.privilege_stack_table[0] = stack_top(&raw const KERNEL_STACK);
        tss.interrupt_stack_table[DOUBLE_FAULT_IST] = stack_top(&raw const DOUBLE_FAULT_STACK);
        tss
    });

    // Kernel code/data, then user data/code: the order SYSCALL/SYSRET would need later.
    let (gdt, sel) = GDT.call_once(|| {
        let mut gdt = GlobalDescriptorTable::new();
        let sel = Selectors {
            kernel_code: gdt.append(Descriptor::kernel_code_segment()),
            kernel_data: gdt.append(Descriptor::kernel_data_segment()),
            user_data: gdt.append(Descriptor::user_data_segment()),
            user_code: gdt.append(Descriptor::user_code_segment()),
            tss: gdt.append(Descriptor::tss_segment(tss)),
        };
        (gdt, sel)
    });

    gdt.load();
    unsafe {
        CS::set_reg(sel.kernel_code);
        SS::set_reg(sel.kernel_data);
        DS::set_reg(SegmentSelector(0));
        ES::set_reg(SegmentSelector(0));
        load_tss(sel.tss);
    }
}

pub fn selectors() -> &'static Selectors {
    &GDT.get().expect("gdt::init not called").1
}
