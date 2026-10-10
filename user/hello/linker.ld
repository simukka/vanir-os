/* Flat binary loaded at 0x400000; the kernel jumps to the first byte. */
ENTRY(_start)

SECTIONS
{
    . = 0x400000;
    .text : { *(.text.entry) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    /* .bss is folded into .data so objcopy -O binary emits its zeros. */
    .data : { *(.data .data.*) *(.bss .bss.*) *(COMMON) }
    /DISCARD/ : { *(.eh_frame*) *(.note .note.*) *(.comment) }
}
