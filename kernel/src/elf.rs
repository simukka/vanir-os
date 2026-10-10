//! Minimal ELF64 loader: maps each PT_LOAD segment into the user half with the permissions its
//! flags ask for, and refuses segments that are both writable and executable (W^X).

use core::mem::size_of;
use core::ptr;

use crate::memory::{self, AddressSpace, PAGE_SIZE};
use crate::usercopy::is_user_range;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 0x3e;

#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    ident: [u8; 16],
    type_: u16,
    machine: u16,
    version: u32,
    entry: u64,
    phoff: u64,
    shoff: u64,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProgramHeader {
    type_: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

#[derive(Debug)]
pub enum LoadError {
    BadHeader,
    BadSegment,
    WritableAndExecutable,
    EntryNotExecutable,
}

/// Read a `T` at `offset`, bounds-checked. The image is a byte array with no alignment guarantee.
fn read<T: Copy>(image: &[u8], offset: u64) -> Result<T, LoadError> {
    let offset = usize::try_from(offset).map_err(|_| LoadError::BadHeader)?;
    match offset.checked_add(size_of::<T>()) {
        Some(end) if end <= image.len() => Ok(unsafe { ptr::read_unaligned(image.as_ptr().add(offset) as *const T) }),
        _ => Err(LoadError::BadHeader),
    }
}

/// Map and copy every PT_LOAD segment of `image` into `space`; returns the entry point.
///
/// Overlapping segments trip an assertion in `map_user_page`; the image is built with the kernel,
/// and verifying it before loading is a later step.
pub fn load(image: &[u8], space: &AddressSpace) -> Result<u64, LoadError> {
    let header: Header = read(image, 0)?;
    let ident_ok = header.ident[..4] == *b"\x7fELF" && header.ident[4] == 2 && header.ident[5] == 1;
    if !ident_ok
        || header.type_ != ET_EXEC
        || header.machine != EM_X86_64
        || header.phentsize as usize != size_of::<ProgramHeader>()
    {
        return Err(LoadError::BadHeader);
    }

    let mut entry_executable = false;
    for i in 0..header.phnum as u64 {
        let ph: ProgramHeader = read(image, header.phoff + i * size_of::<ProgramHeader>() as u64)?;
        if ph.type_ != PT_LOAD {
            continue;
        }
        let writable = ph.flags & PF_W != 0;
        let executable = ph.flags & PF_X != 0;
        if writable && executable {
            return Err(LoadError::WritableAndExecutable);
        }
        let file_end = ph.offset.checked_add(ph.filesz).ok_or(LoadError::BadSegment)?;
        if ph.vaddr % PAGE_SIZE != 0
            || ph.filesz > ph.memsz
            || file_end > image.len() as u64
            || !is_user_range(ph.vaddr, ph.memsz)
        {
            return Err(LoadError::BadSegment);
        }

        let data = &image[ph.offset as usize..file_end as usize];
        for page in (0..ph.memsz).step_by(PAGE_SIZE as usize) {
            // Frames are zeroed, so the part past filesz (.bss) needs no work.
            let frame = space.map_user_page(ph.vaddr + page, writable, executable);
            let chunk = data.get(page as usize..).unwrap_or(&[]);
            let chunk = &chunk[..chunk.len().min(PAGE_SIZE as usize)];
            unsafe { ptr::copy_nonoverlapping(chunk.as_ptr(), memory::phys_to_virt(frame), chunk.len()) };
        }

        if executable && (ph.vaddr..ph.vaddr + ph.memsz).contains(&header.entry) {
            entry_executable = true;
        }
    }

    if !entry_executable {
        return Err(LoadError::EntryNotExecutable);
    }
    Ok(header.entry)
}
