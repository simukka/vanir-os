//! Just enough of a TPM 2.0 driver (CRB interface, locality 0) to measure the boot: extend
//! PCRs and read them back. The kernel uses the TPM only before any task runs.

use core::ptr::{read_volatile, write_volatile};
use sha2::{Digest, Sha256};
use spin::Once;

use crate::memory;

/// Where QEMU's tpm-crb puts the CRB registers (the ACPI TPM2 table would say so on real
/// hardware).
const CRB_PHYS: u64 = 0xfed4_0000;
/// Kernel address of the CRB page (next to the MSI-X table mappings).
const CRB_VIRT: u64 = 0xffff_ffff_7080_0000;

const LOC_CTRL: u64 = 0x08;
const LOC_STS: u64 = 0x0c;
const INTF_ID: u64 = 0x30;
const CTRL_REQ: u64 = 0x40;
const CTRL_START: u64 = 0x4c;
const CTRL_CMD_LADDR: u64 = 0x5c;
const CTRL_RSP_ADDR: u64 = 0x68;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_PCR_EXTEND: u32 = 0x182;
const TPM_CC_PCR_READ: u32 = 0x17e;
const TPM_CC_STARTUP: u32 = 0x144;
const TPM_RC_INITIALIZE: u32 = 0x100;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_RS_PW: u32 = 0x4000_0009;

static PRESENT: Once<bool> = Once::new();

fn reg32(offset: u64) -> u32 {
    unsafe { read_volatile((CRB_VIRT + offset) as *const u32) }
}

fn set32(offset: u64, value: u32) {
    unsafe { write_volatile((CRB_VIRT + offset) as *mut u32, value) }
}

/// Map the CRB page and see whether a TPM answers. Returns whether one does.
pub fn init() -> bool {
    *PRESENT.call_once(|| {
        memory::map_kernel_mmio(CRB_VIRT, CRB_PHYS);
        let id = reg32(INTF_ID);
        // Interface type 1 = CRB; all ones = nothing there.
        if id == u32::MAX || id & 0xf != 1 {
            return false;
        }
        set32(LOC_CTRL, 1); // request locality 0
        if !(0..1_000_000).any(|_| reg32(LOC_STS) & 1 != 0) {
            return false;
        }
        // UEFI firmware with TPM support has already started it; otherwise do it now.
        let mut buf = [0u8; 512];
        let len = command(&mut buf, TPM_ST_NO_SESSIONS, TPM_CC_STARTUP, |w| w.u16(0)); // SU_CLEAR
        match execute(&mut buf, len) {
            Ok(_) => println!("[kernel] tpm: started it (firmware had not)"),
            Err(TPM_RC_INITIALIZE) => {} // already started
            Err(code) => println!("[kernel] tpm: TPM2_Startup failed with {:#x}", code),
        }
        true
    })
}

/// Send one command and return the response code and response length (left in `buf`).
fn execute(buf: &mut [u8; 512], len: usize) -> Result<usize, u32> {
    // The command and response buffers are inside the CRB page.
    let cmd = CRB_VIRT + (reg32(CTRL_CMD_LADDR) as u64 & 0xfff);
    let rsp = CRB_VIRT + (unsafe { read_volatile((CRB_VIRT + CTRL_RSP_ADDR) as *const u64) } & 0xfff);
    set32(CTRL_REQ, 1); // cmdReady
    while reg32(CTRL_REQ) & 1 != 0 {
        core::hint::spin_loop();
    }
    for (i, &b) in buf[..len].iter().enumerate() {
        unsafe { write_volatile((cmd + i as u64) as *mut u8, b) };
    }
    set32(CTRL_START, 1);
    while reg32(CTRL_START) & 1 != 0 {
        core::hint::spin_loop();
    }
    let header: [u8; 10] = core::array::from_fn(|i| unsafe { read_volatile((rsp + i as u64) as *const u8) });
    let size = (u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize).min(buf.len());
    let code = u32::from_be_bytes(header[6..10].try_into().unwrap());
    for (i, b) in buf[..size].iter_mut().enumerate() {
        *b = unsafe { read_volatile((rsp + i as u64) as *const u8) };
    }
    if code != 0 { Err(code) } else { Ok(size) }
}

/// Build a command in `buf`: header (size patched at the end), then `body` writes the rest.
fn command(buf: &mut [u8; 512], tag: u16, code: u32, body: impl FnOnce(&mut Writer)) -> usize {
    let mut w = Writer { buf, len: 0 };
    w.u16(tag);
    w.u32(0);
    w.u32(code);
    body(&mut w);
    let len = w.len;
    buf[2..6].copy_from_slice(&(len as u32).to_be_bytes());
    len
}

struct Writer<'a> {
    buf: &'a mut [u8; 512],
    len: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }
    fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }
}

/// PCR[pcr] = SHA-256(PCR[pcr] || digest).
pub fn extend(pcr: u32, digest: &[u8; 32]) -> Result<(), u32> {
    let mut buf = [0u8; 512];
    let len = command(&mut buf, TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND, |w| {
        w.u32(pcr);
        // Authorization: one empty password session.
        w.u32(9);
        w.u32(TPM_RS_PW);
        w.u16(0);
        w.u8(0);
        w.u16(0);
        // TPML_DIGEST_VALUES with one SHA-256 digest.
        w.u32(1);
        w.u16(TPM_ALG_SHA256);
        w.bytes(digest);
    });
    execute(&mut buf, len).map(|_| ())
}

/// The SHA-256 bank's value of PCR[pcr].
pub fn read(pcr: u32) -> Result<[u8; 32], u32> {
    let mut buf = [0u8; 512];
    let len = command(&mut buf, TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ, |w| {
        w.u32(1); // one selection
        w.u16(TPM_ALG_SHA256);
        w.u8(3); // sizeofSelect: PCRs 0-23
        let mut select = [0u8; 3];
        select[(pcr / 8) as usize] = 1 << (pcr % 8);
        w.bytes(&select);
    });
    let size = execute(&mut buf, len)?;
    // header(10) updateCounter(4) TPML_PCR_SELECTION(4+2+1+3) TPML_DIGEST count(4) size(2) digest
    let at = 10 + 4 + 10 + 4;
    if size < at + 2 + 32 || u16::from_be_bytes([buf[at], buf[at + 1]]) != 32 {
        return Err(u32::MAX);
    }
    Ok(buf[at + 2..at + 34].try_into().unwrap())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
