//! The storage task: the only client of the block driver. Each task that talks to it gets its
//! own volume, a fixed range of the disk, found by the task's manifest name (which the kernel
//! vouches for: it comes from `task_name` of the sender's id, not from the client). Clients use
//! the `vanir_user::block` interface with block numbers relative to their volume, and can't
//! address anything outside it.
//!
//! On disk (4 KiB blocks): block 0 superblock, block 1 the volume table, data from block 2.

#![no_std]
#![no_main]

use vanir_user::block::{self, BLOCK_SIZE, CODE_BAD_OP, CODE_IO_ERROR, CODE_OK, CODE_OUT_OF_RANGE, OP_FLUSH, OP_INFO, OP_READ, OP_WRITE, split};
use vanir_user::{err, lookup, println, recv, reply, sleep, task_name};

vanir_user::entry!(main);

const MAGIC: &[u8; 8] = b"VNRSTOR1";
const SUPERBLOCK: u64 = 0;
const TABLE: u64 = 1;
const FIRST_DATA: u64 = 2;
/// Every volume's size: 1 MiB.
const VOLUME_BLOCKS: u64 = 256;
const MAX_VOLUMES: usize = BLOCK_SIZE / ENTRY;
/// Volume table entry: name (32 bytes, zero padded), start block, size in blocks.
const ENTRY: usize = 64;

#[derive(Clone, Copy)]
struct Volume {
    name: [u8; 32],
    start: u64,
    blocks: u64,
}

struct Storage {
    driver: u64,
    capacity: u64,
    next_free: u64,
    volumes: [Option<Volume>; MAX_VOLUMES],
}

/// Run a driver call, finding the driver again (by name) if it was restarted.
fn on_driver<T>(driver: &mut u64, mut f: impl FnMut(u64) -> Result<T, u64>) -> Result<T, u64> {
    loop {
        match f(*driver) {
            Err(e) if e == err::DEAD => {
                let old = *driver;
                *driver = loop {
                    match lookup("blockdev") {
                        Ok(id) if id != old => break id,
                        _ => sleep(1),
                    }
                };
            }
            other => return other,
        }
    }
}

impl Storage {
    fn read(&mut self, b: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), u64> {
        on_driver(&mut self.driver, |d| block::read(d, b, buf))
    }

    fn write(&mut self, b: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), u64> {
        on_driver(&mut self.driver, |d| block::write(d, b, buf))
    }

    fn flush(&mut self) -> Result<(), u64> {
        on_driver(&mut self.driver, block::flush)
    }

    /// Read the superblock and volume table, formatting the disk if it has none.
    fn open(&mut self) -> Result<(), u64> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read(SUPERBLOCK, &mut buf)?;
        if &buf[..8] != MAGIC {
            println!("storage: no volume table on the disk; formatting");
            self.next_free = FIRST_DATA;
            return self.save();
        }
        self.next_free = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        self.read(TABLE, &mut buf)?;
        for (i, slot) in self.volumes.iter_mut().enumerate() {
            let e = &buf[i * ENTRY..(i + 1) * ENTRY];
            if e[0] != 0 {
                *slot = Some(Volume {
                    name: e[..32].try_into().unwrap(),
                    start: u64::from_le_bytes(e[32..40].try_into().unwrap()),
                    blocks: u64::from_le_bytes(e[40..48].try_into().unwrap()),
                });
            }
        }
        let count = self.volumes.iter().flatten().count();
        println!("storage: {} volume(s) on the disk", count);
        Ok(())
    }

    /// Write the volume table, then the superblock that points past it, then flush.
    fn save(&mut self) -> Result<(), u64> {
        let mut buf = [0u8; BLOCK_SIZE];
        for (i, v) in self.volumes.iter().enumerate() {
            if let Some(v) = v {
                let e = &mut buf[i * ENTRY..(i + 1) * ENTRY];
                e[..32].copy_from_slice(&v.name);
                e[32..40].copy_from_slice(&v.start.to_le_bytes());
                e[40..48].copy_from_slice(&v.blocks.to_le_bytes());
            }
        }
        self.write(TABLE, &buf)?;
        let mut sb = [0u8; BLOCK_SIZE];
        sb[..8].copy_from_slice(MAGIC);
        sb[8..16].copy_from_slice(&self.next_free.to_le_bytes());
        self.write(SUPERBLOCK, &sb)?;
        self.flush()
    }

    /// The volume of the task named `name`, created on first use.
    fn volume(&mut self, name: &[u8]) -> Result<Volume, u64> {
        let mut key = [0u8; 32];
        key[..name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
        if let Some(v) = self.volumes.iter().flatten().find(|v| v.name == key) {
            return Ok(*v);
        }
        let Some(slot) = self.volumes.iter().position(Option::is_none) else { return Err(CODE_OUT_OF_RANGE) };
        if self.next_free + VOLUME_BLOCKS > self.capacity {
            return Err(CODE_OUT_OF_RANGE);
        }
        let v = Volume { name: key, start: self.next_free, blocks: VOLUME_BLOCKS };
        self.volumes[slot] = Some(v);
        self.next_free += VOLUME_BLOCKS;
        self.save()?;
        println!(
            "storage: new volume for {}: blocks {}..{}",
            core::str::from_utf8(name).unwrap_or("?"),
            v.start,
            v.start + v.blocks
        );
        Ok(v)
    }
}

fn main() -> u64 {
    let driver = lookup("blockdev").expect("no blockdev task");
    let mut s = Storage { driver, capacity: 0, next_free: FIRST_DATA, volumes: [None; MAX_VOLUMES] };
    s.capacity = match on_driver(&mut s.driver, block::capacity) {
        Ok(c) => c,
        Err(e) => {
            println!("storage: no disk: {}", block::code_name(e));
            return 1;
        }
    };
    if let Err(e) = s.open() {
        println!("storage: cannot read the volume table: {}", block::code_name(e));
        return 1;
    }

    let mut msg = [0u8; BLOCK_SIZE];
    loop {
        let m = match recv(&mut msg) {
            Ok(m) => m,
            Err(e) => {
                println!("storage: recv failed: {}", err::name(e));
                continue;
            }
        };
        let mut name_buf = [0u8; 64];
        let Ok(name) = task_name(m.sender, &mut name_buf).map(|n| n.as_bytes()) else {
            let _ = reply(m.sender, CODE_BAD_OP, &[]);
            continue;
        };
        let mut name_copy = [0u8; 64];
        name_copy[..name.len()].copy_from_slice(name);
        let name = &name_copy[..name.len()];
        let v = match s.volume(name) {
            Ok(v) => v,
            Err(code) => {
                let _ = reply(m.sender, code, &[]);
                continue;
            }
        };
        let (op, b) = split(m.op);
        let result = match op {
            OP_INFO => {
                let _ = reply(m.sender, CODE_OK, &v.blocks.to_le_bytes());
                continue;
            }
            OP_FLUSH => s.flush(),
            OP_READ | OP_WRITE if b >= v.blocks => Err(CODE_OUT_OF_RANGE),
            OP_READ => match s.read(v.start + b, &mut msg) {
                Ok(()) => {
                    let _ = reply(m.sender, CODE_OK, &msg);
                    continue;
                }
                Err(e) => Err(e),
            },
            OP_WRITE if m.len == BLOCK_SIZE => s.write(v.start + b, &msg),
            _ => Err(CODE_BAD_OP),
        };
        let code = match result {
            Ok(()) => CODE_OK,
            Err(e) if err::is_error(e) => CODE_IO_ERROR,
            Err(code) => code,
        };
        let _ = reply(m.sender, code, &[]);
    }
}
