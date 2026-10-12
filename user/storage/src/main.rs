//! The storage task: the only client of the block driver. Each task that talks to it gets its
//! own volume, a fixed range of the disk, found by the task's manifest name (which the kernel
//! vouches for: it comes from `task_name` of the sender's id, not from the client). Clients use
//! the `vanir_user::block` interface with block numbers relative to their volume, and can't
//! address anything outside it.
//!
//! Every block is encrypted at rest with XChaCha20-Poly1305 under its volume's key,
//! HKDF-SHA256(master key, volume name). The nonce is the block number and a per-block write
//! counter (so it never repeats), and the block's volume name, number and counter are bound in
//! as associated data, so ciphertext changed, moved between blocks or volumes, or paired with
//! the wrong counter fails to decrypt (CODE_INTEGRITY). Counters and tags live in each volume's
//! metadata blocks.
//!
//! Each volume starts with a header block, sealed the same way under block number `HEADER`
//! (its counter and tag sit in plain text at the front of the block): its kind, name and size,
//! and the writer epoch and lease (RFD 3, P1). It is checked against the volume table on a
//! volume's first read or write after each unlock. Volumes are of two kinds, kept apart by the
//! table and by the key's HKDF salt: a fixed task's, found by its task name, and (RFD 3) a
//! service's.
//!
//! **Service volumes (RFD 3, P1).** An instance in a generic slot reaches the volume its signed
//! descriptor declares (`task_listen`'s `volume_blocks`), named after its service, whichever slot
//! it runs in; without one it gets CODE_NOT_ALLOWED. The size is fixed by the version that made
//! the volume: an instance declaring another size gets CODE_OUT_OF_RANGE. Any instance of the
//! service may read; only the writer may write or flush, others get CODE_FENCED. The agent
//! (`loads = true`) names the writer with OP_EPOCH. The writer is a slot, kept in memory only:
//! a restarted writer stays the writer, and after this task restarts nobody is until the agent
//! says again. Epochs only go up, across reboots (they are in the header).
//!
//! The master key is only ever in memory. The task starts locked, answering CODE_LOCKED: it asks
//! the key server ("keys") for the key if it may send to one, and otherwise waits for OP_UNLOCK
//! (from "attest", after the host released the key). A restarted storage task starts locked
//! again, and has to get the key again.
//!
//! Storage events go to the telemetry task if it may send to one: volume_created,
//! storage_locked, storage_unlocked and integrity_error (with the volume and block).
//!
//! On disk (4 KiB blocks): block 0 superblock, block 1 the volume table (both in plain text),
//! then volumes: a header block, then `meta_blocks(size)` metadata blocks, then the data blocks.
//! A disk in an older format is reformatted.

#![no_std]
#![no_main]

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use vanir_user::block::{
    self, BLOCK_SIZE, CODE_BAD_OP, CODE_FENCED, CODE_INTEGRITY, CODE_IO_ERROR, CODE_LOCKED, CODE_NOT_ALLOWED, CODE_OK, CODE_OUT_OF_RANGE,
    OP_EPOCH, OP_FLUSH, OP_INFO, OP_READ, OP_UNLOCK, OP_WRITE, split,
};
use vanir_user::keys::OP_MASTER_KEY;
use vanir_user::telemetry::{self, INTEGRITY_ERROR, Record, STORAGE_LOCKED, STORAGE_UNLOCKED, VOLUME_CREATED};
use vanir_user::{err, lookup, println, recv, reply, send, sleep, task_index, task_listen, task_name, uptime};

vanir_user::entry!(main);

const MAGIC: &[u8; 8] = b"VNRSTOR3";
/// What every format's magic starts with, to tell an older format from a blank disk.
const MAGIC_FAMILY: &[u8; 7] = b"VNRSTOR";
const SUPERBLOCK: u64 = 0;
const TABLE: u64 = 1;
const FIRST_DATA: u64 = 2;
/// A fixed task's volume: 1 MiB of data.
const TASK_BLOCKS: u64 = 256;
/// Per data block: write counter (8 bytes) and tag (16 bytes).
const META_ENTRY: usize = 24;
const META_PER_BLOCK: u64 = (BLOCK_SIZE / META_ENTRY) as u64;
/// The block number the header is sealed under (no data block has it).
const HEADER: u64 = u64::MAX;
const HEADER_MAGIC: &[u8; 8] = b"VNRVOL01";
/// The header's sealed fields: magic, kind, name, size, epoch, lease (after counter and tag).
const HEADER_FIELDS: usize = 72;
/// Volume kinds, in the table and the header.
const KIND_TASK: u8 = 1;
const KIND_SERVICE: u8 = 2;
/// Tasks that may hand over the master key.
const UNLOCKERS: [&[u8]; 2] = [b"keys", b"attest"];
const MAX_VOLUMES: usize = BLOCK_SIZE / ENTRY;
/// Volume table entry: name (32 bytes, zero padded), start block, size in data blocks, kind.
const ENTRY: usize = 64;

#[derive(Clone, Copy)]
struct Volume {
    name: [u8; 32],
    kind: u8,
    start: u64,
    /// Data blocks.
    blocks: u64,
    /// The header has been checked since the last unlock.
    checked: bool,
    /// Writer epoch and lease from the header (RFD 3, P1). The lease is recorded, not enforced.
    epoch: u64,
    lease_until: u64,
    /// The writer's slot (task index), once the agent has named it since this task started.
    writer: Option<u64>,
    /// Slots (bit index - 1) already reported for a fenced write at this epoch.
    fenced_seen: u64,
}

/// Metadata blocks for `blocks` data blocks.
fn meta_blocks(blocks: u64) -> u64 {
    blocks.div_ceil(META_PER_BLOCK)
}

impl Volume {
    /// Blocks the volume takes on the disk: header, metadata and data.
    fn footprint(&self) -> u64 {
        1 + meta_blocks(self.blocks) + self.blocks
    }

    fn data_start(&self) -> u64 {
        self.start + 1 + meta_blocks(self.blocks)
    }
}

struct Storage {
    driver: u64,
    master: Option<[u8; 32]>,
    capacity: u64,
    next_free: u64,
    volumes: [Option<Volume>; MAX_VOLUMES],
    /// The telemetry task, while we may send to it.
    telemetry: Option<u64>,
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
    /// Report a storage event (best effort: telemetry may be absent, gone or not ours to use).
    fn event(&mut self, kind: u64, block: u64, name: &[u8]) {
        let Some(t) = self.telemetry else { return };
        if let Err(e) = telemetry::storage(t, kind, block, name) {
            if e == err::NOT_ALLOWED || e == err::DEAD {
                self.telemetry = None;
            }
        }
    }

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
            if &buf[..7] == MAGIC_FAMILY {
                println!("storage: the disk has an older format ({}); formatting", core::str::from_utf8(&buf[..8]).unwrap_or("?"));
            } else {
                println!("storage: no volume table on the disk; formatting");
            }
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
                    kind: e[48],
                    checked: false,
                    epoch: 0,
                    lease_until: 0,
                    writer: None,
                    fenced_seen: 0,
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
                e[48] = v.kind;
            }
        }
        self.write(TABLE, &buf)?;
        let mut sb = [0u8; BLOCK_SIZE];
        sb[..8].copy_from_slice(MAGIC);
        sb[8..16].copy_from_slice(&self.next_free.to_le_bytes());
        self.write(SUPERBLOCK, &sb)?;
        self.flush()
    }

    /// The index of the volume of kind `kind` called `name`, created with `blocks` data blocks on
    /// first use.
    fn volume(&mut self, kind: u8, name: &[u8], blocks: u64) -> Result<usize, u64> {
        let mut key = [0u8; 32];
        key[..name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
        if let Some(i) = self.volumes.iter().position(|v| v.is_some_and(|v| v.kind == kind && v.name == key)) {
            let had = self.volumes[i].unwrap().blocks;
            if had != blocks {
                println!(
                    "storage: {}: the volume has {} blocks, the instance's descriptor declares {}",
                    core::str::from_utf8(name).unwrap_or("?"),
                    had,
                    blocks
                );
                return Err(CODE_OUT_OF_RANGE);
            }
            return Ok(i);
        }
        let Some(slot) = self.volumes.iter().position(Option::is_none) else { return Err(CODE_OUT_OF_RANGE) };
        let mut v = Volume {
            name: key,
            kind,
            start: self.next_free,
            blocks,
            checked: true,
            epoch: 0,
            lease_until: 0,
            writer: None,
            fenced_seen: 0,
        };
        if self.next_free + v.footprint() > self.capacity {
            return Err(CODE_OUT_OF_RANGE);
        }
        // Fresh metadata (every block unwritten: counter 0), then the header, then the table.
        let zero = [0u8; BLOCK_SIZE];
        for m in 0..meta_blocks(blocks) {
            self.write(v.start + 1 + m, &zero)?;
        }
        self.write(v.start, &zero)?;
        self.write_header(&mut v)?;
        self.volumes[slot] = Some(v);
        self.next_free += v.footprint();
        self.save()?;
        self.event(VOLUME_CREATED, v.start, name);
        println!(
            "storage: new volume for {}: blocks {}..{}",
            core::str::from_utf8(name).unwrap_or("?"),
            v.start,
            v.start + v.footprint()
        );
        Ok(slot)
    }

    /// Check volume `i`'s header against the table, once after each unlock, and load its epoch.
    fn check_header(&mut self, i: usize) -> Result<(), u64> {
        let mut v = self.volumes[i].unwrap();
        if v.checked {
            return Ok(());
        }
        let mut buf = [0u8; BLOCK_SIZE];
        self.read(v.start, &mut buf)?;
        let counter = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let tag = Tag::try_from(&buf[8..24]).unwrap();
        let (nonce, aad) = Self::binding(&v, HEADER, counter);
        let fields = &mut buf[24..24 + HEADER_FIELDS];
        let opened = self.cipher(&v).decrypt_inout_detached(&nonce, &aad, fields.into(), &tag).is_ok();
        if !opened
            || &fields[..8] != HEADER_MAGIC
            || fields[8] != v.kind
            || fields[16..48] != v.name
            || u64::from_le_bytes(fields[48..56].try_into().unwrap()) != v.blocks
        {
            println!("storage: {}: the volume header does not open or does not match", core::str::from_utf8(name_of(&v)).unwrap_or("?"));
            self.event(INTEGRITY_ERROR, HEADER, name_of(&v));
            return Err(CODE_INTEGRITY);
        }
        v.epoch = u64::from_le_bytes(fields[56..64].try_into().unwrap());
        v.lease_until = u64::from_le_bytes(fields[64..72].try_into().unwrap());
        v.checked = true;
        self.volumes[i] = Some(v);
        Ok(())
    }

    /// OP_EPOCH (RFD 3, P1): make `writer` the writer of its service's volume at `epoch`.
    fn assign_epoch(&mut self, epoch: u64, lease_until: u64, writer: u64) -> Result<(), u64> {
        let info = task_listen(writer).map_err(|_| CODE_BAD_OP)?;
        if !info.is_slot() || info.volume_blocks == 0 {
            return Err(CODE_BAD_OP);
        }
        let i = self.volume(KIND_SERVICE, info.service(), info.volume_blocks)?;
        self.check_header(i)?;
        let mut v = self.volumes[i].unwrap();
        let slot = task_index(writer);
        let service = core::str::from_utf8(info.service()).unwrap_or("?");
        if epoch > v.epoch {
            let started = uptime();
            v.epoch = epoch;
            v.lease_until = lease_until;
            v.writer = Some(slot);
            v.fenced_seen = 0;
            self.write_header(&mut v)?;
            self.flush()?;
            self.volumes[i] = Some(v);
            println!("storage: {}: epoch {}, writer task {} (recorded in {} ticks)", service, epoch, slot, uptime() - started);
        } else if epoch == v.epoch && epoch != 0 && v.writer.is_none_or(|w| w == slot) {
            v.writer = Some(slot);
            self.volumes[i] = Some(v);
            println!("storage: {}: epoch {} again, writer task {}", service, epoch, slot);
        } else {
            println!("storage: {}: epoch {} refused (recorded: {})", service, epoch, v.epoch);
            return Err(CODE_FENCED);
        }
        if let Some(t) = self.telemetry {
            let mut r = Record::new("epoch_changed");
            r.text("volume", service).num("epoch", epoch).num("writer", slot);
            let _ = telemetry::event(t, &r);
        }
        Ok(())
    }

    /// Whether slot `slot` may write volume `i` (a service volume's writer; anyone for a task's).
    /// Reports the first refusal per slot and epoch.
    fn may_write(&mut self, i: usize, slot: u64) -> bool {
        let mut v = self.volumes[i].unwrap();
        if v.kind == KIND_TASK || v.writer == Some(slot) {
            return true;
        }
        let bit = 1u64 << ((slot - 1) % 64);
        if v.fenced_seen & bit == 0 {
            v.fenced_seen |= bit;
            self.volumes[i] = Some(v);
            if let Some(t) = self.telemetry {
                let mut r = Record::new("write_fenced");
                r.text("volume", core::str::from_utf8(name_of(&v)).unwrap_or("?")).num("slot", slot).num("epoch", v.epoch);
                let _ = telemetry::event(t, &r);
            }
        }
        false
    }

    /// Seal `v`'s header with the next counter and write it (not flushed).
    fn write_header(&mut self, v: &mut Volume) -> Result<(), u64> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.read(v.start, &mut buf)?;
        let counter = u64::from_le_bytes(buf[..8].try_into().unwrap()) + 1;
        let mut fields = [0u8; HEADER_FIELDS];
        fields[..8].copy_from_slice(HEADER_MAGIC);
        fields[8] = v.kind;
        fields[16..48].copy_from_slice(&v.name);
        fields[48..56].copy_from_slice(&v.blocks.to_le_bytes());
        fields[56..64].copy_from_slice(&v.epoch.to_le_bytes());
        fields[64..72].copy_from_slice(&v.lease_until.to_le_bytes());
        let (nonce, aad) = Self::binding(v, HEADER, counter);
        let tag = self.cipher(v).encrypt_inout_detached(&nonce, &aad, fields.as_mut_slice().into()).map_err(|_| CODE_IO_ERROR)?;
        let mut out = [0u8; BLOCK_SIZE];
        out[..8].copy_from_slice(&counter.to_le_bytes());
        out[8..24].copy_from_slice(&tag);
        out[24..24 + HEADER_FIELDS].copy_from_slice(&fields);
        self.write(v.start, &out)
    }
}

impl Storage {
    fn cipher(&self, v: &Volume) -> XChaCha20Poly1305 {
        let mut key = [0u8; 32];
        let salt: &[u8] = if v.kind == KIND_TASK { b"vanir-storage-v1" } else { b"vanir-service-v1" };
        Hkdf::<Sha256>::new(Some(salt), self.master.as_ref().unwrap())
            .expand(&v.name, &mut key)
            .expect("32 bytes is a valid HKDF output length");
        XChaCha20Poly1305::new(&key.into())
    }

    /// Where data block `b` of `v` keeps its counter and tag: (metadata block, byte offset).
    fn meta(v: &Volume, b: u64) -> (u64, usize) {
        (v.start + 1 + b / META_PER_BLOCK, (b % META_PER_BLOCK) as usize * META_ENTRY)
    }

    /// Nonce and associated data for data block `b` of `v` at write `counter`.
    fn binding(v: &Volume, b: u64, counter: u64) -> (XNonce, [u8; 48]) {
        let mut nonce = [0u8; 24];
        nonce[..8].copy_from_slice(&b.to_le_bytes());
        nonce[8..16].copy_from_slice(&counter.to_le_bytes());
        let mut aad = [0u8; 48];
        aad[..32].copy_from_slice(&v.name);
        aad[32..40].copy_from_slice(&b.to_le_bytes());
        aad[40..48].copy_from_slice(&counter.to_le_bytes());
        (nonce.into(), aad)
    }

    fn read_data(&mut self, v: &Volume, b: u64, out: &mut [u8; BLOCK_SIZE]) -> Result<(), u64> {
        let (mb, at) = Self::meta(v, b);
        let mut meta = [0u8; BLOCK_SIZE];
        self.read(mb, &mut meta)?;
        let counter = u64::from_le_bytes(meta[at..at + 8].try_into().unwrap());
        if counter == 0 {
            *out = [0; BLOCK_SIZE]; // never written
            return Ok(());
        }
        let tag = Tag::try_from(&meta[at + 8..at + 24]).unwrap();
        self.read(v.data_start() + b, out)?;
        let (nonce, aad) = Self::binding(v, b, counter);
        if self.cipher(v).decrypt_inout_detached(&nonce, &aad, out.as_mut_slice().into(), &tag).is_err() {
            self.event(INTEGRITY_ERROR, b, name_of(v));
            return Err(CODE_INTEGRITY);
        }
        Ok(())
    }

    fn write_data(&mut self, v: &Volume, b: u64, data: &mut [u8; BLOCK_SIZE]) -> Result<(), u64> {
        let (mb, at) = Self::meta(v, b);
        let mut meta = [0u8; BLOCK_SIZE];
        self.read(mb, &mut meta)?;
        let counter = u64::from_le_bytes(meta[at..at + 8].try_into().unwrap()) + 1;
        let (nonce, aad) = Self::binding(v, b, counter);
        let tag = self.cipher(v).encrypt_inout_detached(&nonce, &aad, data.as_mut_slice().into()).map_err(|_| CODE_IO_ERROR)?;
        self.write(v.data_start() + b, data)?;
        meta[at..at + 8].copy_from_slice(&counter.to_le_bytes());
        meta[at + 8..at + 24].copy_from_slice(&tag);
        self.write(mb, &meta)
    }
}

/// A volume's name without its zero padding.
fn name_of(v: &Volume) -> &[u8] {
    &v.name[..v.name.iter().position(|&c| c == 0).unwrap_or(32)]
}

/// Ask the key server for the master key, if there is one we may ask.
fn fetch_key() -> Option<[u8; 32]> {
    let keys = lookup("keys").ok()?;
    let mut key = [0u8; 32];
    match send(keys, OP_MASTER_KEY, &[], &mut key) {
        Ok((CODE_OK, 32)) => Some(key),
        _ => None,
    }
}

fn main() -> u64 {
    let driver = lookup("blockdev").expect("no blockdev task");
    let mut s = Storage {
        driver,
        master: None,
        capacity: 0,
        next_free: FIRST_DATA,
        volumes: [None; MAX_VOLUMES],
        telemetry: lookup("telemetry").ok(),
    };
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
    s.event(STORAGE_LOCKED, 0, b"");
    if let Some(key) = fetch_key() {
        s.master = Some(key);
        println!("storage: unlocked by keys");
        s.event(STORAGE_UNLOCKED, 0, b"keys");
    }
    #[cfg(feature = "crash-after-16")]
    let mut writes = 0u32;

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
        let (op, b) = split(m.op);
        #[cfg(feature = "crash-after-16")]
        if op == block::OP_WRITE {
            writes += 1;
            if writes == 16 && vanir_user::getpid() >> 16 == 0 {
                println!("storage: crashing after 15 writes");
                unsafe { core::ptr::read_volatile(0x10 as *const u8) };
            }
        }
        if op == OP_UNLOCK {
            let code = if !UNLOCKERS.contains(&name) {
                CODE_NOT_ALLOWED
            } else if m.len != 32 {
                CODE_BAD_OP
            } else {
                s.master = Some(msg[..32].try_into().unwrap());
                // A new key: every header has to open under it again.
                s.volumes.iter_mut().flatten().for_each(|v| v.checked = false);
                println!("storage: unlocked by {}", core::str::from_utf8(name).unwrap_or("?"));
                s.event(STORAGE_UNLOCKED, 0, name);
                CODE_OK
            };
            let _ = reply(m.sender, code, &[]);
            continue;
        }
        if s.master.is_none() {
            let _ = reply(m.sender, CODE_LOCKED, &[]);
            continue;
        }
        let code_of = |e: u64| if err::is_error(e) { CODE_IO_ERROR } else { e };
        if op == OP_EPOCH {
            let code = if !task_listen(m.sender).is_ok_and(|i| i.may_load()) {
                CODE_NOT_ALLOWED
            } else if m.len != 24 {
                CODE_BAD_OP
            } else {
                let at = |k: usize| u64::from_le_bytes(msg[k..k + 8].try_into().unwrap());
                match s.assign_epoch(at(0), at(8), at(16)) {
                    Ok(()) => CODE_OK,
                    Err(e) => code_of(e),
                }
            };
            let _ = reply(m.sender, code, &[]);
            continue;
        }
        // A slot's instance reaches its service's volume (RFD 3), anything else its task's.
        let info = task_listen(m.sender).ok().filter(|i| i.is_slot());
        let found = match &info {
            Some(i) if i.volume_blocks == 0 => Err(CODE_NOT_ALLOWED),
            Some(i) => s.volume(KIND_SERVICE, i.service(), i.volume_blocks),
            None => s.volume(KIND_TASK, name, TASK_BLOCKS),
        };
        let i = match found {
            Ok(i) => i,
            Err(code) => {
                let _ = reply(m.sender, code_of(code), &[]);
                continue;
            }
        };
        if matches!(op, OP_READ | OP_WRITE)
            && let Err(e) = s.check_header(i)
        {
            let _ = reply(m.sender, code_of(e), &[]);
            continue;
        }
        if matches!(op, OP_WRITE | OP_FLUSH) && !s.may_write(i, task_index(m.sender)) {
            let _ = reply(m.sender, CODE_FENCED, &[]);
            continue;
        }
        let v = s.volumes[i].unwrap();
        let result = match op {
            OP_INFO => {
                let _ = reply(m.sender, CODE_OK, &v.blocks.to_le_bytes());
                continue;
            }
            OP_FLUSH => s.flush(),
            OP_READ | OP_WRITE if b >= v.blocks => Err(CODE_OUT_OF_RANGE),
            OP_READ => match s.read_data(&v, b, &mut msg) {
                Ok(()) => {
                    let _ = reply(m.sender, CODE_OK, &msg);
                    continue;
                }
                Err(e) => Err(e),
            },
            OP_WRITE if m.len == BLOCK_SIZE => s.write_data(&v, b, &mut msg),
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
