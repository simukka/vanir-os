//! The storage task: the only client of the block driver. Each task that talks to it gets its
//! own volume, a fixed range of the disk, found by the task's manifest name (which the kernel
//! vouches for: it comes from `task_name` of the sender's id, not from the client). Clients use
//! the `vanir_user::block` interface with block numbers relative to their volume, and can't
//! address anything outside it.
//!
//! Every block is encrypted at rest with XChaCha20-Poly1305 under its volume's key,
//! HKDF-SHA256(master key, volume name) for a fixed task's volume, and HKDF-SHA256(service key,
//! service name) for a service's (RFD 3, P2). The nonce is the block number and a per-block write
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
//! **Handoff (RFD 3, P3).** Just before the agent routes to a new instance of a service whose old
//! instance still writes, it names the new one the candidate (OP_HANDOFF). From then on the
//! candidate's reads, writes and flushes are held, not answered, until OP_EPOCH makes it the
//! writer; then it gets the writer bit (`block::NOTIFY_WRITER`, posted to every new writer) and
//! the held requests are served in order. Called off (OP_HANDOFF for no candidate or another),
//! they are served at once, as if they had just arrived. A client blocked in a call has one
//! request outstanding, so there is at most one held request per slot.
//!
//! **Moving a volume (RFD 3, P4–P5).** The agent moves a service's volume to another node
//! block by block, as the blocks are on disk: the source exports ciphertext, counters and tags
//! (`OP_EXPORT*`), and the target imports them (`OP_IMPORT*`), checking each block opens with
//! the service key before storing it. While the source mirrors (`OP_MIRROR`), each write by the
//! writer is held after it is made, until the agent says the target has it too. A dropped volume
//! (`OP_DROP`) is wiped and its space reused by the next volume of the same size. At the handoff
//! the source's volume is handed over (`OP_HAND_OVER`: read-only until a higher epoch) and both
//! sides compare digests (`OP_DIGEST`).
//!
//! Keys are only ever in memory. The task starts locked, answering CODE_LOCKED: it asks the key
//! server ("keys") for the master key if it may send to one, and otherwise waits for OP_UNLOCK
//! (from "attest", after the host released the key). A restarted storage task starts locked
//! again, and has to get the key again.
//!
//! **Service keys (RFD 3, P2).** Each service's volume has its own key, which the control plane
//! keeps and releases only to an attested node that runs the service: it reaches us from
//! "attest" (OP_SERVICE_KEY), or from "keys", which we ask when we need one. A service volume
//! needs only its service's key, and answers CODE_LOCKED without it; task volumes need only the
//! master key. The agent has us forget a service's key (OP_FORGET_KEY) once no instance of the
//! service is left on the node.
//!
//! Storage events go to the telemetry task if it may send to one: volume_created,
//! storage_locked, storage_unlocked and integrity_error (with the volume and block). So do counters of the blocks read and written and the flushes, once
//! per snapshot interval while requests come.
//!
//! On disk (4 KiB blocks): block 0 superblock, block 1 the volume table (both in plain text),
//! then volumes: a header block, then `meta_blocks(size)` metadata blocks, then the data blocks.
//! A disk in an older format is reformatted.

#![no_std]
#![no_main]

use chacha20poly1305::{AeadInOut, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use vanir_user::block::{
    self, BLOCK_SIZE, CODE_BAD_OP, CODE_FENCED, CODE_INTEGRITY, CODE_IO_ERROR, CODE_LOCKED, CODE_NOT_ALLOWED, CODE_OK, CODE_OUT_OF_RANGE,
    NOTIFY_WRITER, OP_DROP, OP_EPOCH, OP_EXPORT, OP_EXPORT_ENTRY, OP_EXPORT_HEADER, OP_EXPORT_META, OP_FLUSH, OP_FORGET_KEY, OP_HANDOFF,
    OP_DIGEST, OP_HAND_OVER, OP_IMPORT, OP_IMPORT_ENTRY, OP_IMPORT_HEADER, OP_INFO, OP_MIRROR, OP_MIRROR_ACK, OP_MIRROR_PENDING,
    OP_READ, OP_SERVICE_KEY, OP_UNLOCK, OP_WRITE, split,
};
use vanir_user::keys::{self, OP_MASTER_KEY};
use vanir_user::telemetry::{self, INTEGRITY_ERROR, Record, STORAGE_LOCKED, STORAGE_UNLOCKED, VOLUME_CREATED};
use vanir_user::{err, lookup, notify, println, recv, reply, send, sleep, task_index, task_listen, task_name, uptime};

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
/// A freed volume's space, kept for the next volume of the same size.
const KIND_FREE: u8 = 3;
/// A header's meaningful bytes: counter, tag and sealed fields.
const HEADER_BYTES: usize = 24 + HEADER_FIELDS;
/// Tasks that may hand over the master key.
const UNLOCKERS: [&[u8]; 2] = [b"keys", b"attest"];
const MAX_VOLUMES: usize = BLOCK_SIZE / ENTRY;
/// Volume table entry: name (32 bytes, zero padded), start block, size in data blocks, kind.
const ENTRY: usize = 64;
/// Requests held during handoffs (RFD 3, P3): one per slot is enough.
const MAX_HELD: usize = 8;

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
    /// The handoff's candidate (task id), whose requests are held until it is the writer.
    candidate: Option<u64>,
    /// Mirroring to another node (RFD 3, P4): the writer's last write, made and not yet
    /// answered (its id and block), until the agent says the target has it.
    mirror: bool,
    mirror_pending: Option<(u64, u64)>,
    /// Handed over to another node in a move: read-only until a higher epoch.
    handed_over: bool,
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

/// A request held during a handoff (RFD 3, P3); its data is in `HELD_DATA` at the same index.
#[derive(Clone, Copy)]
struct Held {
    volume: usize,
    sender: u64,
    op: u64,
    len: usize,
    since: u64,
    seq: u64,
}

/// The held requests' data, 4 KiB each: too much for the stack.
static mut HELD_DATA: [[u8; BLOCK_SIZE]; MAX_HELD] = [[0; BLOCK_SIZE]; MAX_HELD];

/// A service's key (RFD 3, P2), by service name (zero padded).
#[derive(Clone, Copy)]
struct ServiceKey {
    service: [u8; 32],
    key: [u8; 32],
}

struct Storage {
    driver: u64,
    master: Option<[u8; 32]>,
    /// The keys of the services whose volumes we may open now.
    service_keys: [Option<ServiceKey>; MAX_VOLUMES],
    capacity: u64,
    next_free: u64,
    volumes: [Option<Volume>; MAX_VOLUMES],
    /// The telemetry task, while we may send to it.
    telemetry: Option<u64>,
    /// Requests held during handoffs, and the next arrival number.
    held: [Option<Held>; MAX_HELD],
    held_seq: u64,
    /// A volume whose held requests are served once the current request has been answered.
    release: Option<usize>,
    /// The last block exported (volume, block, counter, tag), for `OP_EXPORT_ENTRY`, and the
    /// entry `OP_IMPORT` brings next (RFD 3, P5).
    exported: Option<(usize, u64, u64, [u8; 16])>,
    importing: Option<(usize, u64, u64, [u8; 16])>,
    /// Blocks read and written and flushes sent to the driver, reported to telemetry every
    /// snapshot interval (on the next request after it ends).
    io: [u64; 3],
    next_snapshot: u64,
    interval: u64,
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

    /// Send our I/O counters to telemetry if the interval has ended.
    fn snapshot(&mut self) {
        let now = uptime();
        if now < self.next_snapshot {
            return;
        }
        self.next_snapshot = now + self.interval;
        let Some(t) = self.telemetry else { return };
        let mut r = Record::new("storage");
        r.num("t", now).num("blocks_read", self.io[0]).num("blocks_written", self.io[1]).num("flushes", self.io[2]);
        match telemetry::counters(t, &r) {
            Ok(interval) => self.interval = interval,
            Err(e) if e == err::NOT_ALLOWED || e == err::DEAD => self.telemetry = None,
            Err(_) => {}
        }
    }

    fn read(&mut self, b: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), u64> {
        self.io[0] += 1;
        on_driver(&mut self.driver, |d| block::read(d, b, buf))
    }

    fn write(&mut self, b: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), u64> {
        self.io[1] += 1;
        on_driver(&mut self.driver, |d| block::write(d, b, buf))
    }

    fn flush(&mut self) -> Result<(), u64> {
        self.io[2] += 1;
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
                    candidate: None,
                    mirror: false,
                    mirror_pending: None,
                    handed_over: false,
                });
            }
        }
        let count = self.volumes.iter().flatten().filter(|v| v.kind != KIND_FREE).count();
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
        // A freed volume of the same size first, then new space.
        let free = self.volumes.iter().position(|v| v.is_some_and(|v| v.kind == KIND_FREE && v.blocks == blocks));
        let Some(slot) = free.or_else(|| self.volumes.iter().position(Option::is_none)) else { return Err(CODE_OUT_OF_RANGE) };
        let start = free.map_or(self.next_free, |i| self.volumes[i].unwrap().start);
        let mut v = Volume {
            name: key,
            kind,
            start,
            blocks,
            checked: true,
            epoch: 0,
            lease_until: 0,
            writer: None,
            fenced_seen: 0,
            candidate: None,
            mirror: false,
            mirror_pending: None,
            handed_over: false,
        };
        if free.is_none() && self.next_free + v.footprint() > self.capacity {
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
        if free.is_none() {
            self.next_free += v.footprint();
        }
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

    /// The key of service `name`, asking "keys" for it if we don't have it.
    fn service_key(&mut self, name: &[u8; 32]) -> Option<[u8; 32]> {
        if let Some(k) = self.service_keys.iter().flatten().find(|k| k.service == *name) {
            return Some(k.key);
        }
        let key = fetch_service_key(name)?;
        self.set_service_key(name, &key, "keys");
        Some(key)
    }

    /// Whether we have the key for volumes of kind `kind` called `name` (CODE_LOCKED if not).
    fn has_key(&mut self, kind: u8, name: &[u8]) -> Result<(), u64> {
        let have = match kind {
            KIND_TASK => self.master.is_some(),
            _ => self.service_key(&block::service_name(name)).is_some(),
        };
        if have { Ok(()) } else { Err(CODE_LOCKED) }
    }

    /// OP_SERVICE_KEY: keep `key` for service `name`. A changed key has the volume's header
    /// checked again.
    fn set_service_key(&mut self, name: &[u8; 32], key: &[u8; 32], from: &str) -> u64 {
        let held = self.service_keys.iter().position(|k| k.is_some_and(|k| k.service == *name));
        if held.is_some_and(|i| self.service_keys[i].unwrap().key == *key) {
            return CODE_OK;
        }
        let Some(i) = held.or_else(|| self.service_keys.iter().position(Option::is_none)) else { return CODE_OUT_OF_RANGE };
        self.service_keys[i] = Some(ServiceKey { service: *name, key: *key });
        self.uncheck(name);
        println!("storage: {}: key from {}", core::str::from_utf8(trim(name)).unwrap_or("?"), from);
        CODE_OK
    }

    /// OP_FORGET_KEY: drop service `name`'s key.
    fn forget_service_key(&mut self, name: &[u8; 32]) {
        let mut had = false;
        for k in self.service_keys.iter_mut() {
            if k.is_some_and(|k| k.service == *name) {
                *k = None;
                had = true;
            }
        }
        self.uncheck(name);
        let name = core::str::from_utf8(trim(name)).unwrap_or("?");
        println!("storage: {}: key forgotten{}", name, if had { "" } else { " (had none)" });
    }

    /// Have service `name`'s volume header checked again before its next use.
    fn uncheck(&mut self, name: &[u8; 32]) {
        for v in self.volumes.iter_mut().flatten() {
            if v.kind == KIND_SERVICE && v.name == *name {
                v.checked = false;
            }
        }
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
        self.has_key(KIND_SERVICE, info.service())?;
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
            v.handed_over = false;
            self.write_header(&mut v)?;
            self.flush()?;
            self.volumes[i] = Some(v);
            println!("storage: {}: epoch {}, writer task {} (recorded in {} ticks)", service, epoch, slot, uptime() - started);
            // Tell the new writer, before any request it has waiting is answered.
            let _ = notify(writer, NOTIFY_WRITER);
        } else if epoch == v.epoch && epoch != 0 && v.writer.is_none_or(|w| w == slot) && !v.handed_over {
            v.writer = Some(slot);
            self.volumes[i] = Some(v);
            println!("storage: {}: epoch {} again, writer task {}", service, epoch, slot);
        } else {
            println!("storage: {}: epoch {} refused (recorded: {})", service, epoch, v.epoch);
            return Err(CODE_FENCED);
        }
        if self.volumes[i].unwrap().candidate.is_some_and(|c| task_index(c) == slot) {
            self.release = Some(i);
        }
        if let Some(t) = self.telemetry {
            let mut r = Record::new("epoch_changed");
            r.text("volume", service).num("epoch", epoch).num("writer", slot);
            let _ = telemetry::event(t, &r);
        }
        Ok(())
    }

    /// OP_HANDOFF (RFD 3, P3): hold `candidate`'s requests to `service`'s volume until it is the
    /// writer; 0 calls the handoff off.
    fn handoff(&mut self, service: &[u8; 32], candidate: u64) -> Result<(), u64> {
        let i = if candidate == 0 {
            let found = self.volumes.iter().position(|v| v.is_some_and(|v| v.kind == KIND_SERVICE && v.name == *service));
            found.ok_or(CODE_BAD_OP)?
        } else {
            let info = task_listen(candidate).map_err(|_| CODE_BAD_OP)?;
            if !info.is_slot() || info.volume_blocks == 0 || block::service_name(info.service()) != *service {
                return Err(CODE_BAD_OP);
            }
            self.has_key(KIND_SERVICE, info.service())?;
            self.volume(KIND_SERVICE, info.service(), info.volume_blocks)?
        };
        let v = self.volumes[i].unwrap();
        if v.candidate == Some(candidate) || (candidate == 0 && v.candidate.is_none()) {
            return Ok(());
        }
        if v.candidate.is_some() {
            self.release_held(i); // called off: serve what was held as it is
        }
        self.volumes[i].as_mut().unwrap().candidate = (candidate != 0).then_some(candidate);
        if candidate != 0 {
            let mut buf = [0u8; 64];
            let who = task_name(candidate, &mut buf).unwrap_or("?");
            println!("storage: {}: holding {}'s requests (handoff)", core::str::from_utf8(trim(service)).unwrap_or("?"), who);
        }
        Ok(())
    }

    /// Keep a request from volume `i`'s candidate until it is the writer.
    fn hold(&mut self, i: usize, sender: u64, op: u64, len: usize, msg: &[u8; BLOCK_SIZE]) {
        let Some(k) = self.held.iter().position(Option::is_none) else {
            let _ = reply(sender, block::CODE_BUSY, &[]); // the client tries again
            return;
        };
        let data = unsafe { &mut *(&raw mut HELD_DATA) }; // only this task, one request at a time
        data[k][..len].copy_from_slice(&msg[..len]);
        self.held[k] = Some(Held { volume: i, sender, op, len, since: uptime(), seq: self.held_seq });
        self.held_seq += 1;
    }

    /// Serve volume `i`'s held requests in the order they came: to the new writer, or as they
    /// are if the handoff was called off.
    fn release_held(&mut self, i: usize) {
        let mut v = self.volumes[i].unwrap();
        let candidate = v.candidate.take().unwrap_or(0);
        self.volumes[i] = Some(v);
        let writer = v.writer.is_some_and(|w| candidate != 0 && task_index(candidate) == w);
        let (mut n, mut longest, now) = (0u64, 0u64, uptime());
        let mut buf = [0u8; BLOCK_SIZE];
        while let Some(k) = (0..MAX_HELD).filter(|&k| self.held[k].is_some_and(|h| h.volume == i)).min_by_key(|&k| self.held[k].unwrap().seq) {
            let h = self.held[k].take().unwrap();
            let data = unsafe { &*(&raw const HELD_DATA) };
            buf[..h.len].copy_from_slice(&data[k][..h.len]);
            n += 1;
            longest = longest.max(now - h.since);
            self.serve(h.sender, h.op, h.len, &mut buf);
        }
        let service = core::str::from_utf8(name_of(&v)).unwrap_or("?");
        let mut name = [0u8; 64];
        let who = task_name(candidate, &mut name).unwrap_or("?");
        if writer {
            println!("storage: {}: released {} held request(s) to {} (longest wait {} ticks)", service, n, who, longest);
        } else {
            println!("storage: {}: handoff to {} called off; {} held request(s) answered", service, who, n);
        }
        if let Some(t) = self.telemetry {
            let mut r = Record::new("handoff");
            r.text("volume", service).num("held", n).num("longest_wait", longest).num("called_off", !writer as u64);
            let _ = telemetry::event(t, &r);
        }
    }

    /// A service's volume, if there is one (not made on demand).
    fn service_volume(&self, name: &[u8; 32]) -> Result<usize, u64> {
        self.volumes.iter().position(|v| v.is_some_and(|v| v.kind == KIND_SERVICE && v.name == *name)).ok_or(CODE_BAD_OP)
    }

    /// The transfer ops (RFD 3, P5): `msg` starts with the service name, and the reply goes back
    /// into it; returns the reply's length.
    fn transfer(&mut self, op: u64, b: u64, len: usize, msg: &mut [u8; BLOCK_SIZE]) -> Result<usize, u64> {
        if op == OP_IMPORT {
            return self.import(b, len, msg);
        }
        let name: [u8; 32] = msg[..32].try_into().unwrap();
        let shown = core::str::from_utf8(trim(&name)).unwrap_or("?");
        let at = |msg: &[u8; BLOCK_SIZE], k: usize| u64::from_le_bytes(msg[k..k + 8].try_into().unwrap());
        if op == OP_IMPORT_HEADER {
            if len != 40 + HEADER_BYTES {
                return Err(CODE_BAD_OP);
            }
            let blocks = at(msg, 32);
            self.has_key(KIND_SERVICE, trim(&name))?;
            let i = self.volume(KIND_SERVICE, trim(&name), blocks)?;
            let v = self.volumes[i].unwrap();
            if v.writer.is_some() || v.candidate.is_some() {
                println!("storage: {}: not receiving the volume: an instance here uses it", shown);
                return Err(CODE_NOT_ALLOWED);
            }
            // Every block unwritten, then the source's header, which must open here too.
            let zero = [0u8; BLOCK_SIZE];
            for m in 0..meta_blocks(blocks) {
                self.write(v.start + 1 + m, &zero)?;
            }
            let mut header = [0u8; BLOCK_SIZE];
            header[..HEADER_BYTES].copy_from_slice(&msg[40..40 + HEADER_BYTES]);
            self.write(v.start, &header)?;
            self.flush()?;
            self.volumes[i].as_mut().unwrap().checked = false;
            self.check_header(i)?;
            println!("storage: {}: receiving the volume ({} blocks, epoch {})", shown, blocks, self.volumes[i].unwrap().epoch);
            self.importing = None;
            return Ok(0);
        }
        let i = self.service_volume(&name)?;
        let v = self.volumes[i].unwrap();
        match op {
            OP_EXPORT => {
                if b >= v.blocks {
                    return Err(CODE_OUT_OF_RANGE);
                }
                let (mb, off) = Self::meta(&v, b);
                let mut meta = [0u8; BLOCK_SIZE];
                self.read(mb, &mut meta)?;
                let counter = u64::from_le_bytes(meta[off..off + 8].try_into().unwrap());
                let tag: [u8; 16] = meta[off + 8..off + 24].try_into().unwrap();
                self.read(v.data_start() + b, msg)?;
                self.exported = Some((i, b, counter, tag));
                Ok(BLOCK_SIZE)
            }
            OP_EXPORT_ENTRY => {
                let Some((vi, b, counter, tag)) = self.exported.filter(|e| e.0 == i) else { return Err(CODE_BAD_OP) };
                let _ = vi;
                msg[..8].copy_from_slice(&b.to_le_bytes());
                msg[8..16].copy_from_slice(&counter.to_le_bytes());
                msg[16..32].copy_from_slice(&tag);
                Ok(32)
            }
            OP_EXPORT_META => {
                if b >= meta_blocks(v.blocks) {
                    return Err(CODE_OUT_OF_RANGE);
                }
                self.read(v.start + 1 + b, msg)?;
                Ok(BLOCK_SIZE)
            }
            OP_EXPORT_HEADER => {
                let mut header = [0u8; BLOCK_SIZE];
                self.read(v.start, &mut header)?;
                msg[..8].copy_from_slice(&v.blocks.to_le_bytes());
                msg[8..8 + HEADER_BYTES].copy_from_slice(&header[..HEADER_BYTES]);
                Ok(8 + HEADER_BYTES)
            }
            OP_IMPORT_ENTRY => {
                if len != 64 {
                    return Err(CODE_BAD_OP);
                }
                self.importing = Some((i, at(msg, 32), at(msg, 40), msg[48..64].try_into().unwrap()));
                Ok(0)
            }
            OP_MIRROR => {
                let on = len >= 40 && at(msg, 32) != 0;
                let mut v = v;
                v.mirror = on;
                let held = if on { None } else { v.mirror_pending.take() };
                self.volumes[i] = Some(v);
                if let Some((writer, _)) = held {
                    let _ = reply(writer, CODE_OK, &[]);
                }
                println!("storage: {}: mirroring {}", shown, if on { "on" } else { "off" });
                Ok(0)
            }
            OP_MIRROR_PENDING => match v.mirror_pending {
                Some((_, b)) => {
                    msg[..8].copy_from_slice(&b.to_le_bytes());
                    Ok(8)
                }
                None => Ok(0),
            },
            OP_MIRROR_ACK => {
                if let Some((writer, _)) = self.volumes[i].as_mut().unwrap().mirror_pending.take() {
                    let _ = reply(writer, CODE_OK, &[]);
                }
                Ok(0)
            }
            OP_HAND_OVER => {
                let mut v = v;
                v.writer = None;
                v.handed_over = true;
                v.mirror = false;
                self.volumes[i] = Some(v);
                self.flush()?;
                println!("storage: {}: handed over at epoch {}; read-only", shown, v.epoch);
                Ok(0)
            }
            OP_DIGEST => {
                let mut buf = [0u8; BLOCK_SIZE];
                self.read(v.start, &mut buf)?;
                let mut h = Sha256::new().chain_update(&buf[..HEADER_BYTES]);
                for m in 0..meta_blocks(v.blocks) {
                    self.read(v.start + 1 + m, &mut buf)?;
                    h.update(&buf);
                }
                msg[..32].copy_from_slice(&h.finalize());
                Ok(32)
            }
            OP_DROP => {
                if v.writer.is_some() || v.candidate.is_some() || v.mirror {
                    println!("storage: {}: not dropping the volume: it is in use", shown);
                    return Err(CODE_NOT_ALLOWED);
                }
                let zero = [0u8; BLOCK_SIZE];
                for m in 0..=meta_blocks(v.blocks) {
                    self.write(v.start + m, &zero)?;
                }
                self.volumes[i] = Some(Volume { name: [0; 32], kind: KIND_FREE, checked: false, epoch: 0, ..v });
                self.save()?;
                println!("storage: {}: volume dropped (blocks {}..{} free)", shown, v.start, v.start + v.footprint());
                Ok(0)
            }
            _ => Err(CODE_BAD_OP),
        }
    }

    /// OP_IMPORT: block `b`'s ciphertext (all of `msg`), for the entry `OP_IMPORT_ENTRY` gave.
    fn import(&mut self, b: u64, len: usize, msg: &mut [u8; BLOCK_SIZE]) -> Result<usize, u64> {
        let Some((i, eb, counter, tag)) = self.importing.take() else { return Err(CODE_BAD_OP) };
        let v = self.volumes[i].unwrap();
        if len != BLOCK_SIZE || eb != b || b >= v.blocks || v.kind != KIND_SERVICE {
            return Err(CODE_BAD_OP);
        }
        let name = v.name;
        let shown = core::str::from_utf8(trim(&name)).unwrap_or("?");
        self.has_key(KIND_SERVICE, trim(&name))?;
        let (mb, off) = Self::meta(&v, b);
        let mut meta = [0u8; BLOCK_SIZE];
        self.read(mb, &mut meta)?;
        if counter <= u64::from_le_bytes(meta[off..off + 8].try_into().unwrap()) {
            return Ok(0); // what we have is as new or newer
        }
        // It must open here, under this volume's name and this block number.
        let mut check = *msg;
        let (nonce, aad) = Self::binding(&v, b, counter);
        let tag_ = Tag::try_from(&tag[..]).unwrap();
        if self.cipher(&v).decrypt_inout_detached(&nonce, &aad, check.as_mut_slice().into(), &tag_).is_err() {
            println!("storage: {}: block {} from the source does not open", shown, b);
            self.event(INTEGRITY_ERROR, b, trim(&name));
            return Err(CODE_INTEGRITY);
        }
        self.write(v.data_start() + b, msg)?;
        meta[off..off + 8].copy_from_slice(&counter.to_le_bytes());
        meta[off + 8..off + 24].copy_from_slice(&tag);
        self.write(mb, &meta)?;
        Ok(0)
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
        // The caller checked we have the key (`has_key`).
        let (salt, ikm): (&[u8], [u8; 32]) = match v.kind {
            KIND_TASK => (b"vanir-storage-v1", self.master.unwrap()),
            _ => (b"vanir-service-v2", self.service_keys.iter().flatten().find(|k| k.service == v.name).unwrap().key),
        };
        Hkdf::<Sha256>::new(Some(salt), &ikm)
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

impl Storage {
    /// Answer one request (or hold it, from a handoff's candidate).
    fn serve(&mut self, sender: u64, raw_op: u64, len: usize, msg: &mut [u8; BLOCK_SIZE]) {
        let mut name_buf = [0u8; 64];
        let Ok(name) = task_name(sender, &mut name_buf).map(|n| n.as_bytes()) else {
            let _ = reply(sender, CODE_BAD_OP, &[]);
            return;
        };
        let mut name_copy = [0u8; 64];
        name_copy[..name.len()].copy_from_slice(name);
        let name = &name_copy[..name.len()];
        let (op, b) = split(raw_op);
        if op == OP_UNLOCK {
            let code = if !UNLOCKERS.contains(&name) {
                CODE_NOT_ALLOWED
            } else if len != 32 {
                CODE_BAD_OP
            } else {
                self.master = Some(msg[..32].try_into().unwrap());
                // A new key: every task volume's header has to open under it again.
                self.volumes.iter_mut().flatten().filter(|v| v.kind == KIND_TASK).for_each(|v| v.checked = false);
                println!("storage: unlocked by {}", core::str::from_utf8(name).unwrap_or("?"));
                self.event(STORAGE_UNLOCKED, 0, name);
                CODE_OK
            };
            let _ = reply(sender, code, &[]);
            return;
        }
        if op == OP_SERVICE_KEY {
            let code = if !UNLOCKERS.contains(&name) {
                CODE_NOT_ALLOWED
            } else if len != 64 {
                CODE_BAD_OP
            } else {
                let from = core::str::from_utf8(name).unwrap_or("?");
                self.set_service_key(&msg[..32].try_into().unwrap(), &msg[32..64].try_into().unwrap(), from)
            };
            let _ = reply(sender, code, &[]);
            return;
        }
        if op == OP_FORGET_KEY {
            let code = if !task_listen(sender).is_ok_and(|i| i.may_load()) {
                CODE_NOT_ALLOWED
            } else if len != 32 {
                CODE_BAD_OP
            } else {
                self.forget_service_key(&msg[..32].try_into().unwrap());
                CODE_OK
            };
            let _ = reply(sender, code, &[]);
            return;
        }
        let code_of = |e: u64| if err::is_error(e) { CODE_IO_ERROR } else { e };
        if (OP_EXPORT..=OP_DROP).contains(&op) {
            let (code, n) = if !task_listen(sender).is_ok_and(|i| i.may_load()) {
                (CODE_NOT_ALLOWED, 0)
            } else if len < 32 {
                (CODE_BAD_OP, 0)
            } else {
                match self.transfer(op, b, len, msg) {
                    Ok(n) => (CODE_OK, n),
                    Err(e) => (code_of(e), 0),
                }
            };
            let _ = reply(sender, code, &msg[..n]);
            return;
        }
        if op == OP_HANDOFF {
            let code = if !task_listen(sender).is_ok_and(|i| i.may_load()) {
                CODE_NOT_ALLOWED
            } else if len != 40 {
                CODE_BAD_OP
            } else {
                let candidate = u64::from_le_bytes(msg[32..40].try_into().unwrap());
                match self.handoff(&msg[..32].try_into().unwrap(), candidate) {
                    Ok(()) => CODE_OK,
                    Err(e) => code_of(e),
                }
            };
            let _ = reply(sender, code, &[]);
            return;
        }
        if op == OP_EPOCH {
            let code = if !task_listen(sender).is_ok_and(|i| i.may_load()) {
                CODE_NOT_ALLOWED
            } else if len != 24 {
                CODE_BAD_OP
            } else {
                let at = |k: usize| u64::from_le_bytes(msg[k..k + 8].try_into().unwrap());
                match self.assign_epoch(at(0), at(8), at(16)) {
                    Ok(()) => CODE_OK,
                    Err(e) => code_of(e),
                }
            };
            let _ = reply(sender, code, &[]);
            return;
        }
        // A slot's instance reaches its service's volume (RFD 3), anything else its task'self.
        let info = task_listen(sender).ok().filter(|i| i.is_slot());
        let found = match &info {
            Some(i) if i.volume_blocks == 0 => Err(CODE_NOT_ALLOWED),
            Some(i) => self.has_key(KIND_SERVICE, i.service()).and_then(|()| self.volume(KIND_SERVICE, i.service(), i.volume_blocks)),
            None => self.has_key(KIND_TASK, name).and_then(|()| self.volume(KIND_TASK, name, TASK_BLOCKS)),
        };
        let i = match found {
            Ok(i) => i,
            Err(code) => {
                let _ = reply(sender, code_of(code), &[]);
                return;
            }
        };
        // The handoff's candidate waits until it is the writer (RFD 3, P3).
        if matches!(op, OP_READ | OP_WRITE | OP_FLUSH)
            && self.volumes[i].unwrap().candidate.is_some_and(|c| task_index(c) == task_index(sender))
        {
            self.hold(i, sender, raw_op, len, msg);
            return;
        }
        if matches!(op, OP_READ | OP_WRITE)
            && let Err(e) = self.check_header(i)
        {
            let _ = reply(sender, code_of(e), &[]);
            return;
        }
        if matches!(op, OP_WRITE | OP_FLUSH) && !self.may_write(i, task_index(sender)) {
            let _ = reply(sender, CODE_FENCED, &[]);
            return;
        }
        let v = self.volumes[i].unwrap();
        let result = match op {
            OP_INFO => {
                let _ = reply(sender, CODE_OK, &v.blocks.to_le_bytes());
                return;
            }
            OP_FLUSH => self.flush(),
            OP_READ | OP_WRITE if b >= v.blocks => Err(CODE_OUT_OF_RANGE),
            OP_READ => match self.read_data(&v, b, msg) {
                Ok(()) => {
                    let _ = reply(sender, CODE_OK, &msg[..]);
                    return;
                }
                Err(e) => Err(e),
            },
            OP_WRITE if len == BLOCK_SIZE => match self.write_data(&v, b, msg) {
                // Mirroring: answered once the target has it too (RFD 3, P4).
                Ok(()) if v.mirror => {
                    self.volumes[i].as_mut().unwrap().mirror_pending = Some((sender, b));
                    return;
                }
                other => other,
            },
            _ => Err(CODE_BAD_OP),
        };
        let code = match result {
            Ok(()) => CODE_OK,
            Err(e) if err::is_error(e) => CODE_IO_ERROR,
            Err(code) => code,
        };
        let _ = reply(sender, code, &[]);
    }
}

/// A volume's name without its zero padding.
fn name_of(v: &Volume) -> &[u8] {
    trim(&v.name)
}

fn trim(name: &[u8; 32]) -> &[u8] {
    &name[..name.iter().position(|&c| c == 0).unwrap_or(32)]
}

/// Ask the key server for service `name`'s key, if there is one we may ask.
fn fetch_service_key(name: &[u8; 32]) -> Option<[u8; 32]> {
    let keys = lookup("keys").ok()?;
    let mut key = [0u8; 32];
    match send(keys, keys::OP_SERVICE_KEY, trim(name), &mut key) {
        Ok((CODE_OK, 32)) => Some(key),
        _ => None,
    }
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
        service_keys: [None; MAX_VOLUMES],
        capacity: 0,
        next_free: FIRST_DATA,
        volumes: [None; MAX_VOLUMES],
        telemetry: lookup("telemetry").ok(),
        held: [None; MAX_HELD],
        held_seq: 0,
        release: None,
        exported: None,
        importing: None,
        io: [0; 3],
        next_snapshot: 0,
        interval: telemetry::DEFAULT_INTERVAL_TICKS,
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
        #[cfg(feature = "crash-after-16")]
        if split(m.op).0 == block::OP_WRITE {
            writes += 1;
            if writes == 16 && vanir_user::getpid() >> 16 == 0 {
                println!("storage: crashing after 15 writes");
                unsafe { core::ptr::read_volatile(0x10 as *const u8) };
            }
        }
        s.serve(m.sender, m.op, m.len, &mut msg);
        if let Some(i) = s.release.take() {
            s.release_held(i);
        }
        s.snapshot();
    }
}
