//! The kernel event log: what happened to tasks, in order, for the telemetry task to forward.
//!
//! A fixed ring of the most recent `CAPACITY` events, each numbered. The single reader (the task
//! with `events = true` in the manifest) gets every event after the last one it read; if the
//! ring wrapped past those, it is told how many were dropped.

use core::mem::size_of;
use spin::Mutex;

use crate::apic;

const CAPACITY: usize = 128;

pub const TASK_START: u64 = 1;
pub const EXIT: u64 = 2;
pub const FAULT: u64 = 3;
pub const OVER_BUDGET: u64 = 4;
pub const RESTART: u64 = 5;
/// An IPC send refused: a = target id, b = error code.
pub const IPC_REFUSED: u64 = 6;

/// One event, as the reader receives it. Fields `a`, `b`, `c` depend on `kind`:
/// TASK_START none; EXIT a = code; FAULT a = vector, b = rip, c = cr2; OVER_BUDGET a = budget;
/// RESTART a = previous id; IPC_REFUSED a = target, b = error.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Event {
    pub seq: u64,
    pub tick: u64,
    pub kind: u64,
    pub task: u64,
    pub a: u64,
    pub b: u64,
    pub c: u64,
}

pub const EVENT_SIZE: usize = size_of::<Event>();

struct Log {
    ring: [Event; CAPACITY],
    /// Sequence number of the next event (the first is 1).
    next: u64,
    /// Last sequence number handed to the reader.
    read: u64,
}

static LOG: Mutex<Log> = Mutex::new(Log { ring: [Event { seq: 0, tick: 0, kind: 0, task: 0, a: 0, b: 0, c: 0 }; CAPACITY], next: 1, read: 0 });

pub fn log(kind: u64, task: u64, a: u64, b: u64, c: u64) {
    let mut log = LOG.lock();
    let seq = log.next;
    log.ring[seq as usize % CAPACITY] = Event { seq, tick: apic::now(), kind, task, a, b, c };
    log.next += 1;
}

/// Copy events after the last one read into `out`, oldest first. Returns (count, dropped):
/// events that were overwritten before they could be read.
pub fn read(out: &mut [Event]) -> (usize, u64) {
    let mut log = LOG.lock();
    let oldest = log.next.saturating_sub(CAPACITY as u64).max(1);
    let dropped = oldest.saturating_sub(log.read + 1);
    let mut seq = (log.read + 1).max(oldest);
    let mut count = 0;
    while seq < log.next && count < out.len() {
        out[count] = log.ring[seq as usize % CAPACITY];
        count += 1;
        seq += 1;
    }
    log.read = seq - 1;
    (count, dropped)
}

pub fn logged() -> u64 {
    LOG.lock().next - 1
}
