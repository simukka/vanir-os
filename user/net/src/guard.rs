//! Protection against abuse (RFD 1, P6) that needs its own state: the blocklist the control
//! plane sets, and a sketch of the heaviest senders for reports.

/// Address ranges whose packets are dropped before anything else looks at them.
pub struct Blocklist {
    entries: [Option<Entry>; 16],
}

#[derive(Clone, Copy)]
struct Entry {
    addr: u32,
    mask: u32,
    expires: u64,
}

impl Blocklist {
    pub const fn new() -> Blocklist {
        Blocklist { entries: [None; 16] }
    }

    /// Block `addr`/`prefix` until tick `expires`, in place of an expired or the oldest entry.
    pub fn add(&mut self, addr: [u8; 4], prefix: u32, expires: u64, now: u64) {
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
        let entry = Entry { addr: u32::from_be_bytes(addr) & mask, mask, expires };
        let slot = self
            .entries
            .iter()
            .position(|e| e.is_none_or(|e| e.expires <= now || (e.addr, e.mask) == (entry.addr, entry.mask)))
            .unwrap_or_else(|| (0..self.entries.len()).min_by_key(|&i| self.entries[i].unwrap().expires).unwrap());
        self.entries[slot] = Some(entry);
    }

    pub fn blocks(&self, addr: [u8; 4], now: u64) -> bool {
        let addr = u32::from_be_bytes(addr);
        self.entries.iter().flatten().any(|e| e.expires > now && addr & e.mask == e.addr)
    }

    pub fn len(&self, now: u64) -> usize {
        self.entries.iter().flatten().filter(|e| e.expires > now).count()
    }
}

/// The heaviest sources since the last reset, by the Space-Saving algorithm: 32 counters, and
/// a newcomer takes over the smallest one (inheriting its count, so counts are upper bounds).
/// Any source with more than 1/32 of the traffic is sure to be in it.
pub struct Talkers {
    entries: [(u32, u64); 32],
    used: usize,
}

impl Talkers {
    pub const fn new() -> Talkers {
        Talkers { entries: [(0, 0); 32], used: 0 }
    }

    pub fn observe(&mut self, addr: [u8; 4]) {
        let addr = u32::from_be_bytes(addr);
        if let Some(e) = self.entries[..self.used].iter_mut().find(|e| e.0 == addr) {
            e.1 += 1;
        } else if self.used < self.entries.len() {
            self.entries[self.used] = (addr, 1);
            self.used += 1;
        } else {
            let min = (0..self.used).min_by_key(|&i| self.entries[i].1).unwrap();
            self.entries[min] = (addr, self.entries[min].1 + 1);
        }
    }

    /// The `n` heaviest: (address, count), heaviest first.
    pub fn top<const N: usize>(&self) -> [Option<([u8; 4], u64)>; N] {
        let mut sorted = self.entries;
        sorted[..self.used].sort_unstable_by(|a, b| b.1.cmp(&a.1));
        core::array::from_fn(|i| (i < self.used).then(|| (sorted[i].0.to_be_bytes(), sorted[i].1)))
    }

    pub fn reset(&mut self) {
        self.used = 0;
    }
}
