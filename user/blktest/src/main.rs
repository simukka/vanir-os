//! Block storage test client. Writes `BLOCKS` blocks with a pattern derived from the block number,
//! flushes, reads them back and checks them; with `check-only`, just checks (a disk written by an
//! earlier boot). Also checks a read past the end is refused. Talks to the task named "disk"
//! (the driver, or the storage task in later tests), riding out a restart of it.

#![no_std]
#![no_main]

use vanir_user::block::{self, BLOCK_SIZE, CODE_LOCKED, CODE_OUT_OF_RANGE, code_name};
use vanir_user::{err, getpid, lookup, println, sleep, task_name};

vanir_user::entry!(main);

const BLOCKS: u64 = 32;

/// The contents block `block` should have, different for every block and every task name, so
/// two tasks whose volumes overlapped would see each other's data.
/// Every block starts with this, so a test can look for plain text on the disk image.
const MARKER: &[u8; 16] = b"VANIR-PLAINTEXT!";

fn pattern(seed: u64, block: u64, out: &mut [u8; BLOCK_SIZE]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&(seed ^ block * 0x0101_0101 ^ i as u64 ^ 0x5eed_0000_0000).to_le_bytes());
    }
    out[..16].copy_from_slice(MARKER);
}

/// Run `f` against the disk task, finding it again (by name) if it died and was restarted.
fn with_disk<T>(disk: &mut u64, mut f: impl FnMut(u64) -> Result<T, u64>) -> Result<T, u64> {
    loop {
        match f(*disk) {
            Err(e) if e == err::DEAD => {
                let old = *disk;
                *disk = loop {
                    match lookup("disk") {
                        Ok(id) if id != old => break id,
                        _ => sleep(1),
                    }
                };
            }
            other => return other,
        }
    }
}

fn main() -> u64 {
    let mut name = [0u8; 64];
    let name = task_name(getpid(), &mut name).unwrap_or("?");
    // FNV-1a of the task name: this task's data differs from every other task's.
    let seed = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));

    #[cfg(feature = "poke-driver")]
    {
        // Only the storage task may talk to the block driver.
        let driver = lookup("blockdev").expect("no blockdev task");
        let result = block::capacity(driver);
        println!("blktest: talking to the block driver directly: {}", code_name(result.err().unwrap_or(0)));
        return if result == Err(err::NOT_ALLOWED) { 0 } else { 1 };
    }

    #[allow(unreachable_code)]
    let mut disk = lookup("disk").expect("no disk task");
    // The storage task may still be waiting for its key: give it 2 s.
    let mut capacity = with_disk(&mut disk, block::capacity);
    for _ in 0..200 {
        if capacity != Err(CODE_LOCKED) {
            break;
        }
        sleep(1);
        capacity = with_disk(&mut disk, block::capacity);
    }
    let capacity = match capacity {
        Ok(c) => c,
        Err(CODE_LOCKED) => {
            println!("blktest: the disk stayed LOCKED");
            return 1;
        }
        Err(e) => {
            println!("blktest: capacity failed: {}", code_name(e));
            return 1;
        }
    };
    println!("blktest: {} blocks available", capacity);

    let mut want = [0u8; BLOCK_SIZE];
    #[cfg(not(feature = "check-only"))]
    {
        for b in 0..BLOCKS {
            pattern(seed, b, &mut want);
            if let Err(e) = with_disk(&mut disk, |d| block::write(d, b, &want)) {
                println!("blktest: write {} failed: {}", b, code_name(e));
                return 1;
            }
        }
        if let Err(e) = with_disk(&mut disk, block::flush) {
            println!("blktest: flush failed: {}", code_name(e));
            return 1;
        }
        println!("blktest: {} wrote {} blocks", name, BLOCKS);
        // Give other clients time to write theirs before checking ours.
        sleep(20);
    }

    let mut got = [0u8; BLOCK_SIZE];
    for b in 0..BLOCKS {
        pattern(seed, b, &mut want);
        if let Err(e) = with_disk(&mut disk, |d| block::read(d, b, &mut got)) {
            println!("blktest: {} read {} failed: {}", name, b, code_name(e));
            return 1;
        }
        if got != want {
            println!("blktest: block {} has the wrong contents", b);
            return 1;
        }
    }
    println!("blktest: {} read back {} blocks, all correct", name, BLOCKS);

    match with_disk(&mut disk, |d| block::read(d, capacity, &mut got)) {
        Err(CODE_OUT_OF_RANGE) => println!("blktest: block {} (past the end) refused", capacity),
        other => {
            println!("blktest: read past the end returned {:?}", other.map_err(code_name));
            return 1;
        }
    }
    0
}
