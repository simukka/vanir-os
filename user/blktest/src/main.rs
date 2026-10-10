//! Block storage test client. Writes `BLOCKS` blocks with a pattern derived from the block number,
//! flushes, reads them back and checks them; with `check-only`, just checks (a disk written by an
//! earlier boot). Also checks a read past the end is refused. Talks to the task named "disk"
//! (the driver, or the storage task in later tests), riding out a restart of it.

#![no_std]
#![no_main]

use vanir_user::block::{self, BLOCK_SIZE, CODE_OUT_OF_RANGE, code_name};
use vanir_user::{err, lookup, println, sleep};

vanir_user::entry!(main);

const BLOCKS: u64 = 32;

fn pattern(block: u64, out: &mut [u8; BLOCK_SIZE]) {
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&(block * 0x0101_0101 ^ i as u64 ^ 0x5eed_0000_0000).to_le_bytes());
    }
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
    let mut disk = lookup("disk").expect("no disk task");
    let capacity = match with_disk(&mut disk, block::capacity) {
        Ok(c) => c,
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
            pattern(b, &mut want);
            if let Err(e) = with_disk(&mut disk, |d| block::write(d, b, &want)) {
                println!("blktest: write {} failed: {}", b, code_name(e));
                return 1;
            }
        }
        if let Err(e) = with_disk(&mut disk, block::flush) {
            println!("blktest: flush failed: {}", code_name(e));
            return 1;
        }
        println!("blktest: wrote {} blocks", BLOCKS);
    }

    let mut got = [0u8; BLOCK_SIZE];
    for b in 0..BLOCKS {
        pattern(b, &mut want);
        if let Err(e) = with_disk(&mut disk, |d| block::read(d, b, &mut got)) {
            println!("blktest: read {} failed: {}", b, code_name(e));
            return 1;
        }
        if got != want {
            println!("blktest: block {} has the wrong contents", b);
            return 1;
        }
    }
    println!("blktest: read back {} blocks, all correct", BLOCKS);

    match with_disk(&mut disk, |d| block::read(d, capacity, &mut got)) {
        Err(CODE_OUT_OF_RANGE) => println!("blktest: block {} (past the end) refused", capacity),
        other => {
            println!("blktest: read past the end returned {:?}", other.map_err(code_name));
            return 1;
        }
    }
    0
}
