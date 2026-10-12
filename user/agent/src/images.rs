//! Test scripts and the signed slot images they carry (build/slots, made by the Makefile).

use crate::lifecycle::Agent;
#[allow(unused_imports)]
use crate::{Image, load, load_and_report, slot_id, unload_when_done};
#[allow(unused_imports)]
use vanir_user::{err, println, recv, sleep, slot};

macro_rules! image {
    ($name:literal) => {
        Image {
            name: $name,
            elf: include_bytes!(concat!(env!("VANIR_SLOTS"), "/", $name, ".elf")),
            descriptor: include_bytes!(concat!(env!("VANIR_SLOTS"), "/", $name, ".desc")),
            sig: include_bytes!(concat!(env!("VANIR_SLOTS"), "/", $name, ".sig")),
        }
    };
}

#[allow(dead_code)]
const WEB_V1: Image = image!("web-v1");
#[allow(dead_code)]
const HELLO: Image = image!("hello");
#[allow(dead_code)]
const CRASHER: Image = image!("crasher");
#[allow(dead_code)]
const WEB_V2: Image = image!("web-v2");

/// Wait for messages forever (scripts that leave a service running).
#[allow(dead_code)]
fn wait() -> ! {
    let mut buf = [0u8; 64];
    loop {
        let _ = recv(&mut buf);
    }
}

/// Run the script the features pick; returns the exit code, or None if there is none.
pub fn script() -> Option<u64> {
    if let Some(code) = deployment_script() {
        return Some(code);
    }
    #[cfg(feature = "script-load")]
    {
        let _ = load_and_report("small-0", &WEB_V1);
        wait();
    }
    #[cfg(feature = "script-hello")]
    {
        let _ = load_and_report("small-0", &HELLO);
        wait();
    }
    #[cfg(feature = "script-crasher")]
    {
        let _ = load_and_report("small-0", &CRASHER);
        wait();
    }
    #[cfg(feature = "script-hello-loop")]
    {
        for i in 0..200 {
            if let Err((e, _)) = load("small-0", &HELLO) {
                println!("agent: load {} failed: {}", i, err::name(e));
                return Some(1);
            }
            if let Err(e) = unload_when_done("small-0") {
                println!("agent: unload {} failed: {}", i, err::name(e));
                return Some(1);
            }
        }
        println!("agent: loaded and unloaded hello 200 times");
        return Some(0);
    }
    #[cfg(feature = "script-fill-log")]
    {
        for i in 0.. {
            if load_and_report("small-0", &HELLO).is_err() {
                break;
            }
            if let Err(e) = unload_when_done("small-0") {
                println!("agent: unload {} refused: {}", i, err::name(e));
                break;
            }
        }
        return Some(0);
    }
    #[cfg(feature = "script-load-retry")]
    {
        sleep(20); // let the attestation task start (and, in slot-tpm-busy, take the TPM)
        let slot = slot_id("small-0");
        if let Err(e) = slot::stage_all(slot, HELLO.elf) {
            println!("agent: staging failed: {}", err::name(e));
            return Some(1);
        }
        let mut busy = 0;
        loop {
            match slot::load(slot, HELLO.sig, HELLO.descriptor) {
                Err((err::BUSY, _)) => {
                    busy += 1;
                    sleep(10);
                }
                Ok(_) => {
                    println!("agent: loaded hello after {} BUSY answers", busy);
                    return Some(0);
                }
                Err((e, why)) => {
                    println!("agent: load failed: {} ({})", err::name(e), why);
                    return Some(1);
                }
            }
        }
    }
    #[cfg(feature = "try-unsigned")]
    {
        let _ = load_and_report("small-0", &Image { sig: &[], ..WEB_V1 });
        return Some(0);
    }
    #[cfg(feature = "try-tampered-image")]
    {
        // Stage it, then change one byte in the slot's image area before loading.
        let slot = slot_id("small-0");
        slot::stage_all(slot, WEB_V1.elf).expect("stage");
        slot::stage(slot, 4096, &[WEB_V1.elf[4096] ^ 1]).expect("stage");
        report_refusal("web-v1 (one image byte changed)", slot::load(slot, WEB_V1.sig, WEB_V1.descriptor));
        return Some(0);
    }
    #[cfg(feature = "try-tampered-desc")]
    {
        // Listen on one more port than was signed.
        let mut desc = [0u8; 256];
        desc.copy_from_slice(WEB_V1.descriptor);
        desc[80] += 1;
        desc[96..98].copy_from_slice(&81u16.to_le_bytes());
        desc[98..100].copy_from_slice(&64u16.to_le_bytes());
        desc[100..102].copy_from_slice(&64u16.to_le_bytes());
        let slot = slot_id("small-0");
        slot::stage_all(slot, WEB_V1.elf).expect("stage");
        report_refusal("web-v1 (descriptor changed)", slot::load(slot, WEB_V1.sig, &desc));
        return Some(0);
    }
    #[cfg(feature = "try-boot-sig")]
    {
        let boot_sig = include_bytes!(concat!(env!("VANIR_SLOTS"), "/../http.sig"));
        let _ = load_and_report("small-0", &Image { sig: boot_sig, ..WEB_V1 });
        return Some(0);
    }
    #[cfg(feature = "try-floor")]
    {
        let _ = load_and_report("small-0", &image!("web-floor"));
        return Some(0);
    }
    #[cfg(feature = "try-large")]
    {
        let _ = load_and_report("small-0", &image!("web-large"));
        return Some(0);
    }
    #[cfg(feature = "try-occupied")]
    {
        let _ = load_and_report("small-0", &HELLO);
        let slot = slot_id("small-0");
        match slot::stage(slot, 0, &CRASHER.elf[..4096]) {
            Ok(()) => println!("agent: staging over a loaded slot: allowed"),
            Err(e) => println!("agent: staging over a loaded slot: {}", err::name(e)),
        }
        match slot::load(slot, CRASHER.sig, CRASHER.descriptor) {
            Ok(_) => println!("agent: loading over a loaded slot: allowed"),
            Err((e, _)) => println!("agent: loading over a loaded slot: {}", err::name(e)),
        }
        return Some(0);
    }
    #[cfg(feature = "try-web-v1")]
    {
        let _ = load_and_report("small-0", &WEB_V1);
        return Some(0);
    }
    #[allow(unreachable_code)]
    None
}

#[allow(dead_code)]
fn report_refusal(what: &str, result: Result<u64, (u64, u64)>) {
    match result {
        Ok(_) => println!("agent: {}: loaded", what),
        Err((err::REJECTED, why)) => println!("agent: {}: REJECTED ({})", what, vanir_user::events::rejection(why)),
        Err((e, _)) => println!("agent: {}: {}", what, err::name(e)),
    }
}

/// Run deployments until they have all finished, then forget them.
#[allow(dead_code)]
fn settle(agent: &mut Agent) {
    loop {
        agent.advance();
        if agent.idle() {
            agent.deploys = [None; 4];
            return;
        }
        sleep(5);
    }
}

/// Deployment scripts (RFD 2, P3/P4) on `net`, with the supervisor stopping and starting slots.
/// Returns the exit code, or None if no deployment script was picked.
#[allow(unreachable_code, unused_mut, unused_variables)]
fn deployment_script() -> Option<u64> {
    if !cfg!(any(
        feature = "script-deploy",
        feature = "script-rollback",
        feature = "script-not-ready",
        feature = "script-drain-cap",
        feature = "script-commit"
    )) {
        return None;
    }
    let mut agent = Agent::new();
    let (s0, s1) = (agent.slot("small-0"), agent.slot("small-1"));
    // Every script starts with web v1 live in small-0.
    agent.deploy(s0, Some(WEB_V1), None);
    settle(&mut agent);

    #[cfg(feature = "script-deploy")]
    {
        sleep(300);
        agent.deploy(s1, Some(WEB_V2), None);
        settle(&mut agent);
        println!("agent: deployed web v2");
        wait();
    }
    #[cfg(feature = "script-rollback")]
    {
        sleep(200);
        agent.deploy(s1, Some(WEB_V2), None);
        settle(&mut agent);
        sleep(200);
        println!("agent: rolling back to web v1");
        let old = agent.stopped(b"web").expect("v1 is kept until commit");
        agent.deploy(old, None, None);
        settle(&mut agent);
        println!("agent: rolled back to web v1");
        wait();
    }
    #[cfg(feature = "script-not-ready")]
    {
        agent.deploy(s1, Some(WEB_V2), None);
        settle(&mut agent);
        println!("agent: after the failed deployment, {} is {}", agent.get(s0).name, agent.get(s0).state.name());
        return Some(0);
    }
    #[cfg(feature = "script-drain-cap")]
    {
        agent.deploy(s1, Some(WEB_V2), Some(100_000));
        settle(&mut agent);
        return Some(0);
    }
    #[cfg(feature = "script-commit")]
    {
        agent.deploy(s1, Some(WEB_V2), None);
        settle(&mut agent);
        agent.commit(b"web");
        println!("agent: committed web v2; small-0 is {}", agent.get(s0).state.name());
        agent.deploy(s0, Some(WEB_V1), None);
        settle(&mut agent);
        println!("agent: web v1 is live again in {}", agent.get(s0).name);
        return Some(0);
    }
    None
}
