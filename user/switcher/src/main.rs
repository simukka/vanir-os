//! Routing commands for the network stack from a script, standing in for the node agent
//! (RFD 2) in tests. Pick the script with a feature:
//!
//! - `script-swap`: make `web-1` live, let it serve for a while, make `web-2` live and drain
//!   `web-1` (10 s deadline).
//! - `script-drain-deadline`: the same with a 2 s deadline, for a connection that never ends.
//! - `script-not-ready`: try to make `web-idle` live, which never said it was ready.
//! - `script-not-allowed`: try to route without `routes = true` in the manifest.
//!
//! After a script that ends a test, the switcher exits (with the supervisor's `halt-on-exit`,
//! the run ends); otherwise it waits forever.

#![no_std]
#![no_main]

use vanir_user::net::{self, CODE_NOT_READY};
use vanir_user::{lookup, println, recv, sleep};

vanir_user::entry!(main);

fn id(name: &str) -> u64 {
    loop {
        match lookup(name) {
            Ok(id) => return id,
            Err(_) => sleep(1),
        }
    }
}

/// Make `name` live, waiting until it is ready.
#[allow(dead_code)]
fn route(net: u64, name: &str) {
    loop {
        match net::route(net, id(name)) {
            Ok(()) => break,
            Err(CODE_NOT_READY) => sleep(10),
            Err(e) => {
                println!("switcher: routing to {} failed: {}", name, net::code_name(e));
                sleep(10);
            }
        }
    }
    println!("switcher: {} is live", name);
}

#[allow(dead_code)]
fn swap(net: u64, serve_ticks: u64, deadline: u64) {
    route(net, "web-1");
    sleep(serve_ticks);
    route(net, "web-2");
    println!("switcher: draining web-1 ({} ticks)", deadline);
    match net::drain(net, id("web-1"), deadline) {
        Ok(forced) => println!("switcher: web-1 drained, drain_forced = {}", forced),
        Err(e) => println!("switcher: drain failed: {}", net::code_name(e)),
    }
}

fn main() -> u64 {
    let net = id("net");
    #[cfg(feature = "script-swap")]
    swap(net, 300, 1000);
    #[cfg(feature = "script-drain-deadline")]
    swap(net, 300, 200);
    #[cfg(feature = "script-not-ready")]
    {
        sleep(100); // give net time to start
        let r = net::route(net, id("web-idle"));
        println!("switcher: making web-idle live: {}", r.map_or_else(net::code_name, |_| "OK"));
        return 0;
    }
    #[cfg(feature = "script-not-allowed")]
    {
        sleep(100);
        let r = net::route(net, id("web-1"));
        println!("switcher: making web-1 live: {}", r.map_or_else(net::code_name, |_| "OK"));
        let r = net::drain(net, id("web-1"), 100);
        println!("switcher: draining web-1: {}", r.map_or_else(net::code_name, |_| "OK"));
        return 0;
    }
    #[allow(unreachable_code)]
    {
        let _ = net;
        let mut buf = [0u8; 8];
        loop {
            let _ = recv(&mut buf); // nobody sends to us
        }
    }
}
