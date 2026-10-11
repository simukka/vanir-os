//! A TCP echo service on the management stack (`mgmt-net`, port 7): what the node agent will
//! be, for testing that the management network stays separate from the data network.

#![no_std]
#![no_main]

use vanir_user::net::{self, EV_ACCEPT, EV_CLOSED, EV_READ, EV_WRITE, Event};
use vanir_user::{lookup, println, sleep};

vanir_user::entry!(main);

const PORT: u16 = 7;
const CONNECTIONS: usize = 8;

fn main() -> u64 {
    #[cfg(feature = "try-data-net")]
    match lookup("net").map(|data| net::listen(data, PORT)) {
        Ok(Err(e)) => println!("mgmt-echo: talking to net: {}", net::code_name(e)),
        Ok(Ok(_)) => println!("mgmt-echo: talking to net: ALLOWED"),
        Err(e) => println!("mgmt-echo: no net: {}", vanir_user::err::name(e)),
    }
    let mut stack = 0;
    'attach: loop {
        stack = loop {
            match lookup("mgmt-net") {
                Ok(id) if id != stack => break id,
                _ => sleep(1),
            }
        };
        let listener = match net::listen(stack, PORT) {
            Ok(h) => h,
            Err(e) => {
                println!("mgmt-echo: listen refused: {}", net::code_name(e));
                return 1;
            }
        };
        let _ = net::ready(stack);
        println!("mgmt-echo: echoing on port {}", PORT);
        let mut conns = [0u32; CONNECTIONS];
        let mut events = [Event::default(); 16];
        let mut buf = [0u8; 2048];
        loop {
            let n = match net::wait(stack, 0, &mut events) {
                Ok(n) => n,
                Err(_) => continue 'attach, // mgmt-net restarted
            };
            for e in &events[..n] {
                if e.flags & EV_ACCEPT != 0 {
                    while let Ok(Some(a)) = net::accept(stack, listener) {
                        match conns.iter().position(|&c| c == 0) {
                            Some(i) => conns[i] = a.handle,
                            None => drop(net::close(stack, a.handle)),
                        }
                    }
                    continue;
                }
                let Some(i) = conns.iter().position(|&c| c == e.handle) else { continue };
                if e.flags & (EV_READ | EV_WRITE) != 0 {
                    // Echo what came; an echo service may drop bytes the stack has no room for.
                    match net::recv(stack, e.handle, &mut buf) {
                        Ok(len) => drop(net::send_data(stack, e.handle, &buf[..len])),
                        Err(_) => {
                            let _ = net::close(stack, e.handle);
                            conns[i] = 0;
                        }
                    }
                } else if e.flags & EV_CLOSED != 0 {
                    let _ = net::close(stack, e.handle);
                    conns[i] = 0;
                }
            }
        }
    }
}
