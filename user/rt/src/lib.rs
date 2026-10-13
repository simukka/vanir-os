//! The service runtime (RFD 9, P3): what a service in a slot is written against.
//!
//! A service implements `Service` and names itself with `service!`; the runtime owns the event
//! loop. It finds the network stack, listens on the port the service's descriptor declares,
//! says it is ready once `start` returns, and answers HTTP/1.1 requests over keep-alive
//! connections, calling `request` for each one. It enforces the header and idle deadlines,
//! sends telemetry counters (requests by status class and a latency histogram), and runs the
//! drain: no new connections, `Connection: close` as requests finish, then `drain()`, then it
//! tells the network stack it is done. A service can't forget a step of that, or do them out of
//! order.
//!
//! ```ignore
//! struct Hello;
//! impl vanir_rt::Service for Hello {
//!     fn start(_: &mut Ctx) -> Result<Self, Error> { Ok(Hello) }
//!     fn request(&mut self, ctx: &mut Ctx, _: &Request, res: &mut Response) {
//!         let _ = write!(res, "hello from {}\n", ctx.name());
//!     }
//! }
//! vanir_rt::service!(Hello, connections = 16);
//! ```
//!
//! **Settings** (RFD 9, P5) come from the signed descriptor: a service lists the ones it has,
//! with defaults, in `Service::CONFIG`, and reads them with `ctx.config(key)`. A descriptor
//! with a setting the service doesn't list never becomes ready, and says why.
//!
//! **The volume** (RFD 3): `ctx.volume()` opens the one the descriptor declares, waiting while
//! storage is locked. A write refused because this instance isn't the writer (`Error::Fenced`)
//! makes the runtime call `fenced()` once the callback returns, so the service drops what it
//! cached. When the instance becomes the writer, the runtime prints it.
//!
//! Single-threaded and without a heap: one request at a time, from fixed buffers. The connection
//! table's size is `service!`'s `connections`.
//!
//! **On the host** (any target but `x86_64-unknown-none`), this crate is a test backend instead:
//! `host::Host` runs the service's callbacks with a clock the test moves and a volume in memory,
//! so `cargo test --target x86_64-unknown-linux-gnu -p <program>` unit-tests a service. A
//! program builds for both with `#![cfg_attr(target_os = "none", no_std, no_main)]`.

#![cfg_attr(target_os = "none", no_std)]

mod ctx;
#[cfg(not(target_os = "none"))]
pub mod host;
pub mod http;
#[cfg(target_os = "none")]
mod runtime;
mod volume;

pub use ctx::{Ctx, Response};
pub use http::Request;
#[cfg(target_os = "none")]
pub use runtime::{Runtime, run};
pub use volume::{BLOCK_SIZE, Error, Volume};

/// A service: what the runtime calls.
pub trait Service: Sized {
    /// The settings this service has, and their defaults (RFD 9, P5).
    const CONFIG: &'static [(&'static str, u64)] = &[];

    /// Get ready to serve. Returning Err leaves the instance never ready (its deployment fails
    /// at the agent's deadline); say why first.
    fn start(ctx: &mut Ctx) -> Result<Self, Error>;

    /// Answer one GET or HEAD request (the runtime answers anything else, and sends only the
    /// header for HEAD). `res` starts as 200 with an empty body.
    fn request(&mut self, ctx: &mut Ctx, req: &Request, res: &mut Response);

    /// Work on a timer: called once after `start`, then after as many ticks as it returns each
    /// time (None: no more calls).
    fn tick(&mut self, _ctx: &mut Ctx) -> Option<u64> {
        None
    }

    /// The instance is about to tell the network stack it is done (a drain), or to exit: the
    /// last moment to save state.
    fn drain(&mut self, _ctx: &mut Ctx) {}

    /// A volume write or flush was refused: another instance is the writer now. Drop what is
    /// cached.
    fn fenced(&mut self, _ctx: &mut Ctx) {}
}

/// Declare the program's service: `service!(MyService)` or
/// `service!(MyService, connections = 16)` (default 64).
#[cfg(target_os = "none")]
#[macro_export]
macro_rules! service {
    ($svc:ty, connections = $n:expr) => {
        static mut VANIR_RT: $crate::Runtime<$n> = $crate::Runtime::new();
        fn vanir_rt_main() -> u64 {
            $crate::run::<$svc, $n>(unsafe { &mut *(&raw mut VANIR_RT) })
        }
        $crate::__entry!(vanir_rt_main);
    };
    ($svc:ty) => {
        $crate::service!($svc, connections = 64);
    };
}

/// Declare the program's service. On the host, a `main` that says how to run it: the service
/// itself is run by its tests, through `host::Host`.
#[cfg(not(target_os = "none"))]
#[macro_export]
macro_rules! service {
    ($svc:ty, connections = $n:expr) => {
        #[allow(dead_code)]
        fn main() {
            let _ = $crate::host::Host::<$svc>::new;
            eprintln!("a service runs in a slot (make run-service); on the host, run its tests (cargo test)");
            std::process::exit(2);
        }
    };
    ($svc:ty) => {
        $crate::service!($svc, connections = 64);
    };
}

#[cfg(target_os = "none")]
#[doc(hidden)]
pub use vanir_user::entry as __entry;

/// Print a line to the node's log (on the host, to stdout).
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => { $crate::__println!($($arg)*) };
}

#[cfg(target_os = "none")]
#[doc(hidden)]
pub use vanir_user::println as __println;
#[cfg(not(target_os = "none"))]
#[doc(hidden)]
pub use std::println as __println;

/// The task's raw syscalls and IPC (`vanir_user`), for what the runtime doesn't wrap yet. Not
/// part of what the runtime promises (RFD 9, P3).
#[cfg(all(feature = "unstable", target_os = "none"))]
pub mod raw {
    pub use vanir_user::*;
}
