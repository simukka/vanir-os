//! The service runtime (RFD 9, P3): what a service in a slot is written against.
//!
//! `http`: parsing requests and the reasons for status codes, shared with `user/http`.

#![no_std]

pub mod http;
