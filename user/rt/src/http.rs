//! HTTP/1.1 requests: parsing a header, and the reason phrases of the status codes the runtime
//! and `user/http` send. Fixed buffers, no allocation.

/// A request's header must fit in this many bytes (else 431).
pub const HEADER_LIMIT: usize = 4096;
/// Bodies are refused above this (413).
pub const BODY_LIMIT: usize = 16 * 1024;
/// A request's header must be complete this many ticks after its first byte (else 408).
pub const HEADER_TICKS: u64 = 500;
/// A keep-alive connection idle this long between requests is closed.
pub const IDLE_TICKS: u64 = 1500;

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn parse_number(s: &[u8]) -> Option<usize> {
    if s.is_empty() || s.len() > 18 {
        return None;
    }
    s.iter().try_fold(0usize, |n, &c| c.is_ascii_digit().then(|| n * 10 + (c - b'0') as usize))
}

/// What a request asks for, once its header is complete.
pub struct Request<'a> {
    pub method: &'a [u8],
    pub path: &'a [u8],
    pub keep_alive: bool,
    pub content_length: Option<usize>,
    pub chunked: bool,
    /// Bytes of header, including the blank line.
    pub header_len: usize,
}

/// Parse a request's header from the start of `buf`: None until the blank line has arrived;
/// Err(status) for a request to refuse (400, 505).
pub fn parse(buf: &[u8]) -> Option<Result<Request<'_>, u16>> {
    let end = find(buf, b"\r\n\r\n")? + 4;
    let mut lines = buf[..end - 4].split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = lines.next().unwrap_or(&[]);
    let mut parts = line.split(|&b| b == b' ').filter(|p| !p.is_empty());
    let (Some(method), Some(path), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Some(Err(400));
    };
    let mut keep_alive = version == b"HTTP/1.1";
    if !keep_alive && version != b"HTTP/1.0" {
        return Some(Err(505));
    }
    let (mut content_length, mut chunked) = (None, false);
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else { return Some(Err(400)) };
        let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
        if eq_ignore_case(name, b"connection") {
            if eq_ignore_case(value, b"close") {
                keep_alive = false;
            } else if eq_ignore_case(value, b"keep-alive") {
                keep_alive = true;
            }
        } else if eq_ignore_case(name, b"content-length") {
            match parse_number(value) {
                Some(n) => content_length = Some(n),
                None => return Some(Err(400)),
            }
        } else if eq_ignore_case(name, b"transfer-encoding") {
            chunked = true;
        }
    }
    Some(Ok(Request { method, path, keep_alive, content_length, chunked, header_len: end }))
}

/// The reason phrase for a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}
