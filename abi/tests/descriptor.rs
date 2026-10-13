//! `vanir_abi::descriptor` reads what `tools/sign-image.py` writes: the fixtures here are made by
//! it from `descriptor-v1.toml` and `descriptor-v2.toml` (the host check `descriptor-format`
//! makes them again and compares the bytes).
use vanir_abi::descriptor::*;

const V2: &[u8] = include_bytes!("descriptor-v2.bin");
const V1: &[u8] = include_bytes!("descriptor-v1.bin");

fn key(k: &str) -> [u8; KEY_LEN] {
    let mut out = [0; KEY_LEN];
    out[..k.len()].copy_from_slice(k.as_bytes());
    out
}

#[test]
fn format_2() {
    assert_eq!(format(V2), Some(2));
    assert_eq!(name(V2), b"fixture-service");
    assert_eq!(version(V2), 7);
    assert_eq!(min_version(V2), 3);
    assert_eq!(slot_class(V2), b"small");
    assert_eq!(drain_secs(V2), (20, 120));
    assert_eq!(listen_count(V2), 2);
    assert_eq!(listen(V2, 0), (80, 64, 16, 0));
    assert_eq!(listen(V2, 1), (8443, 8, 8, 0));
    assert_eq!(volume_blocks(V2), 256);
    assert_eq!(abi(V2), (1, 0));
    assert_eq!(settings_count(V2), MAX_SETTINGS);
    let want = [
        ("a", 1),
        ("persist_ticks", 1000),
        ("k2", 2),
        ("k3", 3),
        ("k4", 4),
        ("k5", 5),
        ("k6", 6),
        ("k7", 7),
        ("k8", 8),
        ("k9", 9),
        ("k10", 10),
        ("key_sixteen_byte", u64::MAX),
    ];
    for (i, (k, v)) in want.iter().enumerate() {
        assert_eq!(setting(V2, i), (key(k), *v), "setting {i}");
        assert!(valid_key(&setting(V2, i).0));
    }
    assert!(V2[AT_RESERVED_V2..].iter().all(|&b| b == 0));
}

#[test]
fn format_1() {
    assert_eq!(format(V1), Some(1));
    assert_eq!(name(V1), b"fixture-service");
    assert_eq!(listen(V1, 0), (80, 64, 64, 0));
    assert_eq!(abi(V1), (1, 0));
    assert_eq!(settings_count(V1), 0);
    assert!(V1[AT_RESERVED_V1..].iter().all(|&b| b == 0));
}

#[test]
fn keys() {
    assert!(valid_key(&key("a")));
    assert!(valid_key(&key("persist_ticks")));
    assert!(!valid_key(&key("")));
    assert!(!valid_key(&key("1abc")));
    assert!(!valid_key(&key("Upper")));
    assert!(!valid_key(&key("has-dash")));
    let mut gap = key("ab");
    gap[3] = b'c'; // bytes after the zero padding starts
    assert!(!valid_key(&gap));
}

#[test]
fn not_a_descriptor() {
    assert_eq!(format(&V2[..256]), None);
    assert_eq!(format(&V1[..255]), None);
    let mut wrong = [0u8; LEN_V2];
    wrong[..8].copy_from_slice(MAGIC_V1);
    assert_eq!(format(&wrong), None);
}
