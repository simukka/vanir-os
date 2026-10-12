//! The cacophony test vector for Noise_IK_25519_ChaChaPoly_SHA256
//! (github.com/haskell-cryptography/cacophony, vectors/cacophony.txt), initiator side.
//! Run with `cargo test -p noise --target x86_64-unknown-linux-gnu`.

use noise::Initiator;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn key(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

#[test]
fn ik_vector() {
    let mut init = Initiator::new(key("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"), key("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"), key("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"), &hex("4a6f686e2047616c74")).unwrap();
    let mut out = vec![0u8; 1024];
    let n = init.write_message(&hex("4c756477696720766f6e204d69736573"), &mut out).unwrap();
    assert_eq!(out[..n], hex("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7")[..], "message 0");
    let mut reply = hex("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5");
    let (mut t, payload) = init.read_message(&mut reply).unwrap();
    assert_eq!(reply[payload], hex("4d757272617920526f746862617264")[..], "message 1 payload");
    assert_eq!(t.handshake_hash.to_vec(), hex("0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7"), "handshake hash");
    let p = hex("462e20412e20486179656b");
    let mut buf = vec![0u8; p.len() + 16];
    buf[..p.len()].copy_from_slice(&p);
    let n = t.send.encrypt(&[], &mut buf, p.len()).unwrap();
    assert_eq!(buf[..n], hex("050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8")[..], "transport message 2");
    let mut c = hex("344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667");
    let len = c.len();
    let n = t.recv.decrypt(&[], &mut c, len).unwrap();
    assert_eq!(c[..n], hex("4361726c204d656e676572")[..], "transport message 3");
    let p = hex("4a65616e2d426170746973746520536179");
    let mut buf = vec![0u8; p.len() + 16];
    buf[..p.len()].copy_from_slice(&p);
    let n = t.send.encrypt(&[], &mut buf, p.len()).unwrap();
    assert_eq!(buf[..n], hex("62cdeeb172ad7ade7aa7d9e069da5790f12331bfa00177787a1d0810c67dc3b2b4")[..], "transport message 4");
    let mut c = hex("029bead1b40992327044d409d9a1f3ad8f36c3c452775d557e18bbeb2e8dfcead32d514024");
    let len = c.len();
    let n = t.recv.decrypt(&[], &mut c, len).unwrap();
    assert_eq!(c[..n], hex("457567656e2042f6686d20766f6e2042617765726b")[..], "transport message 5");
    // A changed ciphertext doesn't decrypt.
    let mut c = vec![0u8; 32];
    assert!(t.recv.decrypt(&[], &mut c, 32).is_err());
}
