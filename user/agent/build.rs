fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/../linker.ld");
    println!("cargo:rerun-if-changed={dir}/../linker.ld");
    // Test scripts carry the slot images the Makefile builds into build/slots.
    println!("cargo:rerun-if-env-changed=VANIR_SLOTS");
    if std::env::var("VANIR_SLOTS").is_err() {
        println!("cargo:rustc-env=VANIR_SLOTS={dir}/../../build/slots");
    }
    // The control plane: where to dial, and its two keys, pinned in the image (RFD 2, P7). The
    // Makefile makes dev keys (keys/cp-*) on the first build.
    for (var, default) in [("VANIR_CP_PUB", "keys/cp-noise.pub"), ("VANIR_CP_SIGN_PUB", "keys/cp-sign.pub")] {
        println!("cargo:rerun-if-env-changed={var}");
        let path = std::env::var(var).unwrap_or_else(|_| format!("{dir}/../../{default}"));
        assert!(std::fs::metadata(&path).is_ok_and(|m| m.len() == 32), "{path}: need a 32-byte public key (make keys)");
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:rustc-env={var}={path}");
    }
    // The node's name in reports (tests run two nodes from one tree). A real fleet would name
    // a node by its TPM's attestation key instead.
    println!("cargo:rerun-if-env-changed=VANIR_NODE");
    let node = std::env::var("VANIR_NODE").unwrap_or_else(|_| "a".into());
    println!("cargo:rustc-env=VANIR_NODE={node}");
    println!("cargo:rerun-if-env-changed=VANIR_CP_ADDR");
    let addr = std::env::var("VANIR_CP_ADDR").unwrap_or_else(|_| "10.0.2.2:7000".into());
    println!("cargo:rustc-env=VANIR_CP_ADDR={addr}");
}
