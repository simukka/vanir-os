fn main() {
    // The linker script is for a slot's image only: `cargo test` on the host links normally.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        let dir = env!("CARGO_MANIFEST_DIR");
        println!("cargo:rustc-link-arg=-T{dir}/../linker.ld");
    }
    println!("cargo:rerun-if-changed=../linker.ld");
}
