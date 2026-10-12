fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/../linker.ld");
    println!("cargo:rerun-if-changed={dir}/../linker.ld");
    // Test scripts carry the slot images the Makefile builds into build/slots.
    println!("cargo:rerun-if-env-changed=VANIR_SLOTS");
    if std::env::var("VANIR_SLOTS").is_err() {
        println!("cargo:rustc-env=VANIR_SLOTS={dir}/../../build/slots");
    }
}
