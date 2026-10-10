fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/../linker.ld");
    println!("cargo:rerun-if-changed={dir}/../linker.ld");
}
