use std::fmt::Write;

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed={dir}/linker.ld");

    // The static task table: VANIR_TASKS="hello spinner:50" runs hello, then spinner with a CPU
    // budget of 50 timer ticks (0 or absent = unlimited). The Makefile builds each program into
    // build/<name>.elf first.
    println!("cargo:rerun-if-env-changed=VANIR_TASKS");
    let spec = std::env::var("VANIR_TASKS").unwrap_or_else(|_| "hello".into());
    let mut out = String::from("pub static TASKS: &[Task] = &[\n");
    for item in spec.split_whitespace() {
        let (name, budget) = item.split_once(':').unwrap_or((item, "0"));
        let budget: u64 = budget.parse().expect("VANIR_TASKS budget must be a number");
        let path = format!("{dir}/../build/{name}.elf");
        println!("cargo:rerun-if-changed={path}");
        writeln!(
            out,
            "    Task {{ name: {name:?}, image: include_bytes!({path:?}), budget_ticks: {budget} }},"
        )
        .unwrap();
    }
    out.push_str("];\n");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out_dir}/tasks.rs"), out).unwrap();
}
