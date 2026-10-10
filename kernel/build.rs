use std::fmt::Write;

use toml::{Table, Value};

include!("src/pci_kinds.rs");

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed={dir}/linker.ld");

    // The task table comes from an app manifest (VANIR_APP, default apps/default.toml), the
    // build-time list of every process the image runs. See apps/README.md for the format.
    println!("cargo:rerun-if-env-changed=VANIR_APP");
    let app = std::env::var("VANIR_APP").unwrap_or_else(|_| format!("{dir}/../apps/default.toml"));
    println!("cargo:rerun-if-changed={app}");
    let text = std::fs::read_to_string(&app).unwrap_or_else(|e| panic!("{app}: {e}"));
    let manifest: Table = text.parse().unwrap_or_else(|e| panic!("{app}: {e}"));
    let tasks = match manifest.get("task") {
        Some(Value::Array(tasks)) => tasks,
        _ => panic!("{app}: expected one or more [[task]] tables"),
    };

    let names: Vec<&str> = tasks
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap_or_else(|| panic!("{app}: task without name")))
        .collect();
    let mut supervisors = 0;
    let mut out = String::from("pub static TASKS: &[Task] = &[\n");
    for (task, name) in tasks.iter().zip(&names) {
        let task = task.as_table().unwrap();
        for key in task.keys() {
            let known = ["name", "program", "budget", "supervisor", "sends", "devices"];
            assert!(known.contains(&key.as_str()), "{app}: task {name}: unknown key {key}");
        }
        let program = task.get("program").and_then(Value::as_str).unwrap_or(name);
        let budget = task.get("budget").map_or(0, |v| v.as_integer().expect("budget: integer"));
        let supervisor = task.get("supervisor").is_some_and(|v| v.as_bool().expect("supervisor: bool"));
        supervisors += supervisor as u32;
        let sends: Vec<usize> = match task.get("sends") {
            None => vec![],
            Some(v) => v
                .as_array()
                .expect("sends: array of task names")
                .iter()
                .map(|t| {
                    let t = t.as_str().expect("sends: task names");
                    names.iter().position(|n| *n == t).unwrap_or_else(|| panic!("{app}: {name} sends to unknown task {t}"))
                })
                .collect(),
        };
        assert!(names.iter().filter(|n| *n == name).count() == 1, "{app}: duplicate task name {name}");
        // Each entry claims the next unclaimed device of that kind, in PCI discovery order.
        let devices: Vec<usize> = match task.get("devices") {
            None => vec![],
            Some(v) => v
                .as_array()
                .expect("devices: array of device names")
                .iter()
                .map(|d| {
                    let d = d.as_str().expect("devices: names");
                    KINDS.iter().position(|(k, _, _)| *k == d).unwrap_or_else(|| {
                        let known: Vec<_> = KINDS.iter().map(|(k, _, _)| *k).collect();
                        panic!("{app}: {name}: unknown device {d} (known: {known:?})")
                    })
                })
                .collect(),
        };

        let path = format!("{dir}/../build/{program}.elf");
        println!("cargo:rerun-if-changed={path}");
        writeln!(
            out,
            "    Task {{ name: {name:?}, image: include_bytes!({path:?}), budget_ticks: {budget}, \
             supervisor: {supervisor}, sends: &{sends:?}, devices: &{devices:?} }},"
        )
        .unwrap();
    }
    assert!(supervisors <= 1, "{app}: at most one supervisor");
    out.push_str("];\n");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out_dir}/tasks.rs"), out).unwrap();
}
