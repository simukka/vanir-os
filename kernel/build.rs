use std::fmt::Write;

use toml::{Table, Value};

include!("src/pci_kinds.rs");

fn main() {
    let dir = env!("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed={dir}/linker.ld");

    // The key task images must be signed with (tools/sign-image.py; the Makefile makes a dev key).
    println!("cargo:rerun-if-env-changed=VANIR_SIGNING_PUB");
    let public_key = std::env::var("VANIR_SIGNING_PUB").unwrap_or_else(|_| format!("{dir}/../keys/dev-signing.pub"));
    assert!(std::fs::metadata(&public_key).is_ok_and(|m| m.len() == 32), "{public_key}: need a 32-byte Ed25519 public key (make keys)");
    println!("cargo:rerun-if-changed={public_key}");
    println!("cargo:rustc-env=VANIR_SIGNING_PUB={public_key}");

    // The task table comes from an app manifest (VANIR_APP, default apps/default.toml), the
    // build-time list of every process the image runs. See apps/README.md for the format.
    println!("cargo:rerun-if-env-changed=VANIR_APP");
    let app = std::env::var("VANIR_APP").unwrap_or_else(|_| format!("{dir}/../apps/default.toml"));
    println!("cargo:rerun-if-changed={app}");
    let text = std::fs::read_to_string(&app).unwrap_or_else(|e| panic!("{app}: {e}"));
    let manifest: Table = text.parse().unwrap_or_else(|e| panic!("{app}: {e}"));
    for key in manifest.keys() {
        assert!(["task", "slot_class", "runtime_log"].contains(&key.as_str()), "{app}: unknown top-level key {key}");
    }
    let tasks = match manifest.get("task") {
        Some(Value::Array(tasks)) => tasks,
        _ => panic!("{app}: expected one or more [[task]] tables"),
    };
    // Length of the kernel's run-time measurement log (RFD 2, P6): loads refused once it's full.
    let runtime_log = manifest.get("runtime_log").map_or(1024, |v| v.as_integer().expect("runtime_log: integer"));
    assert!((1..=65536).contains(&runtime_log), "{app}: runtime_log must be 1..=65536");

    let names: Vec<&str> = tasks
        .iter()
        .map(|t| t.get("name").and_then(Value::as_str).unwrap_or_else(|| panic!("{app}: task without name")))
        .collect();
    let mut supervisors = 0;
    let mut readers = 0;
    let mut tpm_users = 0;
    let mut loaders = 0;
    // (port, task, service) for every listen declaration so far.
    let mut ports: Vec<(u16, String, String)> = vec![];
    let mut out = String::from("pub static TASKS: &[Task] = &[\n");
    for (task, name) in tasks.iter().zip(&names) {
        let task = task.as_table().unwrap();
        for key in task.keys() {
            let known = [
                "name", "program", "budget", "supervisor", "sends", "devices", "dma_pages", "events", "min_version", "tpm", "service",
                "listen", "routes", "loads", "connects",
            ];
            assert!(known.contains(&key.as_str()), "{app}: task {name}: unknown key {key}");
        }
        let program = task.get("program").and_then(Value::as_str).unwrap_or(name);
        let budget = task.get("budget").map_or(0, |v| v.as_integer().expect("budget: integer"));
        let min_version = task.get("min_version").map_or(0, |v| v.as_integer().expect("min_version: integer"));
        let dma_pages = task.get("dma_pages").map_or(0, |v| v.as_integer().expect("dma_pages: integer"));
        assert!((0..=256).contains(&dma_pages), "{app}: {name}: dma_pages must be 0..=256");
        let supervisor = task.get("supervisor").is_some_and(|v| v.as_bool().expect("supervisor: bool"));
        supervisors += supervisor as u32;
        let events = task.get("events").is_some_and(|v| v.as_bool().expect("events: bool"));
        let tpm = task.get("tpm").is_some_and(|v| v.as_bool().expect("tpm: bool"));
        tpm_users += tpm as u32;
        readers += events as u32;
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

        // Network services: the service this task is an instance of, and the TCP ports it may
        // listen on (`net` asks the kernel, so a task can't claim ports it wasn't given).
        let service = task.get("service").map_or(*name, |v| v.as_str().expect("service: string"));
        assert!(!service.is_empty() && service.len() <= 32, "{app}: {name}: service name must be 1..=32 bytes");
        let routes = task.get("routes").is_some_and(|v| v.as_bool().expect("routes: bool"));
        let loads = task.get("loads").is_some_and(|v| v.as_bool().expect("loads: bool"));
        loaders += loads as u32;
        let connects = task.get("connects").is_some_and(|v| v.as_bool().expect("connects: bool"));
        let listen: Vec<(u16, u16, u16)> = match task.get("listen") {
            None => vec![],
            Some(v) => v
                .as_array()
                .expect("listen: array of { port = N, max_connections = N }")
                .iter()
                .map(|entry| {
                    let entry = entry.as_table().unwrap_or_else(|| panic!("{app}: {name}: listen entries are tables"));
                    for key in entry.keys() {
                        let known = ["port", "max_connections", "max_per_source"];
                        assert!(known.contains(&key.as_str()), "{app}: {name}: listen: unknown key {key}");
                    }
                    let int = |key: &str, default: Option<i64>, range: std::ops::RangeInclusive<i64>| {
                        let v = entry.get(key).map(|v| v.as_integer().unwrap_or_else(|| panic!("{app}: {name}: listen: {key} must be an integer")));
                        let v = v.or(default).unwrap_or_else(|| panic!("{app}: {name}: listen entry without {key}"));
                        assert!(range.contains(&v), "{app}: {name}: listen: {key} = {v} is outside {range:?}");
                        v as u16
                    };
                    let max = int("max_connections", Some(64), 1..=1024);
                    (int("port", None, 1..=65535), max, int("max_per_source", Some(max as i64), 1..=max as i64))
                })
                .collect(),
        };
        assert!(listen.len() <= 8, "{app}: {name}: at most 8 listen entries");
        for (i, (port, ..)) in listen.iter().enumerate() {
            assert!(!listen[..i].iter().any(|l| l.0 == *port), "{app}: {name}: port {port} listed twice");
            if let Some((other, other_service)) = ports.iter().find(|(p, _, _)| p == port).map(|(_, n, s)| (n, s))
                && *other_service != service
            {
                panic!(
                    "{app}: port {port} is declared by {other} (service {other_service}) and {name} (service {service}); \
                     only instances of one service may share a port"
                );
            }
            ports.push((*port, name.to_string(), service.to_string()));
        }
        let listen: Vec<String> = listen
            .iter()
            .map(|(port, max, per_source)| format!("Listen {{ port: {port}, max_connections: {max}, max_per_source: {per_source} }}"))
            .collect();

        writeln!(
            out,
            "    Task {{ name: {name:?}, program: {program:?}, budget_ticks: {budget}, \
             supervisor: {supervisor}, sends: &{sends:?}, devices: &{devices:?}, dma_pages: {dma_pages}, events: {events}, min_version: {min_version}, tpm: {tpm}, \
             service: {service:?}, listen: &[{}], routes: {routes}, loads: {loads}, connects: {connects}, class: None }},",
            listen.join(", ")
        )
        .unwrap();
    }

    // Generic slots (RFD 2, P1): each class becomes `count` table entries named <class>-<i>, after
    // the tasks. A slot runs whatever signed service image the task with `loads = true` puts in it.
    let mut classes = String::from("pub static SLOT_CLASSES: &[SlotClass] = &[\n");
    let mut slots = 0;
    let class_list = match manifest.get("slot_class") {
        None => &vec![],
        Some(v) => v.as_array().expect("[[slot_class]] tables"),
    };
    let mut class_names: Vec<&str> = vec![];
    for (index, class) in class_list.iter().enumerate() {
        let class = class.as_table().expect("[[slot_class]] tables");
        for key in class.keys() {
            let known = ["name", "count", "memory_pages", "image_pages", "budget", "sends"];
            assert!(known.contains(&key.as_str()), "{app}: slot_class: unknown key {key}");
        }
        let name = class.get("name").and_then(Value::as_str).unwrap_or_else(|| panic!("{app}: slot_class without name"));
        assert!(!name.is_empty() && name.len() <= 16, "{app}: slot class name {name:?} must be 1..=16 bytes");
        assert!(!class_names.contains(&name), "{app}: duplicate slot class {name}");
        class_names.push(name);
        let int = |key: &str, range: std::ops::RangeInclusive<i64>| {
            let v = class.get(key).unwrap_or_else(|| panic!("{app}: slot class {name}: no {key}"));
            let v = v.as_integer().unwrap_or_else(|| panic!("{app}: slot class {name}: {key} must be an integer"));
            assert!(range.contains(&v), "{app}: slot class {name}: {key} = {v} is outside {range:?}");
            v
        };
        let count = int("count", 1..=32);
        let memory_pages = int("memory_pages", 32..=1 << 20);
        let image_pages = int("image_pages", 1..=4096);
        let budget = class.get("budget").map_or(0, |v| v.as_integer().expect("budget: integer"));
        let sends: Vec<usize> = match class.get("sends") {
            None => vec![],
            Some(v) => v
                .as_array()
                .expect("sends: array of task names")
                .iter()
                .map(|t| {
                    let t = t.as_str().expect("sends: task names");
                    names.iter().position(|n| *n == t).unwrap_or_else(|| panic!("{app}: slot class {name} sends to unknown task {t}"))
                })
                .collect(),
        };
        writeln!(classes, "    SlotClass {{ name: {name:?}, memory_pages: {memory_pages}, image_pages: {image_pages} }},").unwrap();
        for i in 0..count {
            let slot = format!("{name}-{i}");
            assert!(!names.contains(&slot.as_str()), "{app}: slot {slot} has the name of a task");
            writeln!(
                out,
                "    Task {{ name: {slot:?}, program: \"\", budget_ticks: {budget}, supervisor: false, sends: &{sends:?}, devices: &[], \
                 dma_pages: 0, events: false, min_version: 0, tpm: false, service: \"\", listen: &[], routes: false, loads: false, \
                 connects: false, class: Some(&SLOT_CLASSES[{index}]) }},"
            )
            .unwrap();
            slots += 1;
        }
    }
    classes.push_str("];\n");
    let total = tasks.len() + slots;
    assert!(total <= 64, "{app}: {total} tasks and slots; at most 64");
    assert!(supervisors <= 1, "{app}: at most one supervisor");
    assert!(readers <= 1, "{app}: at most one task may read the event log");
    assert!(tpm_users <= 1, "{app}: at most one task may use the TPM");
    assert!(loaders <= 1, "{app}: at most one task may load images");
    out.push_str("];\n");
    out.push_str(&classes);
    out.push_str(&format!("pub const MAX_PROCESSES: usize = {total};\n"));
    out.push_str(&format!("pub const RUNTIME_LOG: usize = {runtime_log};\n"));
    // The manifest itself, measured into the TPM at boot.
    out.push_str(&format!("pub static MANIFEST: &str = include_str!({app:?});\n"));
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(format!("{out_dir}/tasks.rs"), out).unwrap();
}
