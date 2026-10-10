# App manifests

An app manifest lists every process the kernel runs, fixed at build time. Pick one with
`make run APP=apps/<name>.toml` (default `apps/default.toml`); tests use `tests/apps/`.

```toml
[[task]]
name = "client"        # unique task name; also the program, unless `program` is set
program = "hello"      # optional: build/<program>.elf (any program under user/)
budget = 50            # optional: CPU budget in 10 ms timer ticks (default: unlimited)
supervisor = true      # optional: this task is told when others die (at most one)
sends = ["echo"]       # optional: tasks this one may send IPC messages to
```

Tasks get ids 1, 2, ... in manifest order.
