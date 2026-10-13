#!/usr/bin/env python3
"""Draw a load test's per-second samples (the CSV tools/net-peer.py count-load writes) as an SVG:
time along the x axis, one panel each for the request rate, clients, latency, CPU, memory and
I/O.

  bench-chart.py SAMPLES.csv [-o OUT.svg]     (default: the CSV's name with .svg)
"""
import argparse
import csv
import os

WIDTH, PANEL, GAP, LEFT, RIGHT, TOP = 900, 120, 46, 70, 170, 60
COLORS = ["#2563eb", "#dc2626", "#16a34a", "#9333ea", "#ea580c", "#0891b2", "#be185d", "#65a30d"]


def nice_max(v):
    """A round number at or above v, for the y axis."""
    if v <= 0:
        return 1
    m = 10 ** (len(str(int(v))) - 1)
    for step in (1, 2, 2.5, 5, 10):
        if step * m >= v:
            return step * m
    return 10 * m


def panel(rows, y0, title, series, unit, step=False, ymax=None):
    xs = [float(r["second"]) for r in rows]
    x_max = max(xs) if xs else 1
    top = ymax or nice_max(max((float(r[c]) for c, _ in series for r in rows if r.get(c)), default=0))
    w = WIDTH - LEFT - RIGHT

    def px(x):
        return LEFT + w * x / x_max

    def py(v):
        return y0 + PANEL - PANEL * min(v, top) / top

    out = [f'<text x="{LEFT}" y="{y0 - 8}" class="title">{title}</text>',
           f'<rect x="{LEFT}" y="{y0}" width="{w}" height="{PANEL}" class="frame"/>']
    for k in range(5):
        v = top * k / 4
        y = py(v)
        out.append(f'<line x1="{LEFT}" x2="{LEFT + w}" y1="{y:.1f}" y2="{y:.1f}" class="grid"/>')
        label = f"{v:g}"
        out.append(f'<text x="{LEFT - 6}" y="{y + 4:.1f}" class="tick" text-anchor="end">{label}</text>')
    out.append(f'<text x="{LEFT - 6}" y="{y0 - 8}" class="tick" text-anchor="end">{unit}</text>')
    for i, (col, name) in enumerate(series):
        color = COLORS[i % len(COLORS)]
        pts = []
        for r in rows + [{}]:
            if not r.get(col):  # not sampled (e.g. before the guest's first heartbeat): a gap
                if pts:
                    out.append(f'<polyline points="{" ".join(pts)}" fill="none" stroke="{color}" stroke-width="1.6"/>')
                pts = []
                continue
            x, v = px(float(r["second"])), py(float(r[col]))
            if step and pts:
                pts.append(f"{x - w / x_max:.1f},{pts[-1].split(',')[1]}")
            pts.append(f"{x:.1f},{v:.1f}")
        ly = y0 + 12 + 16 * i
        out.append(f'<line x1="{LEFT + w + 12}" x2="{LEFT + w + 30}" y1="{ly - 4}" y2="{ly - 4}" stroke="{color}" stroke-width="2"/>')
        out.append(f'<text x="{LEFT + w + 36}" y="{ly}" class="legend">{name}</text>')
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("csv")
    p.add_argument("-o", "--out")
    args = p.parse_args()
    with open(args.csv) as f:
        rows = list(csv.DictReader(f))
    cols = rows[0].keys() if rows else []
    tasks = sorted((c for c in cols if c.startswith("cpu_") and c != "cpu_pct"),
                   key=lambda c: -max(float(r.get(c) or 0) for r in rows))
    tasks = [c for c in tasks if max(float(r.get(c) or 0) for r in rows) >= 1][:6]
    panels = [
        ("Requests per second", [("requests_s", "requests/s")], "req/s", False, None),
        ("Clients", [("clients", "clients")], "", True, None),
        ("Latency", [("p50_ms", "p50"), ("p99_ms", "p99")], "ms", False, None),
        ("CPU (guest: ticks charged to tasks)", [("cpu_pct", "all tasks")] + [(c, c[4:]) for c in tasks], "%", False, 100),
        ("Memory (guest frames in use)", [("mem_mib", "MiB used")], "MiB", False, None),
        ("I/O", [("disk_write_kib_s", "disk write"), ("disk_read_kib_s", "disk read"),
                 ("net_rx_kib_s", "net rx"), ("net_tx_kib_s", "net tx")], "KiB/s", False, None),
    ]
    height = TOP + len(panels) * (PANEL + GAP) + 20
    body = []
    for i, (title, series, unit, step, ymax) in enumerate(panels):
        body += panel(rows, TOP + i * (PANEL + GAP), title, [s for s in series if s[0] in cols], unit, step, ymax)
    x_max = max((float(r["second"]) for r in rows), default=1)
    w = WIDTH - LEFT - RIGHT
    y = TOP + len(panels) * (PANEL + GAP) - GAP + 16
    for k in range(7):
        x = x_max * k / 6
        body.append(f'<text x="{LEFT + w * k / 6:.1f}" y="{y}" class="tick" text-anchor="middle">{x:.0f}s</text>')
    name = os.path.splitext(os.path.basename(args.csv))[0]
    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" viewBox="0 0 {WIDTH} {height}">',
           "<style>text{font:12px sans-serif;fill:#222}.title{font-weight:600}.tick{fill:#666;font-size:11px}"
           ".legend{font-size:11px}.frame{fill:none;stroke:#bbb}.grid{stroke:#eee}</style>",
           f'<rect width="{WIDTH}" height="{height}" fill="#fff"/>',
           f'<text x="{LEFT}" y="22" class="title" style="font-size:15px">{name}: one sample a second</text>', *body, "</svg>"]
    out = args.out or os.path.splitext(args.csv)[0] + ".svg"
    with open(out, "w") as f:
        f.write("\n".join(svg) + "\n")
    print(out)


if __name__ == "__main__":
    main()
