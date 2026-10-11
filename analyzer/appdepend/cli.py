"""Command line: appdepend analyze | check | sample"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, analysis
from .config import load_settings
from .inputs import load_collected, load_inventory, load_known, load_waves
from .model import APP, EXTERNAL, UNKNOWN_INTERNAL, build_graph
from .report import graph_json, html_table, stamp, write_excel, write_html


def _load(args):
    settings = load_settings(args.config)
    if args.group_min_persistence is not None:
        settings.group_min_persistence = args.group_min_persistence / 100
    if args.shared:
        settings.shared_vms |= {v.strip().lower() for v in args.shared.split(",") if v.strip()}
    inventory = load_inventory([Path(p) for p in args.inventory or []])
    waves = load_waves(Path(args.waves)) if args.waves else {}
    hosts = load_collected(Path(args.data))
    known = load_known(Path(args.known) if args.known else None)
    g = build_graph(inventory, waves, hosts, known, settings)
    print(f"Loaded {len(inventory)} inventory VMs, {len(hosts)} collected hosts, {len(waves)} wave assignments, "
          f"{len(known)} known endpoints -> {len(g.nodes)} nodes, {len(g.edges)} dependencies", file=sys.stderr)
    return g


def cmd_analyze(args) -> int:
    g = _load(args)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    cov = analysis.coverage(g)
    groups = analysis.move_groups(g)
    xw = analysis.cross_wave(g)
    unk = analysis.unknown_endpoints(g)
    hub = analysis.hubs(g)
    summary = analysis.wave_summary(g, cov, xw, groups)
    fw = analysis.firewall_flows(g)
    all_edges = sorted((analysis.edge_row(g, e) for e in g.edges.values()),
                       key=lambda r: (r["Category"] != APP, r["Client"].lower(), r["Server"].lower(), r["Port"]))
    services = [dict(s, VM=n.id) for n in g.vm_nodes() if n.host for s in n.host.services]
    listeners = [dict(l, VM=n.id) for n in g.vm_nodes() if n.host for l in n.host.listeners]

    write_excel(out / "dependency-report.xlsx", [
        ("Wave Summary", summary, "RED: a VM has no data, a high-latency-sensitivity dependency crosses waves, or an internal IP is unidentified. AMBER: other cross-wave dependencies, short collection, or a split move group."),
        ("Cross-Wave Deps", xw, "App dependencies whose ends are in different waves (or one end has no wave). These become on-prem <-> OCI traffic."),
        ("Move Groups", groups, "VMs connected by application traffic (shared services excluded"
         + (f", links below {g.settings.group_min_persistence:.0%} persistence ignored" if g.settings.group_min_persistence else "")
         + "). Move each group in one wave."),
        ("Unknown Endpoints", unk, "Remote IPs that are not inventoried VMs. Identify them and add them to known-endpoints.csv."),
        ("Hubs", hub, "Nodes with many app peers. Usually shared services that should be marked shared."),
        ("VM Coverage", cov, "Each VM's collection status. A VM without collector data is a blind spot, not a VM with no dependencies."),
        ("All Dependencies", all_edges, ""),
        ("Firewall Flows", fw, "Required flows per wave after cutover: input for OCI NSG / Security Lists and on-prem firewall rules."),
        ("Listeners", listeners, ""),
        ("Services", services, "Running non-Windows services: helps identify the application on each VM."),
        ("Warnings", [{"Warning": w} for w in g.warnings], ""),
    ])

    vms = g.vm_nodes()
    cards = [
        ("VMs in scope", len(vms)), ("VMs with collector data", sum(1 for n in vms if n.collected)),
        ("Waves", len(g.waves())), ("App dependencies", sum(1 for e in g.edges.values() if e.category == APP)),
        ("Cross-wave deps", len(xw)), ("High-risk cross-wave", sum(1 for r in xw if r["Risk"] == "High")),
        ("Split move groups", sum(1 for r in groups if r["Status"] != "OK")),
        ("Unknown internal IPs", sum(1 for n in g.nodes.values() if n.kind == UNKNOWN_INTERNAL)),
        ("Internet endpoints", sum(1 for n in g.nodes.values() if n.kind == EXTERNAL)),
    ]
    write_html(out / "dependency-report.html", "Application Dependency Report",
               f"vSphere -> AIS Cloud (OCI) wave planning · generated {stamp()} · appdepend {__version__}", cards, [
                   ("Wave readiness", html_table("t-sum", summary)),
                   ("Cross-wave dependencies", html_table("t-xw", xw)),
                   ("Move groups", html_table("t-mg", groups)),
                   ("Unknown endpoints", html_table("t-unk", unk)),
                   ("Hubs / shared-service candidates", html_table("t-hub", hub)),
                   ("VM coverage", html_table("t-cov", cov)),
               ], graph_json(g), g.warnings)
    (out / "graph.json").write_text(json.dumps(graph_json(g), indent=1), encoding="utf-8")

    print(f"Report written to {out.resolve()}  (dependency-report.html, dependency-report.xlsx, graph.json)")
    for r in summary:
        print(f"  {r['Wave']:<16} {r['Status']:<6} VMs={r['VMs']:<4} no-data={r['Not Collected']:<3} "
              f"cross-wave={r['Cross-Wave Deps']:<4} high-risk={r['High-Risk Cross-Wave']:<3} unknown-IPs={r['Unknown Internal Endpoints']}")
    return 0


def cmd_check(args) -> int:
    g = _load(args)
    lookup = {n.id.lower(): n.id for n in g.vm_nodes()}
    selected, missing = set(), []
    names: list[str] = []
    if args.vms:
        names += [v for v in args.vms.split(",")]
    if args.vms_file:
        names += [l for l in Path(args.vms_file).read_text(encoding="utf-8-sig").splitlines() if not l.startswith("#")]
    for v in (x.strip() for x in names):
        if not v:
            continue
        (selected.add(lookup[v.lower()]) if v.lower() in lookup else missing.append(v))
    if args.wave:
        wave_vms = {n.id for n in g.vm_nodes() if n.wave.lower() == args.wave.lower()}
        if not wave_vms:
            print(f"No VMs in wave '{args.wave}'. Known waves: {', '.join(g.waves()) or '(none)'}", file=sys.stderr)
            return 2
        selected |= wave_vms
        args.wave = next(w for w in g.waves() if w.lower() == args.wave.lower())
    for m in missing:
        g.warnings.insert(0, f"Selected VM '{m}' is not in the inventory or collected data.")
    if not selected:
        print("Nothing selected. Use --wave, --vms or --vms-file.", file=sys.stderr)
        return 2

    res = analysis.check_selection(g, selected, args.wave)
    name = args.name or (args.wave or "selection").replace(" ", "_")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    deps = res["dependencies"]
    app = [d for d in deps if d["Category"] == APP]
    write_excel(out / f"check-{name}.xlsx", [
        ("Selected VMs", res["selected"], ""),
        ("Dependencies", deps, "Every flow crossing the selection boundary, with a verdict."),
        ("Suggested Additions", res["closure"], "VMs to add so that no application dependency crosses the boundary (Hops=1: direct peers)."),
        ("Warnings", [{"Warning": w} for w in g.warnings], ""),
    ])
    cards = [
        ("Selected VMs", len(selected)), ("Without collector data", sum(1 for r in res["selected"] if r["Collected"] != "yes")),
        ("Flows inside selection", res["internal_edges"]), ("App deps crossing boundary", len(app)),
        ("Unknown IPs to identify", len({d["Peer"] for d in app if d["Verdict"].startswith("IDENTIFY")})),
        ("Direct VM peers to consider", sum(1 for c in res["closure"] if c["Hops"] == 1)),
    ]
    write_html(out / f"check-{name}.html", f"Dependency Check: {args.wave or name}",
               f"Selection boundary analysis · generated {stamp()}", cards, [
                   ("Selected VMs", html_table("t-sel", res["selected"])),
                   ("Dependencies crossing the boundary", html_table("t-dep", deps, cols=[
                       "Selected VM", "Direction", "Peer", "Peer Wave", "Port", "Service", "Category",
                       "Latency Sensitivity", "Persistence %", "Processes", "Verdict"])),
                   ("Suggested additions (transitive)", html_table("t-clo", res["closure"])),
               ], graph_json(g, node_filter=selected), g.warnings)

    print(f"Check written to {out.resolve()}/check-{name}.html and .xlsx")
    print(f"  {len(selected)} selected, {res['internal_edges']} internal flows, {len(app)} app deps cross the boundary, "
          f"{sum(1 for c in res['closure'] if c['Hops'] == 1)} direct VM peers outside the selection")
    for c in [c for c in res["closure"] if c["Hops"] == 1][:20]:
        print(f"    + {c['VM']:<24} (wave: {c['Current Wave']}, linked to {c['Linked To']})")
    return 0


def cmd_sample(args) -> int:
    from .sample import generate

    generate(Path(args.out))
    print(f"Sample data written to {Path(args.out).resolve()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="appdepend", description="Application dependency analysis for VM migration wave planning.")
    p.add_argument("--version", action="version", version=f"appdepend {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-d", "--data", required=True, help="folder with collector CSVs (searched recursively)")
        sp.add_argument("-i", "--inventory", action="append", help="RVTools .xlsx or inventory CSV (repeatable)")
        sp.add_argument("-w", "--waves", help="wave plan CSV: VM,Wave[,Date,Application]")
        sp.add_argument("-k", "--known", help="known endpoints CSV: CIDR,Label,Category[,Note]")
        sp.add_argument("-c", "--config", help="JSON settings (ports, shared VMs, ignores)")
        sp.add_argument("--shared", help="comma-separated VM names to treat as shared services")
        sp.add_argument("--group-min-persistence", type=float, metavar="PCT",
                        help="only links seen in at least PCT%% of samples bind VMs into move groups (default 0)")
        sp.add_argument("-o", "--out", default="report", help="output folder (default: ./report)")

    a = sub.add_parser("analyze", help="full report: wave readiness, cross-wave deps, move groups, unknown IPs, firewall flows")
    common(a)
    a.set_defaults(func=cmd_analyze)

    c = sub.add_parser("check", help="dependencies of one wave or an ad-hoc VM selection")
    common(c)
    c.add_argument("--wave", help="wave name from the wave plan")
    c.add_argument("--vms", help="comma-separated VM names")
    c.add_argument("--vms-file", help="file with one VM name per line")
    c.add_argument("--name", help="output file suffix")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("sample", help="generate a synthetic demo dataset")
    s.add_argument("-o", "--out", default="samples")
    s.set_defaults(func=cmd_sample)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
