"""Wave-planning analyses over a dependency Graph. Every function returns plain
lists of dicts (ordered columns), which the Excel/HTML writers render as-is."""

from __future__ import annotations

from collections import Counter, defaultdict, deque

from .inputs import natural_key
from .model import ADMIN, APP, EXTERNAL, INFRA, KNOWN, UNKNOWN_INTERNAL, Edge, Graph, Node

SENS_RANK = {"High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _procs(e: Edge) -> str:
    parts = []
    if e.client_processes:
        parts.append("client: " + ", ".join(sorted(e.client_processes)))
    if e.server_processes:
        parts.append("server: " + ", ".join(sorted(e.server_processes)))
    return "; ".join(parts)


def _kind_label(n: Node) -> str:
    return {
        "vm": "VM" if (n.vm and n.vm.in_inventory) else "VM (not in inventory)",
        KNOWN: f"Known: {n.known.category}" if n.known else "Known",
        UNKNOWN_INTERNAL: "Unknown internal IP",
        EXTERNAL: "Internet",
    }.get(n.kind, n.kind)


def edge_row(g: Graph, e: Edge, **extra) -> dict:
    c, s = g.nodes[e.client], g.nodes[e.server]
    row = {
        "Client": e.client, "Client Wave": c.wave, "Server": e.server, "Server Wave": s.wave,
        "Server Type": _kind_label(s), "Port": e.port, "Service": e.service,
        "Category": e.category, "Latency Sensitivity": e.sensitivity, "Processes": _procs(e),
        "Persistence %": round(e.persistence * 100, 1), "Samples": e.samples, "Max Concurrent": e.max_concurrent,
        "Seen By": "+".join(sorted(e.observed_by)), "First Seen": e.first_seen, "Last Seen": e.last_seen,
        "Failed Only": "yes" if e.failed_only else "",
    }
    row.update(extra)
    return row


def wave_index(g: Graph) -> dict[str, int]:
    return {w: i for i, w in enumerate(g.waves())}


def _app_edges(g: Graph, include_failed: bool = False):
    for e in g.edges.values():
        if e.category == APP and (include_failed or not e.failed_only):
            yield e


# ---------------------------------------------------------------- coverage


def coverage(g: Graph) -> list[dict]:
    rows = []
    for n in sorted(g.vm_nodes(), key=lambda n: (natural_key(n.wave or "~"), n.id.lower())):
        vm = n.vm
        days = n.host.days if n.host else 0
        issues = []
        if not n.collected:
            issues.append("NO COLLECTOR DATA: dependencies unknown")
        elif days < g.settings.min_collection_days:
            issues.append(f"Short collection ({days:.1f} d < {g.settings.min_collection_days:g} d)")
        if not vm.in_inventory:
            issues.append("Not in inventory")
        app_edges = [e for e in g.edges_of(n.id) if e.category == APP]
        rows.append({
            "VM": n.id, "Wave": n.wave, "Application": vm.application, "OS": vm.os, "Power": vm.power,
            "IPs": ", ".join(sorted(n.ips)), "Shared Service": "yes" if n.is_shared(g.settings) else "",
            "Collected": "yes" if n.collected else "no", "Collection Days": round(days, 1),
            "Samples": n.host.samples if n.host else 0,
            "App Deps Out": sum(1 for e in app_edges if e.client == n.id),
            "App Deps In": sum(1 for e in app_edges if e.server == n.id),
            "Issues": "; ".join(issues),
        })
    return rows


# ---------------------------------------------------------------- move groups


def move_groups(g: Graph) -> list[dict]:
    """Connected components over application edges between VMs (shared services,
    infra/admin ports and links below group_min_persistence excluded). A group that
    spans several waves is a planning risk."""
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    vm_ids = {n.id for n in g.vm_nodes() if not n.is_shared(g.settings)}
    for vid in vm_ids:
        find(vid)
    for e in _app_edges(g):
        if e.client in vm_ids and e.server in vm_ids and e.persistence >= g.settings.group_min_persistence:
            parent[find(e.client)] = find(e.server)

    comps: dict[str, list[str]] = defaultdict(list)
    for vid in vm_ids:
        comps[find(vid)].append(vid)

    windex = wave_index(g)
    groups = []
    for members in comps.values():
        if len(members) < 2:
            continue
        members.sort(key=str.lower)
        waves = Counter(g.nodes[m].wave for m in members if g.nodes[m].wave)
        unassigned = [m for m in members if not g.nodes[m].wave]
        suggested = ""
        if waves:
            suggested = sorted(waves.items(), key=lambda kv: (-kv[1], windex.get(kv[0], 99)))[0][0]
        move = [m for m in members if g.nodes[m].wave and g.nodes[m].wave != suggested]
        groups.append({
            "members": members, "waves": waves, "suggested": suggested, "move": move, "unassigned": unassigned,
            "split": len(waves) > 1 or (bool(waves) and bool(unassigned)),
            "apps": sorted({g.nodes[m].vm.application for m in members if g.nodes[m].vm.application}),
        })
    groups.sort(key=lambda gr: (not gr["split"], -len(gr["members"])))
    rows = []
    for i, gr in enumerate(groups, 1):
        note = ""
        if len(gr["members"]) >= g.settings.large_group_size:
            note = "Very large group: probably held together by a shared service. Check the Hubs sheet and mark shared VMs."
        rows.append({
            "Group": f"MG-{i:03d}", "Size": len(gr["members"]), "Status": "SPLIT ACROSS WAVES" if gr["split"] else "OK",
            "Waves": ", ".join(f"{w} ({c})" for w, c in sorted(gr["waves"].items(), key=lambda kv: natural_key(kv[0]))),
            "Suggested Wave": gr["suggested"],
            "VMs To Re-wave": ", ".join(gr["move"]), "Unassigned VMs": ", ".join(gr["unassigned"]),
            "Applications": ", ".join(gr["apps"]), "Members": ", ".join(gr["members"]), "Note": note,
        })
    return rows


# ---------------------------------------------------------------- wave checks


def cross_wave(g: Graph) -> list[dict]:
    """App dependencies whose two ends are in different waves, or where one end is
    not scheduled. Each one becomes on-prem <-> OCI traffic for some period."""
    windex = wave_index(g)
    rows = []
    for e in _app_edges(g, include_failed=True):
        c, s = g.nodes[e.client], g.nodes[e.server]
        if not (c.is_vm and s.is_vm) or c.wave == s.wave or not (c.wave or s.wave):
            continue
        if c.wave and s.wave:
            first, last = sorted([c.wave, s.wave], key=lambda w: windex[w])
            impact = f"Hybrid traffic from {first} cutover until {last} cutover"
        else:
            unplanned = e.server if not s.wave else e.client
            impact = f"{unplanned} has no wave: permanent hybrid traffic unless it gets scheduled"
        risk = "Info" if e.failed_only else e.sensitivity
        rows.append(edge_row(g, e, Risk=risk, Impact=impact))
    rows.sort(key=lambda r: (-SENS_RANK[r["Risk"]], natural_key(r["Client Wave"] or "~"), r["Client"]))
    return rows


def unknown_endpoints(g: Graph) -> list[dict]:
    """Remote IPs that are not inventoried VMs. Each needs a decision: identify it,
    add it to known-endpoints.csv, or plan the connectivity."""
    agg: dict[str, dict] = {}
    for e in g.edges.values():
        for this, other, direction in ((e.server, e.client, "VMs connect to it"), (e.client, e.server, "it connects to VMs")):
            n = g.nodes[this]
            if n.kind not in (UNKNOWN_INTERNAL, EXTERNAL, KNOWN):
                continue
            a = agg.setdefault(this, {"node": n, "peers": set(), "ports": set(), "dirs": set(), "cats": set(), "waves": set(),
                                      "sens": "Low", "established": False})
            a["established"] |= not e.failed_only
            a["peers"].add(other)
            a["ports"].add(e.port)
            a["dirs"].add(direction)
            a["cats"].add(e.category)
            if g.nodes[other].wave:
                a["waves"].add(g.nodes[other].wave)
            if SENS_RANK[e.sensitivity] > SENS_RANK[a["sens"]] and e.category == APP:
                a["sens"] = e.sensitivity
    order = {UNKNOWN_INTERNAL: 0, KNOWN: 1, EXTERNAL: 2}
    ranked = []
    for node_id, a in agg.items():
        n = a["node"]
        if n.kind == EXTERNAL:
            action = ("Internet egress: check OCI NAT/egress rules and partner allow-lists for the new public source IP"
                      if "VMs connect to it" in a["dirs"] else
                      "Inbound from the internet: needs public IP/LB, DNS and WAF changes in OCI")
        elif n.kind == KNOWN:
            action = f"Known endpoint ({n.known.category}): plan reachability from OCI" + (f". {n.known.note}" if n.known.note else "")
        elif not a["established"]:
            action = "Connection attempts only, never established: stale config pointing at a dead host? Clean up before migrating"
        else:
            action = "IDENTIFY: physical server, appliance, VIP or non-inventoried VM?"
        ranked.append((order[n.kind], -len(a["peers"]), n.label, {
            "Endpoint": n.label, "Type": _kind_label(n), "IPs": ", ".join(sorted(n.ips)),
            "Ports": ", ".join(str(p) for p in sorted(a["ports"])),
            "Directions": ", ".join(sorted(a["dirs"])), "Categories": ", ".join(sorted(a["cats"])),
            "Max Sensitivity": a["sens"], "Peer Count": len(a["peers"]),
            "Peers": ", ".join(sorted(a["peers"], key=str.lower)),
            "Peer Waves": ", ".join(sorted(a["waves"], key=natural_key)), "Action": action,
        }))
    return [r for *_, r in sorted(ranked, key=lambda t: t[:3])]


def hubs(g: Graph) -> list[dict]:
    """Nodes with many distinct application peers. They are usually shared services
    (central SQL, file server, middleware) that glue unrelated apps into one move group."""
    peers: dict[str, set[str]] = defaultdict(set)
    ports: dict[str, Counter] = defaultdict(Counter)
    for e in _app_edges(g):
        peers[e.client].add(e.server)
        peers[e.server].add(e.client)
        ports[e.server][e.port] += 1
    rows = []
    for nid, ps in sorted(peers.items(), key=lambda kv: -len(kv[1])):
        if len(ps) < g.settings.hub_min_peers:
            break
        n = g.nodes[nid]
        rows.append({
            "Node": n.label, "Type": _kind_label(n), "Wave": n.wave, "Distinct App Peers": len(ps),
            "Top Server Ports": ", ".join(f"{p} ({g.settings.service_name(p)})" for p, _ in ports[nid].most_common(5)),
            "Marked Shared": "yes" if n.is_shared(g.settings) else "",
            "Suggestion": "Shared service? Set Role=shared in the inventory or add it to shared_vms. Then move it early or keep it reachable over FastConnect."
                          if not n.is_shared(g.settings) else "",
        })
    return rows


def wave_summary(g: Graph, cov: list[dict], xw: list[dict], groups: list[dict]) -> list[dict]:
    rows = []
    cov_by_vm = {r["VM"]: r for r in cov}
    for w in g.waves():
        members = [n for n in g.vm_nodes() if n.wave == w]
        ids = {n.id for n in members}
        not_collected = [n.id for n in members if not n.collected]
        short = [n.id for n in members if n.collected and cov_by_vm[n.id]["Collection Days"] < g.settings.min_collection_days]
        x = [r for r in xw if r["Client"] in ids or r["Server"] in ids]
        x_high = [r for r in x if r["Risk"] == "High"]
        unknown = set()
        for n in members:
            for e in g.edges_of(n.id):
                other = g.nodes[e.server if e.client == n.id else e.client]
                if other.kind == UNKNOWN_INTERNAL and e.category == APP and not e.failed_only:
                    unknown.add(other.id)
        split = [r["Group"] for r in groups if r["Status"] != "OK" and any(m in ids for m in r["Members"].split(", "))]
        if not_collected or x_high or unknown:
            status = "RED"
        elif x or short or split:
            status = "AMBER"
        else:
            status = "GREEN"
        rows.append({
            "Wave": w, "Status": status, "VMs": len(members), "Not Collected": len(not_collected),
            "Short Collection": len(short), "Cross-Wave Deps": len(x), "High-Risk Cross-Wave": len(x_high),
            "Unknown Internal Endpoints": len(unknown), "Split Move Groups": ", ".join(split),
            "VMs Without Data": ", ".join(sorted(not_collected)),
        })
    return rows


def firewall_flows(g: Graph) -> list[dict]:
    """Flows each wave needs after its cutover, as input for OCI NSG/Security List
    and on-prem firewall rules. Location is from that wave's point of view."""
    rows = []
    windex = wave_index(g)
    for w in g.waves():
        ids = {n.id for n in g.vm_nodes() if n.wave == w}
        for e in g.edges.values():
            if e.failed_only or not (e.client in ids or e.server in ids):
                continue
            c, s = g.nodes[e.client], g.nodes[e.server]

            def where(n: Node) -> str:
                if n.id in ids:
                    return "OCI (this wave)"
                if n.is_vm and n.wave and windex[n.wave] < windex[w]:
                    return "OCI (earlier wave)"
                if n.kind == EXTERNAL:
                    return "Internet"
                return "On-prem" + (f" until {n.wave}" if n.is_vm and n.wave else "")

            src, dst = where(c), where(s)
            if src.startswith("OCI") and dst.startswith("OCI"):
                path = "Intra-OCI"
            elif src.startswith("On-prem") or dst.startswith("On-prem"):
                path = "Hybrid (FastConnect/VPN)"
            else:
                path = "Internet"
            rows.append({
                "Wave": w, "Path": path, "Source": e.client, "Source IPs": ", ".join(sorted(c.ips)), "Source Location": src,
                "Destination": e.server, "Destination IPs": ", ".join(sorted(s.ips)), "Destination Location": dst,
                "Protocol": "TCP", "Port": e.port, "Service": e.service, "Category": e.category,
            })
    rows.sort(key=lambda r: (natural_key(r["Wave"]), r["Path"], r["Destination"], r["Port"]))
    return rows


# ---------------------------------------------------------------- ad-hoc selection


def check_selection(g: Graph, selected: set[str], wave_name: str | None = None) -> dict:
    """What does this set of VMs depend on? Used to build or validate one wave."""
    windex = wave_index(g)
    target_idx = windex.get(wave_name) if wave_name else None
    deps, internal = [], 0
    for e in g.edges.values():
        cin, sin = e.client in selected, e.server in selected
        if not (cin or sin):
            continue
        if cin and sin:
            internal += 1
            continue
        mine, peer_id = (e.client, e.server) if cin else (e.server, e.client)
        peer = g.nodes[peer_id]
        if e.category == INFRA:
            verdict = "Shared/infra service: provide in OCI or keep reachable over FastConnect"
        elif e.category == ADMIN:
            verdict = "Admin access: firewall rule only"
        elif peer.kind == UNKNOWN_INTERNAL:
            verdict = "IDENTIFY this IP before cutover"
        elif peer.kind == EXTERNAL:
            verdict = "Internet: egress/ingress and public IP change"
        elif peer.kind == KNOWN:
            verdict = f"Known endpoint ({peer.known.category}): plan connectivity"
        elif not peer.wave:
            verdict = "Peer has NO WAVE: add it to this wave or accept permanent hybrid traffic"
        elif target_idx is not None and windex[peer.wave] < target_idx:
            verdict = f"Peer already in OCI ({peer.wave}): OK"
        elif target_idx is not None and windex[peer.wave] > target_idx:
            verdict = f"Peer moves later ({peer.wave}): hybrid until then. Consider moving them together"
        else:
            verdict = f"Peer in {peer.wave}"
        if e.failed_only:
            verdict = "Connection attempts only (never established): stale config or decommissioned target? " + verdict
        deps.append(edge_row(g, e, **{"Selected VM": mine, "Direction": "outbound" if cin else "inbound",
                                      "Peer": peer.label, "Peer Wave": peer.wave, "Verdict": verdict}))
    deps.sort(key=lambda r: ({APP: 0, INFRA: 1, ADMIN: 2}[r["Category"]], -SENS_RANK[r["Latency Sensitivity"]], r["Selected VM"]))

    # VMs you would have to add so that no app dependency crosses the boundary (BFS, shared services excluded).
    adj: dict[str, set[str]] = defaultdict(set)
    for e in _app_edges(g):
        if g.nodes[e.client].is_vm and g.nodes[e.server].is_vm:
            adj[e.client].add(e.server)
            adj[e.server].add(e.client)
    closure, seen = [], set(selected)
    q = deque((v, 0) for v in selected)
    while q:
        v, d = q.popleft()
        for nb in sorted(adj[v]):
            if nb in seen or g.nodes[nb].is_shared(g.settings):
                continue
            seen.add(nb)
            via = sorted(x for x in adj[nb] if x in seen and x != nb)
            closure.append({"VM": nb, "Hops": d + 1, "Current Wave": g.nodes[nb].wave or "(none)",
                            "Collected": "yes" if g.nodes[nb].collected else "no",
                            "Linked To": ", ".join(via[:10]), "Application": g.nodes[nb].vm.application})
            q.append((nb, d + 1))

    sel_rows = [{"VM": v, "Wave": g.nodes[v].wave, "Collected": "yes" if g.nodes[v].collected else "NO",
                 "Collection Days": round(g.nodes[v].host.days, 1) if g.nodes[v].host else 0,
                 "OS": g.nodes[v].vm.os, "Application": g.nodes[v].vm.application}
                for v in sorted(selected, key=str.lower)]
    return {"selected": sel_rows, "internal_edges": internal, "dependencies": deps, "closure": closure}
