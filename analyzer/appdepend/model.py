"""Builds the dependency graph: resolves remote IPs to VMs or endpoints, merges
the client-side and server-side observations of each flow, and classifies edges."""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Settings
from .inputs import VM, HostData, KnownEndpoint
from .netutil import CidrTable, classify_ip

# Node kinds
VM_NODE = "vm"
KNOWN = "known"
UNKNOWN_INTERNAL = "unknown-internal"
EXTERNAL = "internet"

# Edge categories
APP, INFRA, ADMIN = "app", "infra", "admin"


@dataclass
class Node:
    id: str
    kind: str
    vm: VM | None = None
    ips: set[str] = field(default_factory=set)
    known: KnownEndpoint | None = None
    host: HostData | None = None       # collector data, when this VM was collected

    @property
    def wave(self) -> str:
        return self.vm.wave if self.vm else ""

    @property
    def is_vm(self) -> bool:
        return self.kind == VM_NODE

    @property
    def collected(self) -> bool:
        return self.host is not None

    @property
    def label(self) -> str:
        if self.known:
            return self.known.label
        return self.id

    def is_shared(self, settings: Settings) -> bool:
        if self.vm and (self.vm.is_shared or self.vm.name.lower() in settings.shared_vms):
            return True
        return bool(self.known and self.known.category == "infra")


@dataclass
class Edge:
    client: str
    server: str
    port: int
    service: str = ""
    sensitivity: str = ""
    category: str = APP
    client_processes: set[str] = field(default_factory=set)
    server_processes: set[str] = field(default_factory=set)
    observed_by: set[str] = field(default_factory=set)     # 'client' and/or 'server'
    samples: int = 0
    persistence: float = 0.0     # fraction of the observing host's samples in which the flow was present
    first_seen: str = ""
    last_seen: str = ""
    states: set[str] = field(default_factory=set)
    max_concurrent: int = 0

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.client, self.server, self.port)

    @property
    def failed_only(self) -> bool:
        """Only connection attempts, never established: the target may be decommissioned or firewalled."""
        return bool(self.states) and self.states <= {"SynSent"}


@dataclass
class Graph:
    nodes: dict[str, Node]
    edges: dict[tuple[str, str, int], Edge]
    settings: Settings
    warnings: list[str]

    def vm_nodes(self) -> list[Node]:
        return [n for n in self.nodes.values() if n.is_vm]

    def edges_of(self, node_id: str):
        return [e for e in self.edges.values() if e.client == node_id or e.server == node_id]

    def waves(self) -> list[str]:
        from .inputs import natural_key

        return sorted({n.wave for n in self.vm_nodes() if n.wave}, key=natural_key)


def _short(name: str) -> str:
    return name.split(".")[0].lower()


def build_graph(inventory: dict[str, VM], waves: dict[str, dict[str, str]], hosts: dict[str, HostData],
                known: CidrTable, settings: Settings) -> Graph:
    warnings: list[str] = []
    vms = dict(inventory)

    # 1. Wave plan overrides any wave column in the inventory.
    for key, w in waves.items():
        vm = vms.get(key)
        if vm is None:
            vm = vms[key] = VM(name=key.upper(), in_inventory=False)
            warnings.append(f"Wave plan lists '{key}', which is not in the inventory.")
        vm.wave = w["wave"]
        if w.get("application") and not vm.application:
            vm.application = w["application"]

    nodes: dict[str, Node] = {vm.name: Node(vm.name, VM_NODE, vm=vm, ips=set(vm.ips)) for vm in vms.values()}
    by_lower = {vm.name.lower(): vm.name for vm in vms.values()}
    by_short = {}
    for vm in vms.values():
        by_short.setdefault(_short(vm.name), vm.name)
        if vm.dns_name:
            by_short.setdefault(_short(vm.dns_name), vm.name)

    # 2. Attach collector data to VMs. The Windows hostname often differs from the
    #    vSphere VM name, so try the name, then the DNS short name, then IP overlap.
    ip_owner_inv: dict[str, str] = {}
    for vm in vms.values():
        for ip in vm.ips:
            ip_owner_inv.setdefault(ip, vm.name)
    for h in hosts.values():
        target = by_lower.get(h.hostname.lower()) or by_short.get(_short(h.hostname))
        if target is None and h.fqdn:
            target = by_short.get(_short(h.fqdn))
        if target is None:
            owners = {ip_owner_inv[ip] for ip in h.ips if ip in ip_owner_inv}
            if len(owners) == 1:
                target = owners.pop()
        if target is None:
            target = h.hostname
            nodes[target] = Node(target, VM_NODE, vm=VM(name=target, os=h.os, in_inventory=False))
            warnings.append(f"Collected host '{h.hostname}' does not match any inventory VM (by name, DNS name or IP).")
        node = nodes[target]
        if node.host is not None:
            warnings.append(f"Two collected hosts map to VM '{target}' ({node.host.hostname}, {h.hostname}); keeping the first.")
            continue
        node.host = h
        node.ips |= h.ips
        node.vm.ips |= h.ips
        if not node.vm.os:
            node.vm.os = h.os

    # 3. IP -> node index. Collector-reported IPs are authoritative.
    ip_index: dict[str, str] = {}
    for n in nodes.values():
        for ip in (n.host.ips if n.host else ()):
            ip_index.setdefault(ip, n.id)
    for n in nodes.values():
        for ip in n.ips:
            owner = ip_index.setdefault(ip, n.id)
            if owner != n.id:
                warnings.append(f"IP {ip} is claimed by both {owner} and {n.id} (VIP or stale inventory?); using {owner}.")

    ignore = CidrTable()
    for c in settings.ignore_cidrs:
        ignore.add(c, True)

    def resolve(ip: str) -> str | None:
        if ip in ip_index:
            return ip_index[ip]
        k = known.lookup(ip)
        if k is not None:
            node_id = f"[{k.label}]"
            n = nodes.setdefault(node_id, Node(node_id, KNOWN, known=k))
            n.ips.add(ip)
            return node_id
        cls = classify_ip(ip)
        if cls in ("loopback", "multicast", "link-local", "invalid"):
            return None
        n = nodes.setdefault(ip, Node(ip, UNKNOWN_INTERNAL if cls == "private" else EXTERNAL))
        n.ips.add(ip)
        return ip

    # 4. Flows -> edges.
    edges: dict[tuple[str, str, int], Edge] = {}
    for node in [n for n in nodes.values() if n.host]:
        h = node.host
        for fl in h.flows.values():
            if fl.port in settings.ignore_ports or fl.process.lower() in settings.ignore_processes:
                continue
            if fl.remote in h.ips or (len(ignore) and ignore.lookup(fl.remote)):
                continue
            other = resolve(fl.remote)
            if other is None or other == node.id:
                continue
            if fl.direction == "Outbound":
                client, server, side = node.id, other, "client"
            else:
                client, server, side = other, node.id, "server"
            key = (client, server, fl.port)
            e = edges.get(key)
            if e is None:
                e = edges[key] = Edge(client, server, fl.port, settings.service_name(fl.port), settings.latency_sensitivity(fl.port))
            e.observed_by.add(side)
            if fl.process and fl.process != "(closed)":
                (e.client_processes if side == "client" else e.server_processes).add(fl.process)
            e.samples = max(e.samples, fl.samples)
            if h.samples:
                e.persistence = max(e.persistence, min(1.0, fl.samples / h.samples))
            e.first_seen = min(filter(None, [e.first_seen, fl.first_seen]), default="")
            e.last_seen = max(e.last_seen, fl.last_seen)
            e.states |= fl.states
            e.max_concurrent = max(e.max_concurrent, fl.max_concurrent)

    # 5. Classify.
    for e in edges.values():
        c, s = nodes[e.client], nodes[e.server]
        if e.port in settings.admin_ports:
            e.category = ADMIN
        elif e.port in settings.infra_ports or s.is_shared(settings) or c.is_shared(settings):
            e.category = INFRA
        elif (s.known and s.known.category == "admin") or (c.known and c.known.category == "admin"):
            e.category = ADMIN
        else:
            e.category = APP

    return Graph(nodes, edges, settings, warnings)
