"""Endpoint resolution rules (approved decision 4). Pure logic, no database access.

Given an observed IP and the time it was observed, decide which VM it belongs to, how sure we
are, and why. Rules are applied in order; the first rule that produces an answer wins:

  R1  DHCP lease valid at that time, whose MAC belongs to exactly one inventory VM
      -> resolved, method dhcp_lease_mac, confidence HIGH (MEDIUM if it contradicts the inventory IP)
  R2  Inventory interface IP owned by exactly one VM
      -> resolved, method inventory_ip, confidence HIGH;
         MEDIUM when the observation is far from the inventory snapshot (IP may have been re-assigned)
         or the VM's own identity is name-only (no vCenter UUID)
  R3  Inventory IP owned by several VMs (VIP, cluster IP, stale data, overlapping networks)
      -> AMBIGUOUS with all candidates. Never picks one.
  R4  DNS/static record valid at that time; its FQDN equals exactly one VM's DNS name
      -> resolved, method dns_fqdn, confidence MEDIUM
  R5  ... only the short host name equals one VM's name or DNS short name
      -> resolved, method dns_name_only, confidence LOW (name-only match, flagged for review)
      ... several VMs share that name -> AMBIGUOUS (duplicate names are never merged)
  R6  nothing matches -> UNRESOLVED, classified internal / external / special. Kept, never forced.

Confidence is an explainable class, not a calibrated probability (reference §5.1)."""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timedelta

RESOLVER_VERSION = "resolver-1.0.0"

RESOLVED, AMBIGUOUS, UNRESOLVED = "resolved", "ambiguous", "unresolved"
HIGH, MEDIUM, LOW, NONE = "high", "medium", "low", "none"

_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


@dataclass(frozen=True)
class VmRef:
    id: str
    name: str
    dns_name: str | None
    has_uuid: bool
    snapshot_at: datetime            # when the inventory record was last confirmed (last import batch time)


@dataclass(frozen=True)
class InterfaceRef:
    vm_id: str
    ip: str | None
    mac: str | None
    valid_from: datetime | None = None
    valid_to: datetime | None = None


@dataclass(frozen=True)
class AddressRef:
    id: int
    ip: str
    record_type: str                 # dns_a | dns_ptr | dhcp_lease | static
    hostname: str | None
    mac: str | None
    valid_from: datetime | None
    valid_to: datetime | None

    def valid_at(self, ts: datetime) -> bool:
        return (self.valid_from is None or self.valid_from <= ts) and (self.valid_to is None or ts <= self.valid_to)


@dataclass(frozen=True)
class Resolution:
    status: str
    vm_id: str | None
    method: str
    confidence: str
    reason: str
    endpoint_class: str
    candidates: tuple[str, ...] = ()
    evidence: tuple[tuple[str, str], ...] = field(default=())    # (kind, reference)


def endpoint_class(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback or addr.is_multicast or addr.is_link_local or addr.is_unspecified or addr.is_reserved \
            or (addr.version == 4 and str(addr) == "255.255.255.255"):
        return "special"
    if any(addr.version == n.version and addr in n for n in _INTERNAL_NETS):
        return "internal"
    return "external" if addr.is_global else "internal"


def _short(name: str | None) -> str | None:
    return name.split(".")[0].lower() if name else None


class EndpointResolver:
    def __init__(self, vms: list[VmRef], interfaces: list[InterfaceRef], addresses: list[AddressRef],
                 staleness: timedelta):
        self.vms = {v.id: v for v in vms}
        self.staleness = staleness
        self.by_ip: dict[str, list[InterfaceRef]] = {}
        self.by_mac: dict[str, set[str]] = {}
        for i in interfaces:
            if i.ip:
                self.by_ip.setdefault(i.ip, []).append(i)
            if i.mac:
                self.by_mac.setdefault(i.mac, set()).add(i.vm_id)
        self.by_fqdn: dict[str, set[str]] = {}
        self.by_short: dict[str, set[str]] = {}
        for v in vms:
            if v.dns_name:
                self.by_fqdn.setdefault(v.dns_name.lower().rstrip("."), set()).add(v.id)
            for n in {_short(v.name), _short(v.dns_name)} - {None}:
                self.by_short.setdefault(n, set()).add(v.id)
        self.addr_by_ip: dict[str, list[AddressRef]] = {}
        for a in addresses:
            self.addr_by_ip.setdefault(a.ip, []).append(a)
        # change points per IP: resolution can only change at these instants (used for caching)
        self.change_points: dict[str, list[datetime]] = {}
        for ip, recs in self.addr_by_ip.items():
            pts = sorted({t for r in recs for t in (r.valid_from, r.valid_to) if t is not None})
            self.change_points[ip] = pts

    def cache_key(self, ip: str, ts: datetime) -> tuple:
        """Two observations with the same key always get the same resolution."""
        pts = self.change_points.get(ip, [])
        segment = bisect_right(pts, ts) if pts else 0
        on_point = bool(pts) and ts in pts
        stale = tuple(sorted(i.vm_id for i in self.by_ip.get(ip, []) if self._stale(i.vm_id, ts)))
        valid_ifaces = tuple(sorted(i.vm_id for i in self.by_ip.get(ip, []) if self._iface_valid(i, ts)))
        return (ip, segment, on_point, stale, valid_ifaces)

    def _stale(self, vm_id: str, ts: datetime) -> bool:
        return abs(ts - self.vms[vm_id].snapshot_at) > self.staleness

    @staticmethod
    def _iface_valid(i: InterfaceRef, ts: datetime) -> bool:
        return (i.valid_from is None or i.valid_from <= ts) and (i.valid_to is None or ts <= i.valid_to)

    def _names(self, ids) -> str:
        return ", ".join(sorted(self.vms[i].name for i in ids))

    def resolve(self, ip: str, ts: datetime) -> Resolution:
        cls = endpoint_class(ip)
        if cls == "special":
            return Resolution(UNRESOLVED, None, "special_address", NONE,
                              "Loopback, multicast, broadcast, link-local or reserved address: not a VM endpoint.", cls)
        addr_now = [a for a in self.addr_by_ip.get(ip, []) if a.valid_at(ts)]
        inv_vms = sorted({i.vm_id for i in self.by_ip.get(ip, []) if self._iface_valid(i, ts)})

        # R1: time-valid DHCP lease + MAC from inventory
        lease_vms: set[str] = set()
        leases = [a for a in addr_now if a.record_type == "dhcp_lease" and a.mac]
        for a in leases:
            lease_vms |= self.by_mac.get(a.mac, set())
        if len(lease_vms) == 1:
            vm_id = next(iter(lease_vms))
            ev = tuple(("address_record", str(a.id)) for a in leases)
            if inv_vms and inv_vms != [vm_id]:
                return Resolution(RESOLVED, vm_id, "dhcp_lease_mac", MEDIUM,
                                  f"DHCP lease at that time maps the MAC to {self.vms[vm_id].name}, but the inventory "
                                  f"lists this IP on {self._names(inv_vms)}. The time-valid lease is preferred; please "
                                  "review.", cls, tuple(sorted({vm_id, *inv_vms})), ev)
            return Resolution(RESOLVED, vm_id, "dhcp_lease_mac", HIGH,
                              f"DHCP lease valid at that time; lease MAC belongs to {self.vms[vm_id].name}.", cls, (), ev)
        if len(lease_vms) > 1:
            return Resolution(AMBIGUOUS, None, "dhcp_lease_mac", NONE,
                              f"Overlapping DHCP leases map this IP to several VMs: {self._names(lease_vms)}.", cls,
                              tuple(sorted(lease_vms)), tuple(("address_record", str(a.id)) for a in leases))

        # R2 / R3: inventory IP
        if len(inv_vms) == 1:
            vm = self.vms[inv_vms[0]]
            notes, conf = [], HIGH
            if self._stale(vm.id, ts):
                conf = MEDIUM
                notes.append(f"observed {abs(ts - vm.snapshot_at).days} days from the inventory snapshot, so the IP "
                             "may have been re-assigned")
            if not vm.has_uuid:
                conf = MEDIUM
                notes.append("the VM record has no vCenter UUID (name-based identity)")
            reason = f"IP is on the inventory record of {vm.name}" + (f"; {'; '.join(notes)}." if notes else ".")
            return Resolution(RESOLVED, vm.id, "inventory_ip", conf, reason, cls, (), (("vm_inventory", vm.id),))
        if len(inv_vms) > 1:
            return Resolution(AMBIGUOUS, None, "inventory_ip", NONE,
                              f"IP appears on several inventory records ({self._names(inv_vms)}): VIP, cluster IP, "
                              "stale data or overlapping networks. Not assigned to any of them.", cls, tuple(inv_vms),
                              tuple(("vm_inventory", v) for v in inv_vms))

        # R4 / R5: DNS / static hostname evidence valid at that time
        named = [a for a in addr_now if a.hostname and a.record_type != "dhcp_lease"]
        named += [a for a in addr_now if a.hostname and a.record_type == "dhcp_lease"]   # lease hostname as weak evidence
        if named:
            ev = tuple(("address_record", str(a.id)) for a in named)
            fq = set().union(*(self.by_fqdn.get(a.hostname, set()) for a in named))
            if len(fq) == 1:
                vm_id = next(iter(fq))
                return Resolution(RESOLVED, vm_id, "dns_fqdn", MEDIUM,
                                  f"DNS/static record valid at that time names {named[0].hostname}, which is the DNS name "
                                  f"of {self.vms[vm_id].name}.", cls, (), ev)
            if len(fq) > 1:
                return Resolution(AMBIGUOUS, None, "dns_fqdn", NONE,
                                  f"DNS names at that time match several VMs: {self._names(fq)}.", cls, tuple(sorted(fq)), ev)
            sh = set().union(*(self.by_short.get(_short(a.hostname), set()) for a in named))
            if len(sh) == 1:
                vm_id = next(iter(sh))
                return Resolution(RESOLVED, vm_id, "dns_name_only", LOW,
                                  f"Only the short host name '{_short(named[0].hostname)}' matches VM "
                                  f"{self.vms[vm_id].name}. Name-only match: confirm before relying on it.", cls, (), ev)
            if len(sh) > 1:
                return Resolution(AMBIGUOUS, None, "dns_name_only", NONE,
                                  f"Host name '{_short(named[0].hostname)}' matches several VMs ({self._names(sh)}). "
                                  "Duplicate names are not merged.", cls, tuple(sorted(sh)), ev)
            return Resolution(UNRESOLVED, None, "dns_unmatched", NONE,
                              f"DNS/DHCP names this IP '{named[0].hostname}', but no inventory VM matches. Probably a "
                              "physical server, appliance or non-inventoried system.", cls, (), ev)

        if leases:
            return Resolution(UNRESOLVED, None, "dhcp_unmatched", NONE,
                              f"DHCP lease MAC {leases[0].mac} at that time is not on any inventory VM (client "
                              "device or non-inventoried system).", cls, (), tuple(("address_record", str(a.id)) for a in leases))
        return Resolution(UNRESOLVED, None, "no_match", NONE,
                          "No inventory, DHCP or DNS evidence for this IP." +
                          (" External address." if cls == "external" else ""), cls)
