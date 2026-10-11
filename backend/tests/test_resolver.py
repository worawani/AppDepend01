"""Endpoint-resolution rules, one test per rule plus the edge cases the brief calls out:
reused IPs, NAT/shared IPs, duplicate VM names, time relevance and unknown endpoints."""

from datetime import datetime, timedelta, timezone

import pytest

from app.resolution.resolver import (AMBIGUOUS, HIGH, LOW, MEDIUM, NONE, RESOLVED, UNRESOLVED, AddressRef,
                                     EndpointResolver, InterfaceRef, VmRef, endpoint_class)

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)
SNAP = T0 + timedelta(days=10)


def vm(id_, name, dns=None, uuid=True, snap=SNAP):
    return VmRef(id_, name, dns, uuid, snap)


VMS = [
    vm("w", "WEB01", "web01.corp.example"),
    vm("d", "DB01", "db01.corp.example"),
    vm("n", "NOUUID01", "nouuid01.corp.example", uuid=False),
    vm("c1", "APP01", "app01.site-a.example"),          # duplicate short names in two sites
    vm("c2", "APP01", "app01.site-b.example"),
    vm("e", "ERP02", "erp02.corp.example"),
]
IFACES = [
    InterfaceRef("w", "10.0.0.1", "00:50:56:00:00:01"),
    InterfaceRef("d", "10.0.0.2", "00:50:56:00:00:02"),
    InterfaceRef("n", "10.0.0.3", None),
    InterfaceRef("c1", "10.9.9.9", None),               # same IP in two sites / VIP
    InterfaceRef("c2", "10.9.9.9", None),
    InterfaceRef("e", None, "00:50:56:00:00:0e"),        # MAC known, IP not in inventory (DHCP)
]


def resolver(addresses=(), staleness_days=90, vms=VMS, ifaces=IFACES):
    return EndpointResolver(list(vms), list(ifaces), list(addresses), timedelta(days=staleness_days))


def addr(id_, ip, rtype, hostname=None, mac=None, start=None, end=None):
    return AddressRef(id_, ip, rtype, hostname, mac, start, end)


def test_r2_inventory_ip_high():
    r = resolver().resolve("10.0.0.1", T0)
    assert (r.status, r.vm_id, r.method, r.confidence) == (RESOLVED, "w", "inventory_ip", HIGH)
    assert r.evidence == (("vm_inventory", "w"),)


def test_r2_stale_snapshot_downgrades_to_medium():
    r = resolver(staleness_days=5).resolve("10.0.0.1", T0)      # observed 10 days before snapshot
    assert (r.status, r.confidence) == (RESOLVED, MEDIUM) and "re-assigned" in r.reason


def test_r2_name_identity_vm_is_never_high():
    r = resolver().resolve("10.0.0.3", T0)
    assert (r.vm_id, r.confidence) == ("n", MEDIUM) and "no vCenter UUID" in r.reason


def test_r3_shared_ip_is_ambiguous_not_guessed():
    r = resolver().resolve("10.9.9.9", T0)
    assert (r.status, r.vm_id, r.confidence) == (AMBIGUOUS, None, NONE)
    assert r.candidates == ("c1", "c2")


def test_r1_dhcp_lease_mac_is_time_relevant():
    leases = [addr(1, "10.60.0.50", "dhcp_lease", mac="00:50:56:00:00:0e", start=T0, end=T0 + timedelta(days=3)),
              addr(2, "10.60.0.50", "dhcp_lease", mac="f0:de:f1:99:88:77", start=T0 + timedelta(days=3, seconds=1))]
    res = resolver(leases)
    during = res.resolve("10.60.0.50", T0 + timedelta(days=1))
    after = res.resolve("10.60.0.50", T0 + timedelta(days=5))
    before = res.resolve("10.60.0.50", T0 - timedelta(days=1))
    assert (during.status, during.vm_id, during.method, during.confidence) == (RESOLVED, "e", "dhcp_lease_mac", HIGH)
    assert (after.status, after.method) == (UNRESOLVED, "dhcp_unmatched")
    assert (before.status, before.method) == (UNRESOLVED, "no_match")


def test_r1_lease_contradicting_inventory_is_medium_and_lists_both():
    lease = addr(1, "10.0.0.1", "dhcp_lease", mac="00:50:56:00:00:0e", start=T0, end=T0 + timedelta(days=1))
    r = resolver([lease]).resolve("10.0.0.1", T0 + timedelta(hours=1))
    assert (r.vm_id, r.confidence) == ("e", MEDIUM) and r.candidates == ("e", "w")


def test_r1_lease_boundaries_are_inclusive():
    lease = addr(1, "10.60.0.9", "dhcp_lease", mac="00:50:56:00:00:0e", start=T0, end=T0 + timedelta(hours=1))
    res = resolver([lease])
    assert res.resolve("10.60.0.9", T0).vm_id == "e"
    assert res.resolve("10.60.0.9", T0 + timedelta(hours=1)).vm_id == "e"
    assert res.resolve("10.60.0.9", T0 + timedelta(hours=1, seconds=1)).vm_id is None


def test_r4_dns_fqdn_medium():
    r = resolver([addr(1, "10.50.0.98", "dns_a", hostname="db01.corp.example")]).resolve("10.50.0.98", T0)
    assert (r.status, r.vm_id, r.method, r.confidence) == (RESOLVED, "d", "dns_fqdn", MEDIUM)


def test_r5_short_name_only_is_low_confidence():
    r = resolver([addr(1, "10.50.0.30", "dns_ptr", hostname="web01.old-domain.local")]).resolve("10.50.0.30", T0)
    assert (r.status, r.vm_id, r.method, r.confidence) == (RESOLVED, "w", "dns_name_only", LOW)
    assert "confirm" in r.reason


def test_r5_duplicate_names_are_ambiguous_never_merged():
    r = resolver([addr(1, "10.50.0.31", "dns_ptr", hostname="app01.unknown.local")]).resolve("10.50.0.31", T0)
    assert (r.status, r.vm_id, r.method) == (AMBIGUOUS, None, "dns_name_only") and r.candidates == ("c1", "c2")


def test_dns_record_outside_validity_is_ignored():
    rec = addr(1, "10.50.0.98", "dns_a", hostname="db01.corp.example", start=T0, end=T0 + timedelta(days=1))
    assert resolver([rec]).resolve("10.50.0.98", T0 + timedelta(days=2)).status == UNRESOLVED


def test_dns_name_without_vm_stays_unresolved_with_evidence():
    r = resolver([addr(7, "10.50.1.20", "static", hostname="mq-prod-01.corp.example")]).resolve("10.50.1.20", T0)
    assert (r.status, r.method, r.evidence) == (UNRESOLVED, "dns_unmatched", (("address_record", "7"),))


@pytest.mark.parametrize("ip,cls,method", [
    ("52.84.10.20", "external", "no_match"), ("10.77.0.1", "internal", "no_match"),
    ("224.0.0.251", "special", "special_address"), ("127.0.0.1", "special", "special_address"),
    ("255.255.255.255", "special", "special_address")])
def test_unresolved_classes(ip, cls, method):
    r = resolver().resolve(ip, T0)
    assert (r.status, r.endpoint_class, r.method, r.vm_id) == (UNRESOLVED, cls, method, None)


def test_endpoint_class_cgnat_and_ula_are_internal():
    assert endpoint_class("100.64.1.1") == "internal" and endpoint_class("fd00::1") == "internal"


def test_inventory_interface_validity_window_respected():
    ifaces = [InterfaceRef("w", "10.1.1.1", None, valid_from=T0, valid_to=T0 + timedelta(days=1)),
              InterfaceRef("d", "10.1.1.1", None, valid_from=T0 + timedelta(days=2))]
    res = resolver(ifaces=ifaces)
    assert res.resolve("10.1.1.1", T0 + timedelta(hours=1)).vm_id == "w"       # IP reused later by another VM
    assert res.resolve("10.1.1.1", T0 + timedelta(days=3)).vm_id == "d"
    assert res.resolve("10.1.1.1", T0 + timedelta(days=1, hours=12)).status == UNRESOLVED


def test_cache_key_separates_every_change_point():
    leases = [addr(1, "10.60.0.50", "dhcp_lease", mac="00:50:56:00:00:0e", start=T0, end=T0 + timedelta(days=3))]
    res = resolver(leases)
    times = [T0 - timedelta(hours=1), T0, T0 + timedelta(days=1), T0 + timedelta(days=3), T0 + timedelta(days=4)]
    by_key = {}
    for t in times:
        by_key.setdefault(res.cache_key("10.60.0.50", t), set()).add(res.resolve("10.60.0.50", t))
    assert all(len(v) == 1 for v in by_key.values())     # same key never yields different answers
