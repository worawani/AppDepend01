"""Deterministic synthetic inventory data (no real customer data). The output is stable
across runs, so tests and reviewers see the same files."""

from __future__ import annotations

import csv
import io
import uuid
from pathlib import Path

_NS = uuid.UUID("6f1c2a8e-0000-4000-8000-000000000001")
VCENTER = "vcsa01.corp.example"

CANONICAL_HEADER = ["vm_name", "vm_uuid", "vcenter", "moref", "dns_name", "guest_os", "power_state", "cluster",
                    "datacenter", "environment", "application", "owner", "criticality", "tier", "ip_addresses",
                    "mac_addresses", "networks"]

# name, application, tier, criticality, os, ip(s), network
DEMO_VMS = [
    ("DC01", "Active Directory", "shared", "critical", "Microsoft Windows Server 2019 (64-bit)", "10.10.0.10", "PG-INFRA"),
    ("DC02", "Active Directory", "shared", "critical", "Microsoft Windows Server 2019 (64-bit)", "10.10.0.11", "PG-INFRA"),
    ("FILE01", "File services", "shared", "high", "Microsoft Windows Server 2016 (64-bit)", "10.10.1.20", "PG-INFRA"),
    ("HR-WEB01", "HR Portal", "web", "high", "Microsoft Windows Server 2016 (64-bit)", "10.20.1.11", "PG-HR-WEB"),
    ("HR-WEB02", "HR Portal", "web", "high", "Microsoft Windows Server 2016 (64-bit)", "10.20.1.12", "PG-HR-WEB"),
    ("HR-APP01", "HR Portal", "app", "high", "Microsoft Windows Server 2012 R2 (64-bit)", "10.20.2.11", "PG-HR-APP"),
    ("HR-SQL01", "HR Portal", "db", "high", "Microsoft Windows Server 2016 (64-bit)", "10.20.3.11;10.20.3.50", "PG-HR-DB"),
    ("ERP-WEB01", "ERP", "web", "critical", "Microsoft Windows Server 2019 (64-bit)", "10.30.1.11", "PG-ERP-WEB"),
    ("ERP-APP01", "ERP", "app", "critical", "Microsoft Windows Server 2019 (64-bit)", "10.30.2.11", "PG-ERP-APP"),
    ("ERP-APP02", "ERP", "app", "critical", "Microsoft Windows Server 2019 (64-bit)", "10.30.2.12", "PG-ERP-APP"),
    ("ERP-DB01", "ERP", "db", "critical", "Microsoft Windows Server 2022 (64-bit)", "10.30.3.11", "PG-ERP-DB"),
    ("CRM-WEB01", "CRM", "web", "medium", "Microsoft Windows Server 2022 (64-bit)", "10.40.1.11", "PG-CRM"),
    ("CRM-SQL01", "CRM", "db", "medium", "Microsoft Windows Server 2022 (64-bit)", "10.40.3.11", "PG-CRM"),
    ("RPT01", "Reporting", "app", "low", "Microsoft Windows Server 2012 (64-bit)", "10.50.0.21", "PG-RPT"),
    ("LEGACY01", "Legacy billing", "app", "medium", "Microsoft Windows Server 2012 (64-bit)", "10.50.0.99", "PG-RPT"),
]


def vm_uuid(name: str) -> str:
    return str(uuid.uuid5(_NS, name))


def mac_for(i: int) -> str:
    return f"00:50:56:{(i >> 16) & 0xff:02x}:{(i >> 8) & 0xff:02x}:{i & 0xff:02x}"


def canonical_rows(n: int | None = None) -> list[dict]:
    """The 15 demo VMs, or n generated VMs in web/app/db triplets for scale tests."""
    rows = []
    if n is None:
        for i, (name, app, tier, crit, os_, ips, net) in enumerate(DEMO_VMS, 1):
            rows.append({"vm_name": name, "vm_uuid": vm_uuid(name), "vcenter": VCENTER, "moref": f"vm-{1000 + i}",
                         "dns_name": f"{name.lower()}.corp.example", "guest_os": os_, "power_state": "poweredOn",
                         "cluster": "PROD-CL01", "datacenter": "BKK-DC1", "environment": "production",
                         "application": app, "owner": f"{app.split()[0].lower()}-owner@corp.example",
                         "criticality": crit, "tier": tier, "ip_addresses": ips, "mac_addresses": mac_for(i),
                         "networks": net})
        return rows
    tiers = ("web", "app", "db")
    for i in range(n):
        app_no, tier = divmod(i, 3)
        name = f"APP{app_no:03d}-{tiers[tier].upper()}01"
        rows.append({"vm_name": name, "vm_uuid": vm_uuid(name), "vcenter": VCENTER, "moref": f"vm-{20000 + i}",
                     "dns_name": f"{name.lower()}.corp.example", "guest_os": "Microsoft Windows Server 2019 (64-bit)",
                     "power_state": "poweredOn", "cluster": f"PROD-CL{app_no % 4 + 1:02d}", "datacenter": "BKK-DC1",
                     "environment": "production", "application": f"Application {app_no:03d}",
                     "owner": f"owner{app_no:03d}@corp.example", "criticality": ("high", "medium", "low")[app_no % 3],
                     "tier": tiers[tier], "ip_addresses": f"10.{100 + i // 65000}.{(i // 250) % 256}.{i % 250 + 1}",
                     "mac_addresses": mac_for(10000 + i), "networks": f"PG-APP{app_no:03d}"})
    return rows


def to_csv(rows: list[dict], header: list[str] | None = None) -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header or list(rows[0].keys()), lineterminator="\r\n")
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


def rvtools_rows() -> list[dict]:
    """The same demo estate as an RVTools vInfo export (subset of real column names), plus a template."""
    rows = []
    for i, r in enumerate(canonical_rows(), 1):
        rows.append({"VM": r["vm_name"], "Powerstate": "poweredOn", "Template": "False", "DNS Name": r["dns_name"],
                     "Primary IP Address": r["ip_addresses"].split(";")[0], "Network #1": r["networks"],
                     "CPUs": "4", "Memory": "16384", "Datacenter": r["datacenter"], "Cluster": r["cluster"],
                     "OS according to the VMware Tools": r["guest_os"], "VM ID": r["moref"], "VM UUID": r["vm_uuid"],
                     "VI SDK Server": VCENTER, "Annotation": ""})
    rows.append({**rows[0], "VM": "TPL-WS2022", "Template": "True", "Powerstate": "poweredOff",
                 "VM UUID": vm_uuid("TPL-WS2022"), "Primary IP Address": "", "DNS Name": ""})
    return rows


def error_rows() -> list[dict]:
    """Deliberately broken rows; each one exercises a validation rule."""
    good = canonical_rows()
    rows = [dict(good[3]), dict(good[4])]
    rows.append({**good[5], "vm_name": ""})                                         # missing name -> error
    rows.append({**good[6], "vm_uuid": "not-a-uuid"})                               # invalid uuid -> error
    rows.append({**good[7], "vm_name": "ERP-WEB01-CLONE"})                          # duplicate of next row's uuid
    rows.append({**good[7]})                                                        # -> both rows error
    rows.append({**good[8], "ip_addresses": "10.30.2.11;10.30.2.999"})              # invalid ip -> warning
    rows.append({**good[9], "mac_addresses": "00:50:56:zz:00:01"})                  # invalid mac -> warning
    rows.append({**good[10], "ip_addresses": good[3]["ip_addresses"]})              # shared ip -> warning
    rows.append({**good[11], "criticality": "tier-1"})                              # unknown criticality -> warning
    rows.append({**good[12], "owner": "=HYPERLINK(\"http://evil.example\",\"x\")"})  # formula text kept raw
    rows.append({**good[13], "vm_uuid": "", "vcenter": ""})                         # name-only identity -> info
    return rows


def write_samples(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "inventory_vcenter.csv": to_csv(canonical_rows(), CANONICAL_HEADER),
        "inventory_rvtools_vinfo.csv": to_csv(rvtools_rows()),
        "inventory_with_errors.csv": to_csv(error_rows(), CANONICAL_HEADER),
        "inventory_scale_1000.csv": to_csv(canonical_rows(1000), CANONICAL_HEADER),
    }
    paths = []
    for name, data in files.items():
        (out / name).write_bytes(data)
        paths.append(out / name)
    return paths + write_telemetry_samples(out)


# ---------------------------------------------------------------- Phase 2: synthetic telemetry (canonical formats)
# Synthetic only. These files exercise the canonical schemas and the resolution rules; they say
# nothing about compatibility with any real firewall or IPFIX export.

FLOW_HEADER = ["ts_start", "ts_end", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "bytes",
               "packets", "flow_count", "source_device", "nat_dst_ip", "record_ref"]
ADDRESS_HEADER = ["ip", "record_type", "hostname", "mac", "valid_from", "valid_to", "source", "record_ref"]
WINDOW_START = "2026-09-01T00:00:00+07:00"
WINDOW_END = "2026-09-08T00:00:00+07:00"

# client, server, port, hours of day it occurs, days (0-6), source device
_FLOW_SCENARIOS = [
    ("10.60.0.21", "10.20.1.11", 443, range(8, 18), range(7), "fw-core-01"),      # DHCP user -> HR web
    ("10.20.1.11", "10.20.2.11", 8080, range(8, 18), range(7), "ipfix-vds-01"),   # web -> app (same segment)
    ("10.20.1.12", "10.20.2.11", 8080, range(8, 18), range(7), "ipfix-vds-01"),
    ("10.20.2.11", "10.20.3.50", 1433, range(0, 24), range(7), "ipfix-vds-01"),   # app -> SQL listener IP
    ("10.30.2.11", "10.30.3.11", 1521, range(0, 24), range(7), "ipfix-vds-01"),   # ERP app -> DB
    ("10.30.2.11", "10.50.1.20", 1414, range(0, 24, 2), range(7), "fw-core-01"),  # -> unidentified MQ (static DNS only)
    ("10.40.1.11", "52.84.10.20", 443, range(9, 17), range(7), "fw-edge-01"),     # CRM -> SaaS (external)
    ("10.50.0.21", "10.20.3.11", 1433, range(1, 2), range(7), "fw-core-01"),      # nightly report pull
    ("10.50.0.98", "10.30.3.11", 1521, range(2, 3), range(7), "fw-core-01"),      # LEGACY01 at its real IP (DNS only)
    ("10.50.0.30", "10.10.1.20", 445, range(3, 4), range(7), "fw-core-01"),       # resolves by short name only
    ("10.60.0.50", "10.30.1.11", 8443, range(10, 12), range(7), "fw-core-01"),    # IP re-used over time (DHCP)
]


def _ts(day: int, hour: int, minute: int) -> str:
    return f"2026-09-{1 + day:02d}T{hour:02d}:{minute:02d}:00+07:00"


def flow_rows() -> list[dict]:
    import random

    rnd = random.Random(42)
    rows, ref = [], 0
    for client, server, port, hours, days, device in _FLOW_SCENARIOS:
        for d in days:
            for h in hours:
                for _ in range(1 + rnd.randrange(2)):
                    ref += 1
                    m = rnd.randrange(55)
                    rows.append({"ts_start": _ts(d, h, m), "ts_end": _ts(d, h, m + rnd.randrange(1, 5)),
                                 "src_ip": client, "src_port": str(49152 + rnd.randrange(16000)), "dst_ip": server,
                                 "dst_port": str(port), "protocol": "tcp", "action": "allow",
                                 "bytes": str(rnd.randrange(500, 900_000)), "packets": str(rnd.randrange(4, 900)),
                                 "flow_count": "1", "source_device": device, "nat_dst_ip": "", "record_ref": f"SYN-{ref:06d}"})
    # internet client -> public VIP, DNAT to CRM-WEB01
    for d in range(7):
        rows.append({**rows[0], "ts_start": _ts(d, 12, 0), "ts_end": _ts(d, 12, 1), "src_ip": "20.43.10.40",
                     "dst_ip": "203.0.113.10", "nat_dst_ip": "10.40.1.11", "dst_port": "443", "source_device": "fw-edge-01",
                     "record_ref": f"SYN-NAT-{d}"})
    # denied attempt, ICMP, and one IPFIX-style return flow
    rows.append({**rows[0], "src_ip": "10.60.0.21", "dst_ip": "10.30.3.11", "dst_port": "1521", "action": "deny",
                 "bytes": "0", "packets": "1", "record_ref": "SYN-DENY-1"})
    rows.append({**rows[0], "dst_ip": "10.10.0.10", "protocol": "icmp", "dst_port": "", "src_port": "",
                 "record_ref": "SYN-ICMP-1"})
    rows.append({**rows[0], "src_ip": "10.30.3.11", "src_port": "1521", "dst_ip": "10.30.2.11", "dst_port": "51515",
                 "source_device": "ipfix-vds-01", "record_ref": "SYN-REV-1"})
    return rows


def flow_error_rows() -> list[dict]:
    good = flow_rows()[:40]
    bad = [
        {**good[0], "src_ip": "10.20.1.999", "record_ref": "BAD-IP"},
        {**good[1], "ts_start": "2026-09-01 10:00:00", "ts_end": "", "record_ref": "BAD-NO-TZ"},
        {**good[2], "ts_end": "2026-08-31T00:00:00+07:00", "record_ref": "BAD-ORDER"},
        {**good[3], "dst_port": "", "record_ref": "BAD-NO-PORT"},
        {**good[4], "protocol": "tcpx", "record_ref": "BAD-PROTO"},
        {**good[5], "bytes": "-5", "record_ref": "BAD-BYTES"},
        {**good[6], "dst_port": "70000", "record_ref": "BAD-PORT"},
        {**good[7], "owner": "x", "src_ip": "=1+1", "record_ref": "BAD-FORMULA"},
    ]
    return good + [{k: v for k, v in r.items() if k in FLOW_HEADER} for r in bad]


def address_rows() -> list[dict]:
    lease_mac_vm = mac_for(10)            # ERP-APP02's MAC in the demo inventory
    return [
        {"ip": "10.50.0.98", "record_type": "dns_a", "hostname": "legacy01.corp.example", "mac": "",
         "valid_from": "", "valid_to": "", "source": "dns-export", "record_ref": "DNS-1"},
        {"ip": "10.50.0.30", "record_type": "dns_ptr", "hostname": "rpt01.olddomain.local", "mac": "",
         "valid_from": "", "valid_to": "", "source": "dns-export", "record_ref": "DNS-2"},
        {"ip": "10.50.1.20", "record_type": "static", "hostname": "mq-prod-01.corp.example", "mac": "",
         "valid_from": "", "valid_to": "", "source": "ipam", "record_ref": "IPAM-1"},
        {"ip": "10.60.0.21", "record_type": "dhcp_lease", "hostname": "nb-somchai.corp.example", "mac": "a4:5e:60:11:22:33",
         "valid_from": WINDOW_START, "valid_to": WINDOW_END, "source": "dhcp-export", "record_ref": "DHCP-1"},
        {"ip": "10.60.0.50", "record_type": "dhcp_lease", "hostname": "", "mac": lease_mac_vm,
         "valid_from": WINDOW_START, "valid_to": "2026-09-03T23:59:59+07:00", "source": "dhcp-export", "record_ref": "DHCP-2"},
        {"ip": "10.60.0.50", "record_type": "dhcp_lease", "hostname": "", "mac": "f0:de:f1:99:88:77",
         "valid_from": "2026-09-04T00:00:00+07:00", "valid_to": WINDOW_END, "source": "dhcp-export", "record_ref": "DHCP-3"},
    ]


def write_telemetry_samples(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    files = {
        "flows_canonical.csv": to_csv(flow_rows(), FLOW_HEADER),
        "flows_with_errors.csv": to_csv(flow_error_rows(), FLOW_HEADER),
        "address_records_canonical.csv": to_csv(address_rows(), ADDRESS_HEADER),
    }
    paths = []
    for name, data in files.items():
        (out / name).write_bytes(data)
        paths.append(out / name)
    return paths
