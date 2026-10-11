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
    return paths
