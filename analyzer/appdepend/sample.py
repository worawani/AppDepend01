"""Synthetic demo estate with deliberate planning mistakes, so the reports have
something to find:
  * HR-SQL01 is in Wave 3 but HR-APP01 (Wave 2) depends on it over 1433
  * RPT01 (Wave 1) reads three databases from later waves every night
  * ERP-APP01 talks to an unidentified physical box (IBM MQ on 10.50.1.20)
  * LEGACY01 has no collector data (blind spot)
  * FILE01 is used by everyone (hub) but is not marked shared
  * VM name 'erp-app02_vm' differs from its Windows hostname ERP-APP02
"""

from __future__ import annotations

import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

START = datetime(2026, 9, 1, 0, 0, 0)
END = START + timedelta(days=21)
SAMPLES = 21 * 24 * (58 * 60 // 15)  # 21 days of hourly 58-minute runs at a 15 s interval
FMT = "%Y-%m-%dT%H:%M:%S"

# name, ip, os, application, role, collected, hostname override
VMS = [
    ("DC01", "10.10.0.10", "Microsoft Windows Server 2019 (64-bit)", "Active Directory", "shared", True, None),
    ("DC02", "10.10.0.11", "Microsoft Windows Server 2019 (64-bit)", "Active Directory", "shared", True, None),
    ("JUMP01", "10.10.0.50", "Microsoft Windows Server 2022 (64-bit)", "Admin jump host", "", True, None),
    ("BACKUP01", "10.10.0.60", "Microsoft Windows Server 2019 (64-bit)", "Veeam", "shared", True, None),
    ("FILE01", "10.10.1.20", "Microsoft Windows Server 2016 (64-bit)", "File server", "", True, None),
    ("HR-WEB01", "10.20.1.11", "Microsoft Windows Server 2016 (64-bit)", "HR Portal", "", True, None),
    ("HR-WEB02", "10.20.1.12", "Microsoft Windows Server 2016 (64-bit)", "HR Portal", "", True, None),
    ("HR-APP01", "10.20.2.11", "Microsoft Windows Server 2012 R2 (64-bit)", "HR Portal", "", True, None),
    ("HR-SQL01", "10.20.3.11", "Microsoft Windows Server 2016 (64-bit)", "HR Portal", "", True, None),
    ("ERP-WEB01", "10.30.1.11", "Microsoft Windows Server 2019 (64-bit)", "ERP", "", True, None),
    ("ERP-APP01", "10.30.2.11", "Microsoft Windows Server 2019 (64-bit)", "ERP", "", True, None),
    ("erp-app02_vm", "10.30.2.12", "Microsoft Windows Server 2019 (64-bit)", "ERP", "", True, "ERP-APP02"),
    ("ERP-DB01", "10.30.3.11", "Microsoft Windows Server 2022 (64-bit)", "ERP", "", True, None),
    ("CRM-WEB01", "10.40.1.11", "Microsoft Windows Server 2022 (64-bit)", "CRM", "", True, None),
    ("CRM-SQL01", "10.40.3.11", "Microsoft Windows Server 2022 (64-bit)", "CRM", "", True, None),
    ("RPT01", "10.50.0.21", "Microsoft Windows Server 2012 (64-bit)", "Reporting", "", True, None),
    ("LEGACY01", "10.50.0.99", "Microsoft Windows Server 2012 (64-bit)", "Legacy billing", "", False, None),
]

WAVES = {
    "CRM-WEB01": "Wave 1", "CRM-SQL01": "Wave 1", "RPT01": "Wave 1",
    "HR-WEB01": "Wave 2", "HR-WEB02": "Wave 2", "HR-APP01": "Wave 2", "FILE01": "Wave 2",
    "HR-SQL01": "Wave 3",  # planning mistake
    "ERP-WEB01": "Wave 3", "ERP-APP01": "Wave 3", "erp-app02_vm": "Wave 3", "ERP-DB01": "Wave 3",
    "LEGACY01": "Wave 3",
}

# client, server (VM name or IP), port, client process, server process, persistence (0-1)
FLOWS = [
    ("10.20.0.5", "HR-WEB01", 443, "", "System", 0.95),          # F5 SNAT -> web
    ("10.20.0.5", "HR-WEB02", 443, "", "System", 0.95),
    ("HR-WEB01", "HR-APP01", 8080, "w3wp", "java", 0.9),
    ("HR-WEB02", "HR-APP01", 8080, "w3wp", "java", 0.9),
    ("HR-APP01", "HR-SQL01", 1433, "java", "sqlservr", 0.99),
    ("HR-APP01", "FILE01", 445, "java", "System", 0.3),
    ("HR-APP01", "10.30.5.5", 1433, "java", "", 0.01),            # stale connection string (SYN only)
    ("ERP-WEB01", "ERP-APP01", 8443, "w3wp", "ErpServer", 0.9),
    ("ERP-WEB01", "ERP-APP02", 8443, "w3wp", "ErpServer", 0.9),
    ("ERP-APP01", "ERP-DB01", 1521, "ErpServer", "oracle", 0.99),
    ("ERP-APP02", "ERP-DB01", 1521, "ErpServer", "oracle", 0.99),
    ("ERP-APP01", "10.50.1.20", 1414, "ErpServer", "", 0.6),     # unidentified MQ box
    ("ERP-APP01", "HR-SQL01", 1433, "ErpIntegration", "sqlservr", 0.04),  # nightly HR sync
    ("ERP-APP01", "FILE01", 445, "ErpServer", "System", 0.5),
    ("ERP-APP02", "FILE01", 445, "ErpServer", "System", 0.5),
    ("CRM-WEB01", "CRM-SQL01", 1433, "w3wp", "sqlservr", 0.98),
    ("CRM-WEB01", "52.84.10.20", 443, "w3wp", "", 0.7),           # SaaS API
    ("20.43.10.40", "CRM-WEB01", 443, "", "System", 0.9),        # public inbound
    ("RPT01", "HR-SQL01", 1433, "ReportingServicesService", "sqlservr", 0.03),
    ("RPT01", "ERP-DB01", 1521, "ReportingServicesService", "oracle", 0.03),
    ("RPT01", "CRM-SQL01", 1433, "ReportingServicesService", "sqlservr", 0.03),
    ("RPT01", "FILE01", 445, "ReportingServicesService", "System", 0.03),
    ("CRM-WEB01", "FILE01", 445, "w3wp", "System", 0.2),
    ("LEGACY01", "FILE01", 445, "", "System", 0.4),
    ("LEGACY01", "ERP-DB01", 1521, "", "oracle", 0.2),
    ("HR-APP01", "10.99.0.25", 25, "java", "", 0.05),             # SMTP relay (known endpoint)
    ("ERP-APP01", "10.99.0.25", 25, "ErpServer", "", 0.05),
]


def generate(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    coll = out / "collected"
    by_name = {v[0]: v for v in VMS}
    host_of = {(v[6] or v[0]): v for v in VMS}   # Windows hostname -> spec
    ip_of = {h: v[1] for h, v in host_of.items()}
    ip_of.update({v[0]: v[1] for v in VMS})

    def hostname(name: str) -> str | None:
        v = by_name.get(name) or host_of.get(name)
        return (v[6] or v[0]) if v else None

    rows: dict[str, list[dict]] = defaultdict(list)
    listeners: dict[str, set[tuple[int, str]]] = defaultdict(set)

    def add(host, direction, remote_ip, port, proc, pers, states="Established;TimeWait"):
        n = max(1, int(_samples(host) * pers))
        rows[host].append({
            "Hostname": host, "Direction": direction, "RemoteAddress": remote_ip, "Port": port,
            "ProcessName": proc or "(closed)", "ProcessPath": "", "ServiceNames": "", "States": states,
            "FirstSeen": (START + timedelta(hours=1)).strftime(FMT), "LastSeen": (END - timedelta(hours=1)).strftime(FMT),
            "SampleCount": n, "MaxConcurrent": 1 + int(pers * 20),
        })

    flows = list(FLOWS)
    collected_hosts = [(v[6] or v[0]) for v in VMS if v[5]]
    for h in collected_hosts:                      # everyone talks to AD/DNS, gets RDP from JUMP01 and backup from BACKUP01
        if h in ("DC01", "DC02"):
            continue
        for dc in ("DC01", "DC02"):
            for port, pers in ((53, 0.9), (88, 0.5), (389, 0.6), (445, 0.2), (135, 0.1)):
                flows.append((h, dc, port, "lsass" if port != 53 else "svchost", "lsass", pers))
        if h != "JUMP01":
            flows.append(("JUMP01", h, 3389, "mstsc", "svchost", 0.02))
        if h != "BACKUP01":
            flows.append(("BACKUP01", h, 6160, "Veeam.Backup.Manager", "VeeamDeploymentSvc", 0.05))
    flows.append(("LEGACY01", "DC01", 389, "", "lsass", 0.5))

    for client, server, port, cproc, sproc, pers in flows:
        ch, sh = hostname(client), hostname(server)
        cip = ip_of.get(client, client)
        sip = ip_of.get(server, server)
        states = "SynSent" if pers <= 0.01 else "Established;TimeWait"
        if ch and host_of[ch][5]:
            add(ch, "Outbound", sip, port, cproc, pers, states)
        if sh and host_of[sh][5] and states != "SynSent":
            add(sh, "Inbound", cip, port, sproc, pers)
            listeners[sh].add((port, sproc))

    for h in collected_hosts:
        spec = host_of[h]
        d = coll / h
        d.mkdir(parents=True, exist_ok=True)
        _write(d / f"{h}_connections.csv", rows[h])
        _write(d / f"{h}_listeners.csv", [
            {"Hostname": h, "LocalAddress": "0.0.0.0", "LocalPort": p, "ProcessName": proc, "ProcessPath": "",
             "ServiceNames": "", "FirstSeen": START.strftime(FMT), "LastSeen": END.strftime(FMT)}
            for p, proc in sorted(listeners[h])])
        _write(d / f"{h}_services.csv", [{"Hostname": h, "Name": "AppSvc", "DisplayName": f"{spec[3]} service",
                                          "StartMode": "Auto", "StartName": "LocalSystem", "PathName": "", "ProcessId": 1234}])
        _write(d / f"{h}_hostinfo.csv", [{
            "Hostname": h, "FQDN": f"{h.lower()}.corp.local", "Domain": "corp.local", "OS": spec[2].replace(" (64-bit)", ""),
            "OSVersion": "", "PSVersion": "5.1", "IPAddresses": spec[1],
            "CollectionStart": START.strftime(FMT), "CollectionEnd": END.strftime(FMT),
            # RPT01 was only collected for 5 days
            "Samples": _samples(h), "IntervalSeconds": 15,
            "CollectorVersion": "1.0.0", "Method": "Get-NetTCPConnection"}])
    # RPT01 started late
    info = coll / "RPT01" / "RPT01_hostinfo.csv"
    info.write_text(info.read_text(encoding="utf-8").replace(START.strftime(FMT), (END - timedelta(days=5)).strftime(FMT), 1), encoding="utf-8")

    _write(out / "inventory.csv", [{
        "VM": v[0], "Powerstate": "poweredOn", "DNS Name": f"{(v[6] or v[0]).lower()}.corp.local",
        "Primary IP Address": v[1], "OS according to the VMware Tools": v[2], "Cluster": "PROD-CL01",
        "CPUs": 4, "Memory": 16384, "Application": v[3], "Role": v[4]} for v in VMS])
    _write(out / "waves.csv", [{"VM": vm, "Wave": w} for vm, w in WAVES.items()])
    _write(out / "known-endpoints.csv", [
        {"CIDR": "10.20.0.0/28", "Label": "F5 LTM SNAT (HR)", "Category": "app", "Note": "Load balancer self-IPs; VIP moves to OCI LB"},
        {"CIDR": "10.99.0.25/32", "Label": "SMTP relay", "Category": "infra", "Note": "Exchange on-prem relay"},
    ])
    (out / "wave2-candidates.txt").write_text("# ad-hoc selection for appdepend check --vms-file\nHR-WEB01\nHR-WEB02\nHR-APP01\n", encoding="utf-8")


def _samples(host: str) -> int:
    return SAMPLES * 5 // 21 if host == "RPT01" else SAMPLES


def _write(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        if not rows:
            return
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(rows)
