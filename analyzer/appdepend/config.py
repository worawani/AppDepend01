"""Defaults for port classification. Any of these can be overridden with a JSON
config file (see samples/config.json)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Well-known service ports -> (service name, latency sensitivity).
# Latency sensitivity estimates how badly the flow suffers when one end is
# on-prem and the other is in OCI (FastConnect/IPSec adds roughly 2-30 ms RTT per round trip).
#   High   chatty or transactional: DB, SMB, RPC, cache, message bus
#   Medium request/response: HTTP(S), app protocols
#   Low    async or tolerant: SMTP, syslog, file transfer
PORT_CATALOG: dict[int, tuple[str, str]] = {
    20: ("FTP-data", "Low"), 21: ("FTP", "Low"), 22: ("SSH/SFTP", "Low"), 23: ("Telnet", "Low"),
    25: ("SMTP", "Low"), 53: ("DNS", "Medium"), 67: ("DHCP", "Low"), 80: ("HTTP", "Medium"),
    88: ("Kerberos", "Medium"), 110: ("POP3", "Low"), 111: ("RPCbind/NFS", "High"),
    123: ("NTP", "Low"), 135: ("MS-RPC EPM", "High"), 137: ("NetBIOS-NS", "Low"),
    139: ("NetBIOS-SSN", "High"), 143: ("IMAP", "Low"), 161: ("SNMP", "Low"), 389: ("LDAP", "Medium"),
    443: ("HTTPS", "Medium"), 445: ("SMB", "High"), 464: ("Kerberos-pwd", "Medium"),
    465: ("SMTPS", "Low"), 514: ("Syslog", "Low"), 587: ("SMTP-submission", "Low"),
    636: ("LDAPS", "Medium"), 993: ("IMAPS", "Low"), 1433: ("MS SQL", "High"),
    1434: ("MS SQL Browser/DAC", "High"), 1521: ("Oracle DB", "High"), 1522: ("Oracle DB", "High"),
    1688: ("KMS", "Low"), 2049: ("NFS", "High"), 2383: ("SSAS", "High"), 3268: ("AD GC", "Medium"),
    3269: ("AD GC SSL", "Medium"), 3306: ("MySQL", "High"), 3389: ("RDP", "Low"),
    4022: ("SQL Service Broker", "High"), 5022: ("SQL AlwaysOn mirroring", "High"),
    5432: ("PostgreSQL", "High"), 5671: ("AMQPS", "High"), 5672: ("AMQP", "High"),
    5985: ("WinRM", "Low"), 5986: ("WinRM-HTTPS", "Low"), 6379: ("Redis", "High"),
    7001: ("WebLogic", "Medium"), 7002: ("WebLogic SSL", "Medium"), 8000: ("HTTP-alt", "Medium"),
    8080: ("HTTP-alt", "Medium"), 8443: ("HTTPS-alt", "Medium"), 8530: ("WSUS", "Low"),
    8531: ("WSUS SSL", "Low"), 9092: ("Kafka", "High"), 9200: ("Elasticsearch", "Medium"),
    9389: ("AD Web Services", "Medium"), 1414: ("IBM MQ", "High"), 11211: ("Memcached", "High"),
    27017: ("MongoDB", "High"), 50000: ("DB2", "High"), 10050: ("Zabbix agent", "Low"),
    10051: ("Zabbix server", "Low"), 5723: ("SCOM", "Low"), 902: ("VMware Auth", "Low"),
    10443: ("HTTPS-alt", "Medium"), 1812: ("RADIUS", "Medium"), 49: ("TACACS+", "Medium"),
}

# Directory/infra protocols that every Windows VM uses. Flows on these ports are
# real, but they are not reasons to move VMs together. Plan for them with
# shared services in OCI (AD DC, DNS, NTP) instead.
DEFAULT_INFRA_PORTS = {53, 67, 68, 88, 123, 137, 138, 161, 162, 389, 464, 514, 636, 1688,
                       3268, 3269, 5723, 8530, 8531, 9389, 10050, 10051}

# Admin and management access. You need firewall rules for these, but they do not
# count as application dependencies.
DEFAULT_ADMIN_PORTS = {22, 3389, 5985, 5986}


@dataclass
class Settings:
    infra_ports: set[int] = field(default_factory=lambda: set(DEFAULT_INFRA_PORTS))
    admin_ports: set[int] = field(default_factory=lambda: set(DEFAULT_ADMIN_PORTS))
    ignore_ports: set[int] = field(default_factory=set)
    ignore_processes: set[str] = field(default_factory=set)   # lower-case process names
    ignore_cidrs: list[str] = field(default_factory=list)
    shared_vms: set[str] = field(default_factory=set)         # lower-case VM names treated as infra
    port_catalog: dict[int, tuple[str, str]] = field(default_factory=lambda: dict(PORT_CATALOG))
    min_collection_days: float = 14.0
    hub_min_peers: int = 5
    large_group_size: int = 25
    # Move groups only use links present in at least this fraction of samples. 0 = every link.
    # Example: 0.05 lets a nightly report pull (about 3% of samples) cross waves while chatty app<->DB links bind.
    group_min_persistence: float = 0.0

    def service_name(self, port: int) -> str:
        if port in self.port_catalog:
            return self.port_catalog[port][0]
        if 49152 <= port <= 65535:
            return "Dynamic/RPC"
        return f"TCP/{port}"

    def latency_sensitivity(self, port: int) -> str:
        if port in self.port_catalog:
            return self.port_catalog[port][1]
        if 49152 <= port <= 65535:
            return "High"   # dynamic RPC (DCOM, WMI, MSDTC) is chatty
        return "Medium"


def load_settings(path: str | Path | None) -> Settings:
    s = Settings()
    if not path:
        return s
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))

    def ports(key: str, base: set[int]) -> set[int]:
        if key in data:
            return {int(p) for p in data[key]}
        add = {int(p) for p in data.get(f"add_{key}", [])}
        remove = {int(p) for p in data.get(f"remove_{key}", [])}
        return (base | add) - remove

    s.infra_ports = ports("infra_ports", s.infra_ports)
    s.admin_ports = ports("admin_ports", s.admin_ports)
    s.ignore_ports = {int(p) for p in data.get("ignore_ports", [])}
    s.ignore_processes = {p.lower() for p in data.get("ignore_processes", [])}
    s.ignore_cidrs = list(data.get("ignore_cidrs", []))
    s.shared_vms = {v.lower() for v in data.get("shared_vms", [])}
    for port, spec in data.get("port_catalog", {}).items():
        s.port_catalog[int(port)] = (spec[0], spec[1]) if isinstance(spec, list) else (str(spec), "Medium")
    s.min_collection_days = float(data.get("min_collection_days", s.min_collection_days))
    s.hub_min_peers = int(data.get("hub_min_peers", s.hub_min_peers))
    s.large_group_size = int(data.get("large_group_size", s.large_group_size))
    s.group_min_persistence = float(data.get("group_min_persistence_pct", s.group_min_persistence * 100)) / 100
    return s
