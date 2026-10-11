"""Inventory CSV parsing, normalisation and validation. Pure functions with no database access.

Schema: docs/mvp/inventory-csv-schema.md. Canonical headers are accepted, and so are the
common vCenter/RVTools vInfo export headers (matching ignores case and punctuation)."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import uuid
from dataclasses import dataclass, field

PARSER_VERSION = "inventory-1.0.0"
SCHEMA_VERSION = "inventory-csv-v1"

# canonical field -> accepted headers (first match wins; multi-valued fields merge every match)
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "vm_name": ("vm_name", "VM", "VM Name", "Name"),
    "vm_uuid": ("vm_uuid", "VM UUID", "Instance UUID", "VI SDK UUID", "SMBIOS UUID", "UUID"),
    "vcenter": ("vcenter", "vCenter", "vCenter Server", "VI SDK Server"),
    "moref": ("moref", "VM ID", "MoRef", "MOID"),
    "dns_name": ("dns_name", "DNS Name", "FQDN", "Hostname"),
    "guest_os": ("guest_os", "OS according to the VMware Tools", "OS according to the configuration file", "Guest OS", "OS"),
    "power_state": ("power_state", "Powerstate", "Power State", "PowerState"),
    "template": ("template", "Template"),
    "cluster": ("cluster", "Cluster"),
    "datacenter": ("datacenter", "Datacenter"),
    "environment": ("environment", "Environment", "Env"),
    "application": ("application", "Application", "App", "Application Name"),
    "owner": ("owner", "Owner", "Application Owner", "App Owner"),
    "criticality": ("criticality", "Criticality", "Business Criticality"),
    "tier": ("tier", "Tier", "Role"),
}
MULTI_ALIASES: dict[str, tuple[str, ...]] = {
    "ip_addresses": ("ip_addresses", "IP Addresses", "Primary IP Address", "IPv4 Address", "IPv6 Address", "IP Address", "IP"),
    "mac_addresses": ("mac_addresses", "MAC Addresses", "MAC Address", "MAC"),
    "networks": ("networks", "Network", "Networks", "Port Group", "Network #1", "Network #2", "Network #3", "Network #4"),
}
REQUIRED = ("vm_name",)

_LIST_SPLIT = re.compile(r"[;,\s]+")
_NET_SPLIT = re.compile(r"\s*[;|]\s*")
_MAC = re.compile(r"^([0-9a-f]{2})[:-]?([0-9a-f]{2})[:.-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})[:.-]?([0-9a-f]{2})[:-]?([0-9a-f]{2})$")
_POWER = {"poweredon": "poweredOn", "on": "poweredOn", "running": "poweredOn",
          "poweredoff": "poweredOff", "off": "poweredOff", "stopped": "poweredOff",
          "suspended": "suspended"}


class InventoryFileError(ValueError):
    """The file as a whole cannot be processed (encoding, size, missing columns, ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class Issue:
    severity: str            # error | warning | info
    code: str
    message: str
    row_number: int | None = None
    field: str | None = None
    raw_value: str | None = None


@dataclass
class InventoryRecord:
    row_number: int
    vm_name: str
    identity_key: str
    vm_uuid: str | None = None
    vcenter: str | None = None
    moref: str | None = None
    dns_name: str | None = None
    guest_os: str | None = None
    power_state: str | None = None
    cluster: str | None = None
    datacenter: str | None = None
    environment: str | None = None
    application: str | None = None
    owner: str | None = None
    criticality: str | None = None
    tier: str | None = None
    ips: list[str] = field(default_factory=list)
    macs: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)
    raw: dict[str, str] = field(default_factory=dict)
    valid: bool = True

    ATTRS = ("vm_name", "vm_uuid", "vcenter", "moref", "dns_name", "guest_os", "power_state", "cluster", "datacenter",
             "environment", "application", "owner", "criticality", "tier")


@dataclass
class ParseResult:
    source_system: str
    encoding: str
    row_count: int
    records: list[InventoryRecord]
    issues: list[Issue]
    column_map: dict[str, list[str]]

    @property
    def valid_records(self) -> list[InventoryRecord]:
        return [r for r in self.records if r.valid]

    def count(self, severity: str) -> int:
        return sum(1 for i in self.issues if i.severity == severity)

    @property
    def rejected_rows(self) -> int:
        return sum(1 for r in self.records if not r.valid)


def _norm(header: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (header or "").lower())


def identity_key(vcenter: str | None, vm_uuid: str | None, name: str) -> str:
    scope = (vcenter or "").strip().lower()
    if vm_uuid:
        return f"uuid:{scope}:{vm_uuid}"
    return f"name:{scope}:{name.strip().lower()}"


def normalise_uuid(text: str) -> str | None:
    """Accepts 8-4-4-4-12, 32 hex digits, or the VMware BIOS form '42 1f 3a ... -...'."""
    compact = re.sub(r"[\s-]", "", text)
    if not re.fullmatch(r"[0-9a-fA-F]{32}", compact):
        return None
    return str(uuid.UUID(compact))


def normalise_mac(text: str) -> str | None:
    m = _MAC.match(text.strip().lower())
    return ":".join(m.groups()) if m else None


def decode(data: bytes, encoding: str | None) -> tuple[str, str]:
    if encoding:
        try:
            return data.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError) as exc:
            raise InventoryFileError("encoding", f"File cannot be decoded as {encoding}: {exc}") from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InventoryFileError(
            "encoding",
            f"File is not valid UTF-8 (byte offset {exc.start}). Save it as 'CSV UTF-8' or pass the encoding explicitly "
            "(for example cp874 for Thai Windows exports).") from exc
    return text, "utf-8"


def parse_inventory_csv(data: bytes, *, max_bytes: int, max_rows: int, encoding: str | None = None,
                        criticality_values: list[str] | None = None) -> ParseResult:
    if len(data) == 0:
        raise InventoryFileError("empty", "File is empty.")
    if len(data) > max_bytes:
        raise InventoryFileError("too_large", f"File is {len(data):,} bytes; the limit is {max_bytes:,}.")
    text, used_encoding = decode(data, encoding)
    if "\x00" in text:
        raise InventoryFileError("binary", "File contains NUL bytes; it is not a text CSV (an .xlsx saved as .csv?).")

    try:
        dialect = csv.Sniffer().sniff(text[:8192], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.reader(io.StringIO(text), dialect)
    try:
        header = [h.strip() for h in next(reader)]
    except StopIteration:
        raise InventoryFileError("empty", "File has no header row.") from None
    if not any(header):
        raise InventoryFileError("no_header", "Header row is empty.")

    norm_to_index: dict[str, int] = {}
    for i, h in enumerate(header):
        norm_to_index.setdefault(_norm(h), i)
    column_map: dict[str, list[str]] = {}
    single_idx: dict[str, int] = {}
    for fld, aliases in FIELD_ALIASES.items():
        for a in aliases:
            if _norm(a) in norm_to_index:
                single_idx[fld] = norm_to_index[_norm(a)]
                column_map[fld] = [header[single_idx[fld]]]
                break
    multi_idx: dict[str, list[int]] = {}
    for fld, aliases in MULTI_ALIASES.items():
        idx = sorted({norm_to_index[_norm(a)] for a in aliases if _norm(a) in norm_to_index})
        if idx:
            multi_idx[fld] = idx
            column_map[fld] = [header[i] for i in idx]
    missing = [f for f in REQUIRED if f not in single_idx]
    if missing:
        raise InventoryFileError("missing_columns", f"Required column(s) missing: {', '.join(missing)}. "
                                 f"Accepted headers for vm_name: {', '.join(FIELD_ALIASES['vm_name'])}.")

    issues: list[Issue] = []
    used = set(single_idx.values()) | {i for idx in multi_idx.values() for i in idx}
    ignored = [h for i, h in enumerate(header) if i not in used and h]
    if ignored:
        issues.append(Issue("info", "ignored_columns", f"{len(ignored)} column(s) not mapped (kept in raw_record): "
                            + ", ".join(ignored[:20]) + (" ..." if len(ignored) > 20 else "")))

    source_system = "rvtools-vinfo" if "VI SDK Server" in header or "OS according to the VMware Tools" in header else "inventory-csv"
    allowed_crit = {c.lower() for c in (criticality_values or [])}
    records: list[InventoryRecord] = []
    row_count = 0

    for row in reader:
        if not any(c.strip() for c in row):
            continue
        row_count += 1
        if row_count > max_rows:
            raise InventoryFileError("too_many_rows", f"File has more than {max_rows:,} data rows.")
        rn = row_count + 1   # spreadsheet row number (header is row 1)
        raw = {header[i] if i < len(header) else f"column_{i + 1}": v for i, v in enumerate(row)}
        if len(row) != len(header):
            issues.append(Issue("warning", "column_count", f"Row has {len(row)} fields, header has {len(header)}.", rn))

        def get(fld: str) -> str:
            i = single_idx.get(fld)
            return row[i].strip() if i is not None and i < len(row) else ""

        def get_multi(fld: str) -> list[tuple[str, str]]:
            out = []
            for i in multi_idx.get(fld, []):
                if i < len(row) and row[i].strip():
                    out.append((header[i], row[i].strip()))
            return out

        name = get("vm_name")
        if get("template").lower() in ("true", "yes", "1"):
            issues.append(Issue("info", "template_skipped", f"Template '{name}' skipped.", rn, "template"))
            continue
        rec = InventoryRecord(row_number=rn, vm_name=name, identity_key="", raw=raw)
        if not name:
            issues.append(Issue("error", "missing_name", "vm_name is empty.", rn, "vm_name"))
            rec.valid = False

        raw_uuid = get("vm_uuid")
        if raw_uuid:
            rec.vm_uuid = normalise_uuid(raw_uuid)
            if rec.vm_uuid is None:
                issues.append(Issue("error", "invalid_uuid", "vm_uuid is not a valid UUID.", rn, "vm_uuid", raw_uuid))
                rec.valid = False
        for fld in ("vcenter", "moref", "dns_name", "guest_os", "cluster", "datacenter", "environment",
                    "application", "owner", "tier"):
            setattr(rec, fld, get(fld) or None)

        p = get("power_state")
        if p:
            rec.power_state = _POWER.get(_norm(p))
            if rec.power_state is None:
                issues.append(Issue("warning", "unknown_power_state", "Unrecognised power state; stored empty.", rn,
                                    "power_state", p))
        crit = get("criticality")
        if crit:
            rec.criticality = crit.lower()
            if allowed_crit and rec.criticality not in allowed_crit:
                issues.append(Issue("warning", "unknown_criticality",
                                    f"Criticality not in {sorted(allowed_crit)}; kept as-is.", rn, "criticality", crit))

        for col, value in get_multi("ip_addresses"):
            for part in filter(None, _LIST_SPLIT.split(value)):
                try:
                    ip = ipaddress.ip_address(part.split("%")[0])
                except ValueError:
                    issues.append(Issue("warning", "invalid_ip", f"Not an IP address (column '{col}'); ignored.", rn,
                                        "ip_addresses", part))
                    continue
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                    continue
                if str(ip) not in rec.ips:
                    rec.ips.append(str(ip))
        for col, value in get_multi("mac_addresses"):
            for part in filter(None, re.split(r"[;,\s]+", value)):
                mac = normalise_mac(part)
                if mac is None:
                    issues.append(Issue("warning", "invalid_mac", f"Not a MAC address (column '{col}'); ignored.", rn,
                                        "mac_addresses", part))
                elif mac not in rec.macs:
                    rec.macs.append(mac)
        for _, value in get_multi("networks"):
            for part in filter(None, _NET_SPLIT.split(value)):
                if part not in rec.networks:
                    rec.networks.append(part)

        if rec.valid:
            rec.identity_key = identity_key(rec.vcenter, rec.vm_uuid, rec.vm_name)
            if not rec.vm_uuid:
                issues.append(Issue("info", "name_identity",
                                    "No vm_uuid: identified by vCenter + name, which breaks if the VM is renamed.",
                                    rn, "vm_uuid"))
        records.append(rec)

    _cross_row_checks(records, issues)
    issues.sort(key=lambda i: (i.row_number is not None, i.row_number or 0))   # file-level first, then by row
    return ParseResult(source_system, used_encoding, row_count, records, issues, column_map)


def _cross_row_checks(records: list[InventoryRecord], issues: list[Issue]) -> None:
    by_key: dict[str, list[InventoryRecord]] = {}
    for r in records:
        if r.valid:
            by_key.setdefault(r.identity_key, []).append(r)
    for key, rows in by_key.items():
        if len(rows) > 1:
            what = "vm_uuid" if key.startswith("uuid:") else "vCenter + vm_name (no vm_uuid)"
            nums = ", ".join(str(r.row_number) for r in rows)
            for r in rows:
                r.valid = False
                issues.append(Issue("error", "duplicate_identity", f"Duplicate {what} in rows {nums}; resolve before import.",
                                    r.row_number, "vm_uuid" if key.startswith("uuid:") else "vm_name"))

    by_name: dict[str, set[str]] = {}
    for r in records:
        if r.valid:
            by_name.setdefault(r.vm_name.lower(), set()).add(r.identity_key)
    for name, keys in by_name.items():
        if len(keys) > 1:
            issues.append(Issue("warning", "duplicate_name",
                                f"VM name '{name}' appears {len(keys)} times with different identifiers "
                                "(another vCenter, or a clone?). Name lookups for it are ambiguous.", None, "vm_name"))

    by_ip: dict[str, list[InventoryRecord]] = {}
    for r in records:
        if r.valid:
            for ip in r.ips:
                by_ip.setdefault(ip, []).append(r)
    for ip, rows in by_ip.items():
        if len(rows) > 1:
            names = ", ".join(sorted(r.vm_name for r in rows))
            issues.append(Issue("warning", "shared_ip",
                                f"IP {ip} is reported for {len(rows)} VMs ({names}): VIP, cluster IP, or stale data. "
                                "Flows to this IP will be marked ambiguous.", None, "ip_addresses", ip))
