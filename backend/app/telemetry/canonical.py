"""The two vendor-neutral canonical formats (docs/mvp/telemetry-schema.md).

They are the contract every future vendor parser maps onto. They are also directly usable:
any source can be converted to these CSVs with a script or spreadsheet. They are NOT a claim of
compatibility with any vendor export."""

from __future__ import annotations

import re

from .base import (FUTURE_TOLERANCE, AddressEvidence, CsvTelemetryParser, FlowRecord, ParserInfo, RowError,
                   in_window, parse_count, parse_ip, parse_port, parse_protocol, parse_timestamp)
from ..importers.inventory import normalise_mac

SCHEMA_DOC = "docs/mvp/telemetry-schema.md"
EPHEMERAL_START = 32768

_ALLOW = {"allow", "accept", "accepted", "permit", "permitted", "pass", "allowed"}
_DENY = {"deny", "denied", "drop", "dropped", "reject", "rejected", "block", "blocked"}
_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")


class CanonicalFlowCsv(CsvTelemetryParser):
    info = ParserInfo(
        name="canonical-flow-csv", version="1.0.0", kind="flow",
        description="Vendor-neutral flow/session CSV (one row per observed connection or flow record).",
        schema_doc=SCHEMA_DOC,
        required_fields=("ts_start", "src_ip", "dst_ip", "protocol", "dst_port"),
        optional_fields=("ts_end", "src_port", "action", "bytes", "packets", "flow_count", "source_device",
                         "nat_src_ip", "nat_dst_ip", "record_ref"),
    )

    def convert(self, row, rn, ctx, warn):
        g = row.get
        ts_start = parse_timestamp(g("ts_start", ""), "ts_start", ctx)
        ts_end = parse_timestamp(g("ts_end", ""), "ts_end", ctx) if g("ts_end", "").strip() else None
        if ts_end and ts_end < ts_start:
            raise RowError("time_order", "ts_end is earlier than ts_start.", "ts_end", g("ts_end"))
        src_ip = parse_ip(g("src_ip", ""), "src_ip")
        dst_ip = parse_ip(g("dst_ip", ""), "dst_ip")
        protocol = parse_protocol(g("protocol", ""))
        src_port = parse_port(g("src_port", ""), "src_port")
        dst_port = parse_port(g("dst_port", ""), "dst_port")
        if protocol in ("tcp", "udp", "sctp") and dst_port is None:
            raise RowError("missing_value", f"dst_port is required for {protocol}.", "dst_port")
        if protocol not in ("tcp", "udp", "sctp"):
            dst_port = None
        counters = {f: parse_count(g(f, ""), f) for f in ("bytes", "packets", "flow_count")}
        if counters["flow_count"] == 0:
            raise RowError("invalid_counter", "flow_count must be at least 1 when given.", "flow_count", "0")

        nat_dst = g("nat_dst_ip", "").strip()
        dst_original = None
        if nat_dst:
            translated = parse_ip(nat_dst, "nat_dst_ip")
            if translated != dst_ip:
                dst_original, dst_ip = dst_ip, translated
        if g("nat_src_ip", "").strip():
            parse_ip(g("nat_src_ip"), "nat_src_ip")   # validated; src_ip (pre-SNAT) is the real client

        raw_action = g("action", "").strip().lower()
        if not raw_action:
            action = "observed"
        elif raw_action in _ALLOW:
            action = "allow"
        elif raw_action in _DENY:
            action = "deny"
        else:
            action = "unknown"
            warn("unknown_action", "action not recognised as allow/deny; stored as 'unknown'.", "action", raw_action)

        if ts_start > ctx.now + FUTURE_TOLERANCE:
            warn("future_timestamp", "ts_start is in the future (clock or time-zone problem?).", "ts_start", g("ts_start"))
        if not in_window(ts_start, ctx):
            warn("outside_window", "ts_start is outside the declared observation window.", "ts_start", g("ts_start"))
        # Unidirectional exports (IPFIX/NetFlow) contain the server->client return flow as its own record:
        # source on a service port, destination in the ephemeral range (32768+ covers Linux and Windows 2008+).
        reverse = src_port is not None and dst_port is not None and src_port < EPHEMERAL_START <= dst_port
        if reverse:
            warn("possible_reverse_flow", "src_port looks like a service port and dst_port is in the ephemeral range: "
                 "probably a server->client return flow, so src/dst may be swapped relative to the initiator.",
                 "src_port", f"{src_port}->{dst_port}")
        return FlowRecord(rn, ts_start, ts_end, src_ip, dst_ip, dst_original, protocol, src_port, dst_port, action,
                          counters["bytes"], counters["packets"], counters["flow_count"] or 1,
                          g("record_ref", "").strip() or f"row {rn}", reverse)


class CanonicalAddressCsv(CsvTelemetryParser):
    info = ParserInfo(
        name="canonical-address-csv", version="1.0.0", kind="address",
        description="Vendor-neutral DNS/DHCP evidence CSV: IP <-> hostname/MAC with an optional validity period.",
        schema_doc=SCHEMA_DOC,
        required_fields=("ip", "record_type"),
        optional_fields=("hostname", "mac", "valid_from", "valid_to", "source", "record_ref"),
    )
    TYPES = {"dns_a": "dns_a", "a": "dns_a", "aaaa": "dns_a", "dns_ptr": "dns_ptr", "ptr": "dns_ptr",
             "dhcp_lease": "dhcp_lease", "dhcp": "dhcp_lease", "lease": "dhcp_lease", "static": "static",
             "manual": "static", "reservation": "static"}

    def convert(self, row, rn, ctx, warn):
        g = row.get
        ip = parse_ip(g("ip", ""), "ip")
        rtype = self.TYPES.get(g("record_type", "").strip().lower())
        if rtype is None:
            raise RowError("invalid_record_type", f"record_type must be one of {sorted(set(self.TYPES.values()))}.",
                           "record_type", g("record_type"))
        hostname = g("hostname", "").strip().lower().rstrip(".") or None
        if hostname and not _HOSTNAME.match(hostname):
            raise RowError("invalid_hostname", "hostname is not a valid DNS name.", "hostname", g("hostname"))
        mac = None
        if g("mac", "").strip():
            mac = normalise_mac(g("mac"))
            if mac is None:
                raise RowError("invalid_mac", "mac is not a MAC address.", "mac", g("mac"))
        if not hostname and not mac:
            raise RowError("missing_value", "Each record needs a hostname, a mac, or both.", "hostname")
        if rtype == "dhcp_lease" and not mac:
            raise RowError("missing_value", "dhcp_lease records need the client mac.", "mac")
        vf = parse_timestamp(g("valid_from", ""), "valid_from", ctx) if g("valid_from", "").strip() else None
        vt = parse_timestamp(g("valid_to", ""), "valid_to", ctx) if g("valid_to", "").strip() else None
        if vf and vt and vt < vf:
            raise RowError("time_order", "valid_to is earlier than valid_from.", "valid_to", g("valid_to"))
        if rtype == "dhcp_lease" and not (vf and vt):
            warn("open_lease", "DHCP lease without both valid_from and valid_to is treated as valid at all times, "
                 "which weakens time-based matching.", "valid_from")
        return AddressEvidence(rn, ip, rtype, hostname, mac, vf, vt, g("record_ref", "").strip() or f"row {rn}")
