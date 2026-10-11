"""Telemetry parser interface.

A parser turns one source format into canonical records:
  * FlowRecord     network conversations (firewall sessions, IPFIX/NetFlow flows, ...)
  * AddressEvidence time-bounded IP <-> hostname/MAC facts (DNS, DHCP, ...)

Everything downstream (validation workflow, aggregation, storage, endpoint resolution) only
sees canonical records, so adding a source means adding a parser class and registering it.

A parser must declare honestly what it has been validated against. `validated_samples` lists
representative real-world samples it has been tested with. Vendor parsers must not be
registered until such a sample exists (see docs/mvp/telemetry-schema.md)."""

from __future__ import annotations

import csv
import ipaddress
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, ClassVar
from zoneinfo import ZoneInfo

from ..importers.common import FileError, Issue, IssueLog, RejectedRow, reserialise, sniff_dialect, text_lines


@dataclass(frozen=True)
class ParserInfo:
    name: str
    version: str
    kind: str                         # "flow" | "address"
    description: str
    schema_doc: str
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    validated_samples: tuple[str, ...] = ()   # real, representative samples this parser was tested with

    @property
    def validation_status(self) -> str:
        return "validated against: " + ", ".join(self.validated_samples) if self.validated_samples \
            else "synthetic fixtures only (no real-world sample validated yet)"


@dataclass
class ParseContext:
    timezone: ZoneInfo | None = None             # applied to timestamps that carry no UTC offset
    window_start: datetime | None = None         # declared observation window (optional)
    window_end: datetime | None = None
    max_rows: int = 5_000_000
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class FlowRecord:
    row_number: int
    ts_start: datetime                # UTC
    ts_end: datetime | None
    src_ip: str
    dst_ip: str                       # effective destination (post-DNAT when nat_dst_ip given)
    dst_ip_original: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    action: str
    bytes: int | None
    packets: int | None
    flow_count: int
    ref: str                          # source record reference (record_ref or "row N")
    reverse_suspect: bool = False


@dataclass
class AddressEvidence:
    row_number: int
    ip: str
    record_type: str                  # dns_a | dns_ptr | dhcp_lease | static
    hostname: str | None
    mac: str | None
    valid_from: datetime | None
    valid_to: datetime | None
    ref: str


class RowError(Exception):
    def __init__(self, code: str, message: str, field: str | None = None, raw_value: str | None = None):
        super().__init__(message)
        self.code, self.field, self.raw_value = code, field, raw_value


class TelemetryParser(ABC):
    info: ClassVar[ParserInfo]

    @abstractmethod
    def parse(self, stream: BinaryIO, ctx: ParseContext, log: IssueLog,
              reject: Callable[[RejectedRow], None], encoding: str | None = None) -> Iterator[FlowRecord | AddressEvidence]:
        """Yield canonical records. Report record-level problems through `log` and `reject`;
        raise FileError for anything that makes the whole file untrustworthy."""

    # The source encoding actually used, set by parse(); reported in the batch metadata.
    used_encoding: str = "utf-8"
    rows_seen: int = 0


# ---------------------------------------------------------------- CSV base + field helpers

_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "58": "icmpv6", "47": "gre", "50": "esp", "132": "sctp"}
_PROTO_NAMES = {"tcp", "udp", "icmp", "icmpv6", "gre", "esp", "sctp"}


def norm_header(h: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", (h or "").strip().lower())


def parse_timestamp(text: str, fld: str, ctx: ParseContext) -> datetime:
    t = text.strip()
    if not t:
        raise RowError("missing_value", f"{fld} is empty.", fld)
    try:
        dt = datetime.fromisoformat(t.replace("Z", "+00:00") if t.endswith("Z") else t)
    except ValueError:
        raise RowError("invalid_timestamp", f"{fld} is not ISO 8601 (e.g. 2026-09-01T10:00:00+07:00).", fld, t) from None
    if dt.tzinfo is None:
        if ctx.timezone is None:
            raise RowError("missing_timezone", f"{fld} has no UTC offset and no batch time zone was given.", fld, t)
        dt = dt.replace(tzinfo=ctx.timezone)
    return dt.astimezone(timezone.utc)


def parse_ip(text: str, fld: str) -> str:
    t = text.strip()
    if not t:
        raise RowError("missing_value", f"{fld} is empty.", fld)
    try:
        ip = ipaddress.ip_address(t.split("%")[0])
    except ValueError:
        raise RowError("invalid_ip", f"{fld} is not an IP address.", fld, t) from None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_port(text: str, fld: str) -> int | None:
    t = text.strip()
    if not t:
        return None
    if not t.isdigit() or int(t) > 65535:
        raise RowError("invalid_port", f"{fld} must be an integer 0-65535.", fld, t)
    return int(t)


def parse_count(text: str, fld: str) -> int | None:
    t = text.strip()
    if not t:
        return None
    if not t.isdigit():
        raise RowError("invalid_counter", f"{fld} must be a non-negative integer.", fld, t)
    return int(t)


def parse_protocol(text: str) -> str:
    t = text.strip().lower()
    if t in _PROTO_NAMES:
        return t
    if t in _PROTO_NUM:
        return _PROTO_NUM[t]
    if t.isdigit() and int(t) <= 255:
        return t
    raise RowError("invalid_protocol", "protocol must be tcp/udp/icmp/... or an IANA number 0-255.", "protocol", text)


class CsvTelemetryParser(TelemetryParser):
    """Header-based CSV parsing with strict required columns. Subclasses implement convert()."""

    @abstractmethod
    def convert(self, row: dict[str, str], row_number: int, ctx: ParseContext,
                warn: Callable[[str, str, str | None, str | None], None]) -> FlowRecord | AddressEvidence:
        """Build a canonical record or raise RowError. `warn(code, message, field, raw_value)`."""

    def parse(self, stream, ctx, log, reject, encoding=None):
        lines, self.used_encoding = text_lines(stream, encoding)
        first = next(lines, None)
        if first is None or not first.strip():
            raise FileError("empty", "File is empty or has no header row.")
        dialect = sniff_dialect(first)

        def all_lines():
            yield first
            yield from lines

        reader = csv.reader(all_lines(), dialect)
        header = [norm_header(h) for h in next(reader)]
        missing = [f for f in self.info.required_fields if f not in header]
        if missing:
            raise FileError("schema_mismatch",
                            f"Not a '{self.info.name}' file: required column(s) missing: {', '.join(missing)}. "
                            f"Found: {', '.join(h for h in header if h) or '(none)'}. See {self.info.schema_doc}.")
        known = set(self.info.required_fields) | set(self.info.optional_fields)
        extra = [h for h in header if h and h not in known]
        if extra:
            log.add(Issue("info", "ignored_columns", f"Column(s) not part of the schema were ignored: {', '.join(extra[:20])}"))
        self.rows_seen = 0
        for fields in reader:
            if not any(f.strip() for f in fields):
                continue
            self.rows_seen += 1
            if self.rows_seen > ctx.max_rows:
                raise FileError("too_many_rows", f"File has more than {ctx.max_rows:,} records.")
            rn = self.rows_seen + 1
            row = {header[i]: v for i, v in enumerate(fields) if i < len(header) and header[i]}

            def warn(code, message, fld=None, raw=None, _rn=rn):
                log.add(Issue("warning", code, message, _rn, fld, raw))

            if len(fields) != len(header):
                warn("column_count", f"Row has {len(fields)} fields, header has {len(header)}.")
            try:
                yield self.convert(row, rn, ctx, warn)
            except RowError as exc:
                log.add(Issue("error", exc.code, str(exc), rn, exc.field, exc.raw_value))
                reject(RejectedRow(rn, reserialise(fields, dialect.delimiter),
                                   [{"code": exc.code, "field": exc.field, "message": str(exc), "raw_value": exc.raw_value}]))


def in_window(ts: datetime, ctx: ParseContext) -> bool:
    return not ((ctx.window_start and ts < ctx.window_start) or (ctx.window_end and ts > ctx.window_end))


FUTURE_TOLERANCE = timedelta(days=1)
