"""Telemetry import workflow: parse (streamed, hashed, size-limited) -> validation preview ->
policy-checked commit of aggregated flows or address evidence, rejected rows, issues and audit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO

from sqlalchemy import insert
from sqlalchemy.orm import Session

from ..config import Settings
from ..importers.common import FileError, Issue, IssueLog, RejectedRow, check_invalid_ratio
from ..models import AddressRecord, FlowObservation, ImportBatch
from ..telemetry.aggregate import FlowAggregator
from ..telemetry.base import AddressEvidence, FlowRecord, ParseContext
from ..telemetry.registry import get_parser
from .policy import audit_import, enforce_commit_policy, previous_batch, store_issues_and_rejects

SCHEMA_VERSION = "telemetry-canonical-v1"


class _HashingLimitedReader:
    """Hashes and counts bytes as the parser streams them; aborts past the size limit."""

    def __init__(self, raw: BinaryIO, limit: int):
        self.raw, self.limit = raw, limit
        self.sha = hashlib.sha256()
        self.size = 0

    def _account(self, chunk: bytes) -> bytes:
        self.size += len(chunk)
        if self.size > self.limit:
            raise FileError("too_large", f"File exceeds {self.limit:,} bytes.")
        self.sha.update(chunk)
        return chunk

    def read(self, n: int = -1) -> bytes:
        return self._account(self.raw.read(n))

    def read1(self, n: int = -1) -> bytes:
        return self._account(self.raw.read1(n) if hasattr(self.raw, "read1") else self.raw.read(n))

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

    readable = staticmethod(lambda: True)
    writable = staticmethod(lambda: False)
    seekable = staticmethod(lambda: False)
    closed = False

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


@dataclass
class TelemetryParseResult:
    parser_name: str
    parser_version: str
    kind: str
    encoding: str
    sha256: str
    size: int
    rows: int
    accepted: int
    log: IssueLog
    rejected: list[RejectedRow]
    aggregator: FlowAggregator | None = None
    addresses: list[AddressEvidence] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None

    @property
    def errors(self) -> int:
        return self.log.count("error")

    @property
    def warnings(self) -> int:
        return self.log.count("warning")


def parse_telemetry(stream: BinaryIO, parser_name: str, ctx: ParseContext, settings: Settings,
                    encoding: str | None = None) -> TelemetryParseResult:
    parser = get_parser(parser_name)
    reader = _HashingLimitedReader(stream, settings.max_telemetry_bytes)
    log = IssueLog(settings.issue_examples_per_code)
    rejected: list[RejectedRow] = []
    agg = FlowAggregator() if parser.info.kind == "flow" else None
    addresses: list[AddressEvidence] = []
    accepted = 0
    for rec in parser.parse(reader, ctx, log, rejected.append, encoding):
        accepted += 1
        if isinstance(rec, FlowRecord):
            agg.add(rec)
        else:
            addresses.append(rec)
    # Drain anything the parser did not read, so the hash covers the whole file.
    while reader.read(1 << 20):
        pass
    if reader.size == 0:
        raise FileError("empty", "File is empty.")
    rows = parser.rows_seen
    check_invalid_ratio(rows, len(rejected), settings.max_invalid_record_ratio)
    if rows and accepted == 0:
        raise FileError("no_valid_records", "No record in the file passed validation.")
    result = TelemetryParseResult(parser.info.name, parser.info.version, parser.info.kind, parser.used_encoding,
                                  reader.sha.hexdigest(), reader.size, rows, accepted, log, rejected, agg, addresses)
    result.window_start = ctx.window_start or (agg.min_ts if agg else None)
    result.window_end = ctx.window_end or (agg.max_ts if agg else None)
    return result


def commit_telemetry(session: Session, result: TelemetryParseResult, *, settings: Settings, file_name: str, actor: str,
                     allow_partial: bool = False, partial_reason: str | None = None, force: bool = False,
                     timezone_name: str | None = None) -> ImportBatch:
    source_type = "telemetry" if result.kind == "flow" else "address"
    prev = previous_batch(session, result.sha256, source_type)
    partial = enforce_commit_policy(settings, errors=result.errors, rejected=len(result.rejected),
                                    allow_partial=allow_partial, partial_reason=partial_reason,
                                    previous_batch_id=prev, force=force)
    batch = ImportBatch(
        source_type=source_type, source_system=result.parser_name, file_name=file_name[:255], file_sha256=result.sha256,
        file_size=result.size, encoding=result.encoding, parser_version=f"{result.parser_name}-{result.parser_version}",
        schema_version=SCHEMA_VERSION, uploaded_by=actor, status="committed_partial" if result.errors else "committed",
        row_count=result.rows, accepted_count=result.accepted, rejected_count=len(result.rejected),
        warning_count=result.warnings, observation_window_start=result.window_start,
        observation_window_end=result.window_end,
        summary={"issue_counts": result.log.summary(), "forced": bool(prev and force), "timezone": timezone_name,
                 "aggregated_rows": len(result.aggregator.groups) if result.aggregator else None,
                 "partial_import": partial and {**partial, "decided_by": actor}},
    )
    session.add(batch)
    session.flush()
    # Rows are built lazily, one chunk at a time: a list of every row dict at once costs
    # more memory than the aggregation itself.
    if result.aggregator:
        _insert_chunked(session, FlowObservation, (
            dict(batch_id=batch.id, bucket_start=a.bucket_start, src_ip=a.src_ip, dst_ip=a.dst_ip,
                 dst_ip_original=a.dst_ip_original, protocol=a.protocol, dst_port=a.dst_port, action=a.action,
                 record_count=a.record_count, flow_count=a.flow_count, bytes=a.bytes, packets=a.packets,
                 first_seen=a.first_seen, last_seen=a.last_seen, reverse_suspect_count=a.reverse_suspect_count,
                 sample_refs=a.sample_refs) for a in result.aggregator.groups.values()))
    if result.addresses:
        _insert_chunked(session, AddressRecord, (
            dict(batch_id=batch.id, ip=a.ip, mac=a.mac, hostname=a.hostname, record_type=a.record_type,
                 valid_from=a.valid_from, valid_to=a.valid_to, source_row_ref=f"{batch.id}:{a.ref}")
            for a in result.addresses))
    dropped = store_issues_and_rejects(session, batch, result.log.issues(), result.rejected,
                                       settings.max_rejected_rows_stored)
    audit_import(session, batch, actor, f"{source_type}.import",
                 {"file_name": file_name, "sha256": result.sha256, "parser": result.parser_name, "rows": result.rows,
                  "accepted": result.accepted, "rejected": len(result.rejected), "rejected_rows_not_stored": dropped,
                  **batch.summary})
    session.commit()
    return batch


def _insert_chunked(session: Session, model, rows, size: int = 5000) -> None:
    chunk = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            session.execute(insert(model), chunk)
            chunk = []
    if chunk:
        session.execute(insert(model), chunk)


def preview_issues(result: TelemetryParseResult) -> list[Issue]:
    return result.log.issues()
