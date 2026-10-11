"""Aggregation of flow records on import (decision D10): one row per
(hour, src, dst, protocol, dst port, action, pre-NAT dst), so storage grows with distinct
conversations rather than raw session volume."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .base import FlowRecord

MAX_SAMPLE_REFS = 5


@dataclass(slots=True)
class FlowAggregate:
    bucket_start: datetime
    src_ip: str
    dst_ip: str
    dst_ip_original: str | None
    protocol: str
    dst_port: int | None
    action: str
    record_count: int = 0
    flow_count: int = 0
    bytes: int | None = None
    packets: int | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    reverse_suspect_count: int = 0
    sample_refs: list[str] = field(default_factory=list)


class FlowAggregator:
    def __init__(self):
        self.groups: dict[tuple, FlowAggregate] = {}
        self.min_ts: datetime | None = None
        self.max_ts: datetime | None = None
        self.records = 0

    def add(self, r: FlowRecord) -> None:
        bucket = r.ts_start.replace(minute=0, second=0, microsecond=0)
        key = (bucket, r.src_ip, r.dst_ip, r.dst_ip_original, r.protocol, r.dst_port, r.action)
        a = self.groups.get(key)
        if a is None:
            a = self.groups[key] = FlowAggregate(bucket, r.src_ip, r.dst_ip, r.dst_ip_original, r.protocol, r.dst_port, r.action)
        end = r.ts_end or r.ts_start
        a.record_count += 1
        a.flow_count += r.flow_count
        if r.bytes is not None:
            a.bytes = (a.bytes or 0) + r.bytes
        if r.packets is not None:
            a.packets = (a.packets or 0) + r.packets
        a.first_seen = r.ts_start if a.first_seen is None else min(a.first_seen, r.ts_start)
        a.last_seen = end if a.last_seen is None else max(a.last_seen, end)
        a.reverse_suspect_count += int(r.reverse_suspect)
        if len(a.sample_refs) < MAX_SAMPLE_REFS:
            a.sample_refs.append(r.ref)
        self.records += 1
        self.min_ts = r.ts_start if self.min_ts is None else min(self.min_ts, r.ts_start)
        self.max_ts = end if self.max_ts is None else max(self.max_ts, end)
