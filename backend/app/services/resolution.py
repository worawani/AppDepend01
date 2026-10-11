"""Run endpoint resolution for one flow batch and persist the results.

Every distinct IP seen in the batch (source and destination) is resolved per hourly bucket.
Consecutive buckets with the same outcome are stored as one EndpointMapping row with its time
window. Re-running replaces that batch's mappings, so new inventory or DNS/DHCP data can be applied."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import delete, func, select, union_all
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import AddressRecord, AuditEvent, EndpointMapping, FlowObservation, ImportBatch, VmInventory, VmNetworkInterface
from ..resolution.resolver import RESOLVER_VERSION, AddressRef, EndpointResolver, InterfaceRef, Resolution, VmRef


class ResolutionError(Exception):
    pass


@dataclass
class _Group:
    ip: str
    res: Resolution
    start: object
    end: object
    buckets: int
    flows: int


def _as_aware(dt):
    """SQLite returns naive datetimes even for timezone=True columns; values are stored in UTC."""
    from datetime import timezone

    return dt.replace(tzinfo=timezone.utc) if dt is not None and dt.tzinfo is None else dt


def build_resolver(session: Session, settings: Settings) -> EndpointResolver:
    batch_time = {k: _as_aware(v) for k, v in session.execute(select(ImportBatch.id, ImportBatch.imported_at)).all()}
    vms = [VmRef(v.id, v.name, v.dns_name, v.vm_uuid is not None, batch_time[v.last_import_batch_id])
           for v in session.scalars(select(VmInventory))]
    ifaces = [InterfaceRef(i.vm_id, i.ip, i.mac, _as_aware(i.valid_from), _as_aware(i.valid_to))
              for i in session.scalars(select(VmNetworkInterface))]
    addrs = [AddressRef(a.id, a.ip, a.record_type, a.hostname, a.mac, _as_aware(a.valid_from), _as_aware(a.valid_to))
             for a in session.scalars(select(AddressRecord))]
    return EndpointResolver(vms, ifaces, addrs, timedelta(days=settings.inventory_staleness_days))


def run_resolution(session: Session, settings: Settings, flow_batch_id: str, actor: str) -> dict:
    batch = session.get(ImportBatch, flow_batch_id)
    if batch is None or batch.source_type != "telemetry":
        raise ResolutionError(f"No flow (telemetry) batch with id {flow_batch_id}.")
    resolver = build_resolver(session, settings)

    session.execute(delete(EndpointMapping).where(EndpointMapping.flow_batch_id == flow_batch_id))

    # Every (ip, hour) seen at either end of a flow, collapsed and ordered in SQL and streamed,
    # so memory grows with distinct IPs, not with the number of aggregated rows.
    fo = FlowObservation
    ends = union_all(
        select(fo.src_ip.label("ip"), fo.bucket_start.label("bucket"), fo.flow_count.label("flows")).where(fo.batch_id == flow_batch_id),
        select(fo.dst_ip, fo.bucket_start, fo.flow_count).where(fo.batch_id == flow_batch_id)).subquery()
    q = select(ends.c.ip, ends.c.bucket, func.sum(ends.c.flows)).group_by(ends.c.ip, ends.c.bucket) \
        .order_by(ends.c.ip, ends.c.bucket).execution_options(yield_per=10_000)

    cache: dict[tuple, Resolution] = {}
    groups: list[_Group] = []
    last: _Group | None = None
    distinct_ips = 0
    for ip, bucket, flows in session.execute(q):
        bucket, flows = _as_aware(bucket), int(flows)
        key = resolver.cache_key(ip, bucket)
        res = cache.get(key)
        if res is None:
            res = cache[key] = resolver.resolve(ip, bucket)
        if last is None or last.ip != ip:
            distinct_ips += 1
        if last is not None and last.ip == ip and last.res == res:
            last.end = bucket
            last.buckets += 1
            last.flows += flows
        else:
            last = _Group(ip, res, bucket, bucket, 1, flows)
            groups.append(last)

    for g in groups:
        r = g.res
        session.add(EndpointMapping(
            flow_batch_id=flow_batch_id, ip=g.ip, endpoint_class=r.endpoint_class, status=r.status,
            vm_id=r.vm_id, method=r.method, confidence=r.confidence, candidate_vm_ids=list(r.candidates),
            reason=r.reason, evidence={"items": [list(e) for e in r.evidence]},
            window_start=g.start, window_end=g.end + timedelta(hours=1), bucket_count=g.buckets, flow_count=g.flows,
            resolver_version=RESOLVER_VERSION))
    stats: dict[str, int] = {}
    for g in groups:
        k = f"{g.res.status}:{g.res.confidence}"
        stats[k] = stats.get(k, 0) + 1
    summary = {"distinct_ips": distinct_ips, "mapping_rows": len(groups), "by_status_confidence": stats,
               "resolver_version": RESOLVER_VERSION}
    session.add(AuditEvent(actor=actor, action="resolution.run", entity_type="import_batch", entity_id=flow_batch_id,
                           outcome="completed", details=summary))
    session.commit()
    return summary

