"""End-to-end workflow through the API: inventory -> DNS/DHCP evidence -> flows -> resolution."""

import csv
import io

from sqlalchemy import func, select

from app.models import AddressRecord, AuditEvent, EndpointMapping, FlowObservation, ImportRejectedRow
from app.sampledata import (ADDRESS_HEADER, CANONICAL_HEADER, FLOW_HEADER, WINDOW_END, WINDOW_START, address_rows,
                            canonical_rows, flow_error_rows, flow_rows, to_csv)

REASON = "Rows 42-49 are known-bad test records from the pilot export"


def upload(client, data, parser="canonical-flow-csv", name="flows.csv", **params):
    return client.post("/api/imports/telemetry", params={"parser": parser, **params},
                       files={"file": (name, data, "text/csv")})


def load_world(client):
    assert client.post("/api/imports/inventory", params={"commit": True},
                       files={"file": ("inv.csv", to_csv(canonical_rows(), CANONICAL_HEADER), "text/csv")}).status_code == 200
    r = upload(client, to_csv(address_rows(), ADDRESS_HEADER), parser="canonical-address-csv", name="dns.csv", commit=True)
    assert r.status_code == 200, r.text
    r = upload(client, to_csv(flow_rows(), FLOW_HEADER), commit=True, window_start=WINDOW_START, window_end=WINDOW_END)
    assert r.status_code == 200, r.text
    return r.json()["batch_id"]


def test_parsers_endpoint_is_honest(client):
    ps = client.get("/api/telemetry/parsers").json()
    assert {p["name"] for p in ps} == {"canonical-flow-csv", "canonical-address-csv"}
    assert all(p["validated_samples"] == [] and "synthetic" in p["validation_status"] for p in ps)


def test_preview_writes_nothing_and_reports(client, session):
    r = upload(client, to_csv(flow_error_rows(), FLOW_HEADER))
    body = r.json()
    assert r.status_code == 200 and not body["committed"]
    assert (body["rows"], body["accepted"], body["rejected"], body["errors"]) == (48, 40, 8, 8)
    assert len(body["rejected_preview"]) == 8 and body["rejected_preview"][0]["row_number"] == 42
    assert "synthetic" in body["parser_validation_status"]
    assert session.scalar(select(func.count()).select_from(FlowObservation)) == 0


def test_fatal_errors_are_422_and_nothing_written(client, session):
    r = upload(client, b"time,source\n1,2\n")
    assert r.status_code == 422 and r.json()["detail"]["code"] == "schema_mismatch" and r.json()["detail"]["fatal"]
    r = upload(client, to_csv(flow_rows()[:5], FLOW_HEADER), parser="fortigate-traffic")
    assert r.status_code == 422 and r.json()["detail"]["code"] == "unsupported_format"
    r = upload(client, "﻿ts_start\n".encode("utf-16"))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "encoding"
    assert upload(client, b"x", name="flows.json").status_code == 415
    assert upload(client, to_csv(flow_rows()[:5], FLOW_HEADER), timezone="Mars/Olympus").status_code == 422
    assert upload(client, to_csv(flow_rows()[:5], FLOW_HEADER), window_start="2026-09-01T00:00:00").status_code == 422
    assert session.scalar(select(func.count()).select_from(FlowObservation)) == 0


def test_partial_import_requires_explicit_reason_and_keeps_rejects(client, session):
    data = to_csv(flow_error_rows(), FLOW_HEADER)
    r = upload(client, data, commit=True)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "validation_errors"
    r = upload(client, data, commit=True, allow_partial=True)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "reason_required"
    r = upload(client, data, commit=True, allow_partial=True, partial_reason=REASON)
    assert r.status_code == 200
    batch_id = r.json()["batch_id"]
    batch = client.get(f"/api/imports/{batch_id}").json()
    assert batch["status"] == "committed_partial" and batch["summary"]["partial_import"]["reason"] == REASON
    rejected = client.get(f"/api/imports/{batch_id}/rejected").json()
    assert [x["row_number"] for x in rejected] == list(range(42, 50))
    assert session.scalar(select(func.count()).select_from(ImportRejectedRow)) == 8
    outcomes = session.scalars(select(AuditEvent.outcome).where(AuditEvent.action == "telemetry.import")
                               .order_by(AuditEvent.id)).all()
    assert outcomes == ["refused", "refused", "committed_partial"]


def test_error_report_csv_is_spreadsheet_safe(client):
    data = to_csv(flow_error_rows(), FLOW_HEADER)
    batch_id = upload(client, data, commit=True, allow_partial=True, partial_reason=REASON).json()["batch_id"]
    r = client.get(f"/api/imports/{batch_id}/error-report.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))
    formula = next(x for x in rows if x["raw_value"].endswith("=1+1"))
    assert formula["raw_value"] == "'=1+1" and "BAD-FORMULA" in formula["rejected_row"]
    assert all(not v.startswith(("=", "+", "-", "@")) for row in rows for v in row.values())


def test_duplicate_flow_file_needs_force(client):
    data = to_csv(flow_rows()[:50], FLOW_HEADER)
    first = upload(client, data, commit=True).json()["batch_id"]
    assert upload(client, data).json()["already_imported_as"] == first
    assert upload(client, data, commit=True).status_code == 409
    assert upload(client, data, commit=True, force=True).status_code == 200


def test_partial_disabled_by_admin(settings, client):
    client.app.state.settings.allow_partial_imports = False   # same object the routes read
    try:
        r = upload(client, to_csv(flow_error_rows(), FLOW_HEADER), commit=True, allow_partial=True, partial_reason=REASON)
        assert r.status_code == 409 and r.json()["detail"]["code"] == "partial_disabled"
    finally:
        client.app.state.settings.allow_partial_imports = True


def test_storage_is_aggregated_with_provenance(client, session):
    batch_id = load_world(client)
    batch = client.get(f"/api/imports/{batch_id}").json()
    stored = session.scalar(select(func.count()).select_from(FlowObservation))
    assert stored == batch["summary"]["aggregated_rows"] < batch["row_count"]
    obs = session.scalars(select(FlowObservation).where(FlowObservation.dst_ip_original.is_not(None))).all()
    assert {o.dst_ip for o in obs} == {"10.40.1.11"} and all(o.sample_refs[0].startswith("SYN-NAT") for o in obs)
    assert session.scalar(select(func.count()).select_from(AddressRecord)) == 6
    assert batch["observation_window_start"] is not None


def test_resolution_end_to_end(client, session):
    batch_id = load_world(client)
    summary = client.post(f"/api/resolution/{batch_id}/run").json()
    assert summary["distinct_ips"] == 19
    page = client.get("/api/endpoint-mappings", params={"batch_id": batch_id, "limit": 1000}).json()
    by_ip = {}
    for m in page["items"]:
        by_ip.setdefault(m["ip"], []).append(m)
    def one(ip):
        assert len(by_ip[ip]) == 1, by_ip[ip]
        m = by_ip[ip][0]
        return m["status"], m["vm_name"], m["method"], m["confidence"]

    assert one("10.20.3.50") == ("resolved", "HR-SQL01", "inventory_ip", "high")
    assert one("10.40.1.11") == ("resolved", "CRM-WEB01", "inventory_ip", "high")    # reached through DNAT
    assert one("10.50.0.98") == ("resolved", "LEGACY01", "dns_fqdn", "medium")
    assert one("10.50.0.30") == ("resolved", "RPT01", "dns_name_only", "low")
    assert one("10.50.1.20")[:3] == ("unresolved", None, "dns_unmatched")
    assert one("52.84.10.20")[0] == "unresolved" and by_ip["52.84.10.20"][0]["endpoint_class"] == "external"
    reused = sorted(by_ip["10.60.0.50"], key=lambda m: m["window_start"])
    assert [(m["status"], m["vm_name"], m["confidence"]) for m in reused] == [
        ("resolved", "ERP-APP02", "high"), ("unresolved", None, "none")]
    assert reused[0]["window_end"] <= reused[1]["window_start"]

    review = client.get("/api/endpoint-mappings", params={"batch_id": batch_id, "needs_review": True, "limit": 1000}).json()
    review_ips = {m["ip"] for m in review["items"]}
    assert {"10.50.0.30", "10.50.0.98", "10.50.1.20", "10.60.0.21"} <= review_ips
    assert "10.20.3.50" not in review_ips and "52.84.10.20" not in review_ips

    s = client.get("/api/endpoint-mappings/summary", params={"batch_id": batch_id}).json()
    assert 0 < s["resolved_flow_endpoint_pct"] < 100

    # re-run is idempotent and audited
    first_count = session.scalar(select(func.count()).select_from(EndpointMapping))
    client.post(f"/api/resolution/{batch_id}/run")
    assert session.scalar(select(func.count()).select_from(EndpointMapping)) == first_count
    assert session.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "resolution.run")) == 2


def test_resolution_reflects_new_evidence_on_rerun(client):
    """Importing DNS/DHCP data after the flows and re-running improves the mapping; nothing is stale-cached."""
    client.post("/api/imports/inventory", params={"commit": True},
                files={"file": ("inv.csv", to_csv(canonical_rows(), CANONICAL_HEADER), "text/csv")})
    batch_id = upload(client, to_csv(flow_rows(), FLOW_HEADER), commit=True).json()["batch_id"]
    client.post(f"/api/resolution/{batch_id}/run")
    before = client.get("/api/endpoint-mappings", params={"batch_id": batch_id, "ip": "10.50.0.98"}).json()["items"]
    assert before[0]["status"] == "unresolved"
    upload(client, to_csv(address_rows(), ADDRESS_HEADER), parser="canonical-address-csv", name="dns.csv", commit=True)
    client.post(f"/api/resolution/{batch_id}/run")
    after = client.get("/api/endpoint-mappings", params={"batch_id": batch_id, "ip": "10.50.0.98"}).json()["items"]
    assert (after[0]["status"], after[0]["vm_name"]) == ("resolved", "LEGACY01")


def test_resolution_unknown_batch_404(client):
    assert client.post("/api/resolution/nope/run").status_code == 404
