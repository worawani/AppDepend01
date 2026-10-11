import io
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from app.config import Settings
from app.importers.common import FileError, IssueLog
from app.sampledata import ADDRESS_HEADER, FLOW_HEADER, address_rows, flow_error_rows, flow_rows, to_csv
from app.services.telemetry import parse_telemetry
from app.telemetry import registry
from app.telemetry.base import CsvTelemetryParser, FlowRecord, ParseContext, ParserInfo, RowError, parse_ip, parse_timestamp

FLOW = "canonical-flow-csv"
ADDR = "canonical-address-csv"
SETTINGS = Settings(database_url="sqlite://", max_telemetry_upload_mb=5, issue_examples_per_code=3)
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def parse(data: bytes, parser=FLOW, settings=SETTINGS, **ctx):
    return parse_telemetry(io.BytesIO(data), parser, ParseContext(now=NOW, **ctx), settings)


def flow_csv(*rows: dict) -> bytes:
    base = {"ts_start": "2026-09-01T10:00:00+07:00", "src_ip": "10.0.0.1", "src_port": "50000", "dst_ip": "10.0.0.2",
            "dst_port": "1433", "protocol": "tcp"}
    return to_csv([{**base, **r} for r in rows], FLOW_HEADER)


def codes(result, severity=None):
    return [c["code"] for c in result.log.summary() if severity is None or c["severity"] == severity]


# ---------------------------------------------------------------- registry / interface

def test_registry_lists_only_canonical_parsers_with_honest_status():
    names = [p.info.name for p in registry.list_parsers()]
    assert names == [ADDR, FLOW]
    for p in registry.list_parsers():
        assert p.info.validated_samples == ()
        assert "synthetic fixtures only" in p.info.validation_status


def test_unknown_parser_is_fatal():
    with pytest.raises(FileError) as e:
        parse(flow_csv({}), parser="paloalto-traffic")
    assert e.value.code == "unsupported_format"


def test_new_source_plugs_in_through_the_interface():
    """A future vendor parser is just a subclass + register(); the workflow stays unchanged."""

    class PipeDemo(CsvTelemetryParser):
        info = ParserInfo("test-pipe-demo", "0.0.1", "flow", "test only", "n/a", ("when", "a", "b", "port"), ())

        def convert(self, row, rn, ctx, warn):
            ts = parse_timestamp(row["when"], "when", ctx)
            return FlowRecord(rn, ts, None, parse_ip(row["a"], "a"), parse_ip(row["b"], "b"), None, "tcp", None,
                              int(row["port"]), "observed", None, None, 1, f"row {rn}")

    registry.register(PipeDemo)
    try:
        r = parse(b"when|a|b|port\n2026-09-01T10:00:00Z|10.0.0.1|10.0.0.2|443\n", parser="test-pipe-demo")
        assert r.accepted == 1 and len(r.aggregator.groups) == 1
    finally:
        registry._REGISTRY.pop("test-pipe-demo")


# ---------------------------------------------------------------- fatal file-level errors

@pytest.mark.parametrize("data,code", [
    (b"", "empty"),
    (b"time,source,dest\n1,2,3\n", "schema_mismatch"),
    (b"ts_start,src_ip,dst_ip,protocol,dst_port\n\x00\x01\n", "binary"),
])
def test_fatal_file_errors(data, code):
    with pytest.raises(FileError) as e:
        parse(data)
    assert e.value.code == code


def test_encoding_error_mid_file_is_fatal_and_names_line():
    data = flow_csv({}, {}) + "2026-09-01T10:00:00+07:00,,10.0.0.1,1,10.0.0.2,1433,tcp,ผิด\n".encode("cp874")
    with pytest.raises(FileError) as e:
        parse(data)
    assert e.value.code == "encoding" and "line 4" in str(e.value)


def test_size_and_row_limits():
    small = Settings(database_url="sqlite://", max_telemetry_upload_mb=1)
    with pytest.raises(FileError) as e:
        parse(flow_csv(*[{}] * 20000), settings=small)
    assert e.value.code == "too_large"
    with pytest.raises(FileError) as e:
        parse(flow_csv(*[{}] * 11), max_rows=10)
    assert e.value.code == "too_many_rows"


def test_mostly_invalid_file_is_rejected_as_wrong_format():
    with pytest.raises(FileError) as e:
        parse(flow_csv(*[{"src_ip": "x"}] * 30, *[{}] * 5))
    assert e.value.code == "too_many_invalid_records"


def test_file_with_no_valid_record_is_fatal():
    with pytest.raises(FileError) as e:
        parse(flow_csv({"src_ip": "bad"}))
    assert e.value.code == "no_valid_records"


# ---------------------------------------------------------------- record-level validation

def test_error_fixture_every_rule_rejects_and_keeps_raw_row():
    r = parse(to_csv(flow_error_rows(), FLOW_HEADER))
    assert (r.rows, r.accepted, len(r.rejected)) == (48, 40, 8)
    assert set(codes(r, "error")) == {"invalid_ip", "missing_timezone", "time_order", "missing_value", "invalid_protocol",
                                      "invalid_counter", "invalid_port"}
    formula = next(x for x in r.rejected if "BAD-FORMULA" in x.raw)
    assert "=1+1" in formula.raw and formula.errors[0]["code"] == "invalid_ip"


def test_timezone_rules():
    naive = flow_csv({"ts_start": "2026-09-01 10:00:00"})
    with pytest.raises(FileError):          # the only record is invalid -> nothing valid
        parse(naive)
    r = parse(naive, timezone=ZoneInfo("Asia/Bangkok"))
    a = next(iter(r.aggregator.groups.values()))
    assert a.first_seen == datetime(2026, 9, 1, 3, 0, tzinfo=timezone.utc)
    z = parse(flow_csv({"ts_start": "2026-09-01T03:00:00Z"}))
    assert next(iter(z.aggregator.groups.values())).first_seen == a.first_seen


def test_warnings_do_not_reject():
    r = parse(flow_csv({"ts_start": "2027-01-01T00:00:00+00:00"},
                       {"src_port": "1521", "dst_port": "51515"},
                       {"action": "teardown"},
                       {"ts_start": "2026-08-01T00:00:00+00:00"}),
              window_start=datetime(2026, 8, 31, tzinfo=timezone.utc), window_end=datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert r.accepted == 4 and not r.rejected
    assert set(codes(r, "warning")) == {"future_timestamp", "possible_reverse_flow", "unknown_action", "outside_window"}


def test_icmp_needs_no_port_and_action_normalisation():
    r = parse(flow_csv({"protocol": "1", "dst_port": ""}, {"action": "ACCEPT"}, {"action": "drop"}, {"action": ""}))
    actions = sorted(a.action for a in r.aggregator.groups.values())
    assert actions == ["allow", "deny", "observed", "observed"]
    icmp = [a for a in r.aggregator.groups.values() if a.protocol == "icmp"]
    assert icmp and icmp[0].dst_port is None


def test_dnat_uses_translated_destination():
    r = parse(flow_csv({"dst_ip": "203.0.113.10", "nat_dst_ip": "10.40.1.11", "dst_port": "443"}))
    a = next(iter(r.aggregator.groups.values()))
    assert (a.dst_ip, a.dst_ip_original) == ("10.40.1.11", "203.0.113.10")


def test_issue_examples_are_capped_but_counted():
    r = parse(flow_csv(*[{"action": "weird"}] * 10))
    summary = {c["code"]: c for c in r.log.summary()}
    assert summary["unknown_action"]["count"] == 10 and summary["unknown_action"]["shown"] == 3
    shown = [i for i in r.log.issues() if i.code == "unknown_action"]
    assert len(shown) == 3
    assert any(i.code == "issues_truncated" and "7 more" in i.message for i in r.log.issues())


def test_issue_log_counts():
    log = IssueLog(1)
    from app.importers.common import Issue
    for n in range(3):
        log.add(Issue("error", "x", "m", n))
    assert log.count("error") == 3 and len(log.kept) == 1


# ---------------------------------------------------------------- aggregation

def test_aggregation_per_hour_conversation():
    r = parse(flow_csv(
        {"ts_start": "2026-09-01T10:05:00+07:00", "ts_end": "2026-09-01T10:06:00+07:00", "bytes": "100", "flow_count": "2", "record_ref": "A"},
        {"ts_start": "2026-09-01T10:45:00+07:00", "bytes": "50", "src_port": "60000", "record_ref": "B"},
        {"ts_start": "2026-09-01T11:01:00+07:00", "record_ref": "C"}))
    groups = sorted(r.aggregator.groups.values(), key=lambda a: a.bucket_start)
    assert len(groups) == 2
    g = groups[0]
    assert (g.record_count, g.flow_count, g.bytes, g.packets) == (2, 3, 150, None)
    assert g.first_seen.minute == 5 and g.last_seen.minute == 45 and g.sample_refs == ["A", "B"]
    assert r.window_start == g.first_seen


def test_sample_fixture_parses_clean():
    r = parse(to_csv(flow_rows(), FLOW_HEADER))
    assert r.errors == 0 and r.accepted == r.rows
    assert codes(r, "warning") == ["possible_reverse_flow"]


# ---------------------------------------------------------------- address evidence

def test_address_fixture_and_rules():
    r = parse(to_csv(address_rows(), ADDRESS_HEADER), parser=ADDR)
    assert r.accepted == 6 and r.errors == 0
    types = sorted(a.record_type for a in r.addresses)
    assert types == ["dhcp_lease", "dhcp_lease", "dhcp_lease", "dns_a", "dns_ptr", "static"]
    bad = to_csv([
        {"ip": "10.0.0.1", "record_type": "dhcp_lease", "hostname": "pc1"},                       # lease needs mac
        {"ip": "10.0.0.2", "record_type": "cname", "hostname": "x"},                              # bad type
        {"ip": "10.0.0.3", "record_type": "dns_a"},                                               # no hostname/mac
        {"ip": "10.0.0.4", "record_type": "dns_a", "hostname": "bad_host!.example"},              # bad hostname
        {"ip": "10.0.0.5", "record_type": "static", "hostname": "ok.example", "valid_from": "2026-09-02T00:00:00Z",
         "valid_to": "2026-09-01T00:00:00Z"},                                                     # time order
        {"ip": "10.0.0.6", "record_type": "A", "hostname": "Good.Example."},
        {"ip": "10.0.0.7", "record_type": "dhcp", "mac": "AA-BB-CC-DD-EE-FF"},                    # open lease -> warning
        *[{"ip": f"10.0.1.{i}", "record_type": "ptr", "hostname": f"h{i}.example"} for i in range(10)],
    ], ADDRESS_HEADER)
    r = parse(bad, parser=ADDR)
    assert len(r.rejected) == 5 and r.accepted == 12
    assert set(codes(r, "error")) == {"missing_value", "invalid_record_type", "invalid_hostname", "time_order"}
    assert codes(r, "warning") == ["open_lease"]
    good = {a.ip: a for a in r.addresses}
    assert good["10.0.0.6"].hostname == "good.example" and good["10.0.0.7"].mac == "aa:bb:cc:dd:ee:ff"


def test_rowerror_shape():
    e = RowError("c", "m", "f", "v")
    assert (e.code, e.field, e.raw_value, str(e)) == ("c", "f", "v", "m")
