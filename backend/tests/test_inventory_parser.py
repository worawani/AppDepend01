import pytest

from app.importers.inventory import InventoryFileError, normalise_mac, normalise_uuid, parse_inventory_csv
from app.sampledata import CANONICAL_HEADER, canonical_rows, error_rows, rvtools_rows, to_csv

LIMITS = dict(max_bytes=10_000_000, max_rows=5000, criticality_values=["critical", "high", "medium", "low"])


def parse(data: bytes, **kw):
    return parse_inventory_csv(data, **{**LIMITS, **kw})


def codes(result, severity=None):
    return [i.code for i in result.issues if severity is None or i.severity == severity]


def test_canonical_file_is_clean():
    r = parse(to_csv(canonical_rows(), CANONICAL_HEADER))
    assert r.row_count == 15 and len(r.valid_records) == 15
    assert codes(r, "error") == [] and codes(r, "warning") == []
    sql = next(x for x in r.records if x.vm_name == "HR-SQL01")
    assert sql.ips == ["10.20.3.11", "10.20.3.50"]
    assert sql.identity_key.startswith("uuid:vcsa01.corp.example:")
    assert r.source_system == "inventory-csv"


def test_rvtools_headers_and_template_skip():
    r = parse(to_csv(rvtools_rows()))
    assert r.source_system == "rvtools-vinfo"
    assert len(r.valid_records) == 15
    assert "template_skipped" in codes(r, "info")
    assert r.column_map["vm_uuid"] == ["VM UUID"] and r.column_map["vcenter"] == ["VI SDK Server"]
    dc = r.records[0]
    assert dc.power_state == "poweredOn" and dc.moref == "vm-1001" and dc.networks == ["PG-INFRA"]


def test_error_file_rules():
    r = parse(to_csv(error_rows(), CANONICAL_HEADER))
    err = codes(r, "error")
    assert err.count("missing_name") == 1
    assert err.count("invalid_uuid") == 1
    assert err.count("duplicate_identity") == 2          # both rows of the duplicated UUID
    warn = codes(r, "warning")
    for c in ("invalid_ip", "invalid_mac", "shared_ip", "unknown_criticality"):
        assert c in warn, c
    assert "name_identity" in codes(r, "info")
    assert r.rejected_rows == 4 and len(r.valid_records) == 8
    # formula-looking text is stored raw; it is escaped only on export
    owner = next(x for x in r.records if x.owner and x.owner.startswith("="))
    assert owner.owner.startswith("=HYPERLINK")


def test_issue_order_file_level_first_then_rows():
    r = parse(to_csv(error_rows(), CANONICAL_HEADER))
    rows = [i.row_number for i in r.issues]
    file_level = [x for x in rows if x is None]
    assert rows[:len(file_level)] == file_level
    numbered = [x for x in rows if x is not None]
    assert numbered == sorted(numbered)


def test_duplicate_names_without_uuid_are_errors():
    data = b"vm_name,ip_addresses\nAPP01,10.0.0.1\napp01,10.0.0.2\n"
    r = parse(data)
    assert codes(r, "error") == ["duplicate_identity", "duplicate_identity"]


def test_same_name_different_uuid_is_warning_not_error():
    data = (b"vm_name,vm_uuid,vcenter\n"
            b"APP01,11111111-1111-1111-1111-111111111111,vc-a\n"
            b"APP01,22222222-2222-2222-2222-222222222222,vc-b\n")
    r = parse(data)
    assert codes(r, "error") == [] and "duplicate_name" in codes(r, "warning")


def test_ip_normalisation():
    data = b"vm_name,ip_addresses\nA,\"10.0.0.1, 127.0.0.1;fe80::1%4 ::ffff:10.0.0.2 2001:db8::5\"\n"
    r = parse(data)
    assert r.records[0].ips == ["10.0.0.1", "10.0.0.2", "2001:db8::5"]


@pytest.mark.parametrize("text,expected", [
    ("00-50-56-AB-CD-EF", "00:50:56:ab:cd:ef"), ("0050.56ab.cdef", "00:50:56:ab:cd:ef"),
    ("005056abcdef", "00:50:56:ab:cd:ef"), ("00:50:56:zz:00:01", None)])
def test_mac(text, expected):
    assert normalise_mac(text) == expected


@pytest.mark.parametrize("text,ok", [
    ("421F3A6B-0000-1111-2222-333344445555", True), ("42 1f 3a 6b 00 00 11 11-22 22 33 33 44 44 55 55", True),
    ("421f3a6b000011112222333344445555", True), ("not-a-uuid", False), ("421f3a6b", False)])
def test_uuid(text, ok):
    assert (normalise_uuid(text) is not None) is ok


@pytest.mark.parametrize("delim", [",", ";", "\t"])
def test_delimiters(delim):
    data = f"vm_name{delim}ip_addresses{delim}owner\nA{delim}10.0.0.1{delim}x\n".encode()
    r = parse(data)
    assert r.records[0].vm_name == "A" and r.records[0].ips == ["10.0.0.1"]


def test_bom_accepted():
    r = parse("﻿vm_name\nA\n".encode("utf-8"))
    assert r.records[0].vm_name == "A"


def test_non_utf8_rejected_with_guidance_and_explicit_encoding_works():
    data = "vm_name,owner\nA,สมชาย\n".encode("cp874")
    with pytest.raises(InventoryFileError) as e:
        parse(data)
    assert e.value.code == "encoding" and "cp874" in str(e.value)
    r = parse(data, encoding="cp874")
    assert r.records[0].owner == "สมชาย"


@pytest.mark.parametrize("data,code", [
    (b"", "empty"), (b"owner,ip\nx,10.0.0.1\n", "missing_columns"), (b"vm_name\x00\nA\n", "binary")])
def test_file_level_rejections(data, code):
    with pytest.raises(InventoryFileError) as e:
        parse(data)
    assert e.value.code == code


def test_size_and_row_limits():
    with pytest.raises(InventoryFileError) as e:
        parse(b"vm_name\n" + b"A\n" * 10, max_bytes=10)
    assert e.value.code == "too_large"
    rows = "vm_name\n" + "".join(f"VM{i}\n" for i in range(11))
    with pytest.raises(InventoryFileError) as e:
        parse(rows.encode(), max_rows=10)
    assert e.value.code == "too_many_rows"


def test_header_only_file_parses_to_zero_rows():
    r = parse(b"vm_name,ip_addresses\n")
    assert r.row_count == 0 and r.records == []


def test_unknown_columns_kept_raw():
    r = parse(b"vm_name,CPUs,Annotation\nA,4,hello\n")
    assert "ignored_columns" in codes(r, "info")
    assert r.records[0].raw == {"vm_name": "A", "CPUs": "4", "Annotation": "hello"}
