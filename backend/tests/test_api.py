from app.sampledata import CANONICAL_HEADER, canonical_rows, error_rows, to_csv

URL = "/api/imports/inventory"


def upload(client, data: bytes, name="inventory.csv", **params):
    return client.post(URL, params=params, files={"file": (name, data, "text/csv")})


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_preview_writes_nothing(client):
    r = upload(client, to_csv(canonical_rows(), CANONICAL_HEADER))
    body = r.json()
    assert r.status_code == 200
    assert (body["committed"], body["new"], body["errors"]) == (False, 15, 0)
    assert client.get("/api/vms").json()["total"] == 0
    assert client.get("/api/imports").json() == []


def test_commit_list_and_detail(client):
    r = upload(client, to_csv(canonical_rows(), CANONICAL_HEADER), commit=True)
    body = r.json()
    assert r.status_code == 200 and body["committed"] and body["batch_id"]
    batches = client.get("/api/imports").json()
    assert [b["id"] for b in batches] == [body["batch_id"]]
    detail = client.get(f"/api/imports/{body['batch_id']}").json()
    assert detail["status"] == "committed" and detail["accepted_count"] == 15
    assert client.get("/api/imports/does-not-exist").status_code == 404


def test_validation_errors_return_409_and_are_audited(client):
    r = upload(client, to_csv(error_rows(), CANONICAL_HEADER), commit=True)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "validation_errors"
    assert client.get("/api/vms").json()["total"] == 0
    r = upload(client, to_csv(error_rows(), CANONICAL_HEADER), commit=True, allow_partial=True,
               partial_reason="Rejected rows belong to retired VMs (ticket CHG-1234)")
    assert r.status_code == 200 and r.json()["rejected_rows"] == 4
    detail = client.get(f"/api/imports/{r.json()['batch_id']}").json()
    assert any(i["code"] == "missing_name" and i["row_number"] == 4 for i in detail["issues"])


def test_duplicate_file_409_then_force(client):
    data = to_csv(canonical_rows(), CANONICAL_HEADER)
    first = upload(client, data, commit=True).json()["batch_id"]
    preview = upload(client, data).json()
    assert preview["already_imported_as"] == first
    r = upload(client, data, commit=True)
    assert r.status_code == 409 and r.json()["detail"]["batch_id"] == first
    assert upload(client, data, commit=True, force=True).status_code == 200


def test_upload_limits(client):
    assert upload(client, b"vm_name\nA\n", name="inv.xlsx").status_code == 415
    big = b"vm_name\n" + b"A" * (1024 * 1024 + 10)
    assert upload(client, big).status_code == 413
    r = upload(client, b"owner\nx\n")
    assert r.status_code == 422 and r.json()["detail"]["code"] == "missing_columns"
    r = upload(client, "vm_name\nสมชาย\n".encode("cp874"))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "encoding"
    assert upload(client, "vm_name\nสมชาย\n".encode("cp874"), encoding="cp874").status_code == 200


def test_vm_search_and_pagination(client):
    upload(client, to_csv(canonical_rows(), CANONICAL_HEADER), commit=True)
    page = client.get("/api/vms", params={"limit": 5, "offset": 0}).json()
    assert page["total"] == 15 and len(page["items"]) == 5
    assert page["items"][0]["name"] == "CRM-SQL01"
    hits = client.get("/api/vms", params={"search": "erp"}).json()
    assert hits["total"] == 4
    by_ip = client.get("/api/vms", params={"search": "10.20.3.50"}).json()
    assert [v["name"] for v in by_ip["items"]] == ["HR-SQL01"]
    assert by_ip["items"][0]["interfaces"][0]["mac"] == "00:50:56:00:00:07"
