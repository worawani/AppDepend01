from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IssueOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    severity: str
    code: str
    message: str
    row_number: int | None = None
    field: str | None = None
    raw_value: str | None = None


class RejectedRowOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    row_number: int
    raw_text: str
    errors: list[dict]


class InventoryImportResult(BaseModel):
    committed: bool
    batch_id: str | None = None
    file_name: str
    file_sha256: str
    source_system: str
    encoding: str
    rows: int
    valid_rows: int
    rejected_rows: int
    new: int
    updated: int
    unchanged: int
    errors: int
    warnings: int
    already_imported_as: str | None = None
    column_map: dict[str, list[str]]
    issues: list[IssueOut]
    rejected_preview: list[RejectedRowOut] = []


class BatchOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    source_type: str
    source_system: str
    file_name: str
    file_sha256: str
    file_size: int
    encoding: str
    parser_version: str
    schema_version: str
    uploaded_by: str
    imported_at: datetime
    status: str
    row_count: int
    accepted_count: int
    rejected_count: int
    warning_count: int
    observation_window_start: datetime | None = None
    observation_window_end: datetime | None = None
    summary: dict


class BatchDetail(BatchOut):
    issues: list[IssueOut]


class InterfaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    ip: str | None
    mac: str | None
    network: str | None


class VmOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    identity_key: str
    name: str
    vcenter: str | None
    vm_uuid: str | None
    moref: str | None
    dns_name: str | None
    guest_os: str | None
    power_state: str | None
    cluster: str | None
    datacenter: str | None
    environment: str | None
    application: str | None
    owner: str | None
    criticality: str | None
    tier: str | None
    first_import_batch_id: str
    last_import_batch_id: str
    source_row_ref: str
    updated_at: datetime
    interfaces: list[InterfaceOut]


class VmPage(BaseModel):
    total: int
    items: list[VmOut]


class IssueCount(BaseModel):
    severity: str
    code: str
    count: int
    shown: int


class ParserOut(BaseModel):
    name: str
    version: str
    kind: str
    description: str
    schema_doc: str
    required_fields: list[str]
    optional_fields: list[str]
    validated_samples: list[str]
    validation_status: str


class TelemetryImportResult(BaseModel):
    committed: bool
    batch_id: str | None = None
    file_name: str
    file_sha256: str
    parser: str
    parser_version: str
    parser_validation_status: str
    kind: str
    encoding: str
    rows: int
    accepted: int
    rejected: int
    errors: int
    warnings: int
    aggregated_rows: int | None
    window_start: datetime | None
    window_end: datetime | None
    already_imported_as: str | None = None
    issue_counts: list[IssueCount]
    issues: list[IssueOut]
    rejected_preview: list[RejectedRowOut]


class EndpointMappingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    flow_batch_id: str
    ip: str
    endpoint_class: str
    status: str
    vm_id: str | None
    vm_name: str | None = None
    method: str
    confidence: str
    candidate_vm_ids: list[str]
    candidate_vm_names: list[str] = []
    reason: str
    evidence: dict
    window_start: datetime
    window_end: datetime
    bucket_count: int
    flow_count: int
    resolver_version: str


class EndpointMappingPage(BaseModel):
    total: int
    items: list[EndpointMappingOut]
