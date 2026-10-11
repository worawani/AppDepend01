# Import validation workflow (approved decision 3)

The same workflow applies to every import: inventory, flow telemetry, DNS/DHCP evidence.

```
upload ──► FATAL FILE CHECKS ──fail──► 422, file rejected, nothing written
              │ pass
              ▼
         RECORD VALIDATION ──► preview (default): counts, issues, rejected rows, nothing written
              │ commit=true
              ▼
         COMMIT POLICY
           same SHA-256 as an earlier batch, no force ────────────► 409 duplicate_file
           record errors, no allow_partial ──────────────────────► 409 validation_errors
           allow_partial, but admin disabled partial imports ────► 409 partial_disabled
           allow_partial without partial_reason (≥10 chars) ─────► 409 reason_required
              │ pass
              ▼
         batch (committed / committed_partial) + valid records + rejected rows verbatim
         + all issues + audit event (actor, decision, reason)
```

Every refusal is audited too.

## Fatal file-level errors (the file is rejected, nothing is imported)

* Unsupported format (unknown parser) or schema invalid (required columns missing)
* Cannot be decoded safely: invalid bytes (the exact line is named), UTF-16/32, NUL bytes / binary
* Empty file, no header, over the size or row limit
* **More than 50 % of records invalid** (`VDM_MAX_INVALID_RECORD_RATIO`): treated as the wrong
  format rather than offered for partial import
* No valid record at all

## Record-level errors

* The record is excluded from the import and **kept verbatim** with its error(s) (`import_rejected_row`).
* The preview shows the first 50 rejected rows and every issue. Issues of one type beyond 100
  examples are counted and reported as truncated, never silently dropped.
* After commit: `GET /api/imports/{id}/rejected` and `GET /api/imports/{id}/error-report.csv`
  (UTF-8 with BOM, formula-injection-safe). CLI: `--error-report file.csv` works on a preview too.

## Partial import: the explicit, audited decision

`commit=true&allow_partial=true&partial_reason=<why>`. Stored as
`batch.summary.partial_import = {reason, rejected_records, errors, decided_by}` and in the audit event.
The batch status is `committed_partial`.

## Configuration

| Setting | Default | Note |
|---|---|---|
| `VDM_ALLOW_PARTIAL_IMPORTS` | `true` | `false` forbids partial imports entirely. Per request, partial is always opt-in |
| `VDM_PARTIAL_REASON_MIN_LENGTH` | 10 | |
| `VDM_MAX_INVALID_RECORD_RATIO` | 0.5 | above this the file is fatal |
| `VDM_MAX_REJECTED_ROWS_STORED` | 100000 | beyond this, the count is recorded and an explicit warning is stored |
| `VDM_ISSUE_EXAMPLES_PER_CODE` | 100 | examples listed per issue type, all counted |

The safe defaults cannot be weakened into silent partial imports. There is deliberately no setting that makes `allow_partial` the default.
