# Telemetry input: parser interface and canonical schemas (v1)

## Compatibility statement

**No vendor format is supported or claimed.** The only registered parsers are the two
vendor-neutral canonical CSV formats below. They have been tested **with synthetic fixtures only**
(`GET /api/telemetry/parsers` reports this per parser in `validation_status`).

A vendor parser (a firewall traffic log, a VDS IPFIX collector export, ...) will be written only after:
1. the customer confirms which source is actually available, and
2. a sanitized, representative sample of it has been provided.

The parser then declares that sample in `validated_samples`. Until then, any source can still be
used by converting it to the canonical CSV outside the tool.

## Candidate sources (to be confirmed by the customer)

| Source | Sees same-segment / same-host VM-to-VM traffic? | Notes |
|---|---|---|
| Firewall traffic logs | Only traffic that crosses the firewall | Good for inter-zone and internet flows. Typically **misses web→app→DB inside one segment** |
| VMware VDS IPFIX (via a collector) | Yes, including intra-host | Requires a Distributed Switch and an IPFIX collector that can export records. **Not assumed to exist** |
| Physical switch NetFlow/sFlow | Partly; misses intra-host traffic; sampling drops rare flows | |
| NSX DFW logs | Yes, if NSX is deployed and rules log | |

Whatever is chosen, the coverage gap of that source must be stated in reports.

## Parser interface (for developers)

`backend/app/telemetry/base.py`

```python
class TelemetryParser(ABC):
    info: ParserInfo     # name, version, kind ("flow" | "address"), required/optional fields,
                         # schema_doc, validated_samples (real samples tested; empty = synthetic only)
    def parse(self, stream, ctx: ParseContext, log: IssueLog, reject, encoding=None)
        -> Iterator[FlowRecord | AddressEvidence]
```

* Yield **canonical records** only. Everything downstream (validation workflow, aggregation,
  storage, endpoint resolution, reports) is source-agnostic.
* Record problems: `log.add(Issue(...))` plus `reject(RejectedRow(...))` (the raw record and its errors).
* Whole-file problems: `raise FileError(code, message)`. The file is then rejected and nothing is imported.
* CSV sources can subclass `CsvTelemetryParser` and implement only `convert(row, ...)`. Header
  checks, streaming, line-accurate encoding errors, limits and rejected-row capture are inherited.
* Register with `registry.register(MyParser)`. `tests/test_telemetry_parsers.py::test_new_source_plugs_in_through_the_interface`
  shows a complete example in about 10 lines.

## Canonical flow CSV: `canonical-flow-csv`

One row per observed connection / flow record. UTF-8, header row, `,` `;` tab or `|` delimited.
Header names are case-insensitive. Unknown columns are ignored (reported once).

| Column | Required | Rules | Error / warning |
|---|---|---|---|
| `ts_start` | **yes** | ISO 8601 **with UTC offset** (`2026-09-01T10:00:00+07:00`, `...Z`). Without an offset, it is accepted only if the batch declares `timezone` (IANA, e.g. `Asia/Bangkok`) | error `missing_timezone` / `invalid_timestamp` |
| `ts_end` | no | same format, ≥ `ts_start` | error `time_order` |
| `src_ip` | **yes** | IPv4/IPv6. IPv4-mapped IPv6 → IPv4. **The initiator (client) of the connection** | error `invalid_ip` |
| `dst_ip` | **yes** | IPv4/IPv6, the destination as logged (pre-NAT) | error `invalid_ip` |
| `dst_port` | **yes** (column) | 0–65535. Value required for tcp/udp/sctp, ignored for icmp etc. | error `missing_value` / `invalid_port` |
| `protocol` | **yes** | `tcp` `udp` `icmp` `icmpv6` `gre` `esp` `sctp` or IANA number 0–255 | error `invalid_protocol` |
| `src_port` | no | 0–65535 | error `invalid_port` |
| `action` | no | allow/accept/permit/pass → `allow`; deny/drop/reject/block → `deny`; empty → `observed`; anything else → `unknown` | warning `unknown_action` |
| `bytes`, `packets` | no | non-negative integers, summed on aggregation | error `invalid_counter` |
| `flow_count` | no | integer ≥ 1 (default 1): records this row represents | error `invalid_counter` |
| `nat_dst_ip` | no | post-DNAT destination. **Used as the effective destination**; the logged `dst_ip` is kept as `dst_ip_original` | error `invalid_ip` |
| `nat_src_ip` | no | validated only. `src_ip` (pre-SNAT) stays the client | error `invalid_ip` |
| `source_device`, `record_ref` | no | `record_ref` is kept (first 5 per aggregate) for traceability back to the source | |

Additional warnings (the record is kept):
* `future_timestamp`: more than 1 day in the future (clock or time-zone problem).
* `outside_window`: outside the declared observation window.
* `possible_reverse_flow`: source port below 32768 and destination port 32768 or higher. Typical of
  unidirectional IPFIX/NetFlow return traffic, where src/dst may be swapped relative to the
  initiator. Counted per aggregate as `reverse_suspect_count`.

## Canonical address evidence CSV: `canonical-address-csv`

DNS / DHCP / IPAM facts used for endpoint resolution. Each row is one IP ↔ hostname/MAC fact with an optional validity period.

| Column | Required | Rules |
|---|---|---|
| `ip` | **yes** | IPv4/IPv6 |
| `record_type` | **yes** | `dns_a` (also `a`, `aaaa`), `dns_ptr` (`ptr`), `dhcp_lease` (`dhcp`, `lease`), `static` (`manual`, `reservation`) |
| `hostname` | one of hostname/mac | valid DNS name, lower-cased, trailing dot removed |
| `mac` | one of hostname/mac; **required for `dhcp_lease`** | normalised to `aa:bb:cc:dd:ee:ff` |
| `valid_from`, `valid_to` | no | ISO 8601 (offset or batch time zone); `valid_to` ≥ `valid_from`. A lease without both → warning `open_lease` (treated as always valid) |
| `source`, `record_ref` | no | |

## Fatal file errors (whole file rejected, HTTP 422, nothing imported)

`unsupported_format` (unknown parser), `schema_mismatch` (required columns missing), `encoding`
(invalid bytes, with the exact line; UTF-16 refused), `binary` (NUL bytes), `empty`, `too_large`,
`too_many_rows`, `too_many_invalid_records` (more than `VDM_MAX_INVALID_RECORD_RATIO`, default 50 %, of
records invalid: almost certainly the wrong format), `no_valid_records`.

## Storage: aggregated on import

Valid flow records are aggregated per `(hour UTC, src_ip, effective dst_ip, dst_ip_original, protocol, dst_port, action)`
with record/flow counts, summed bytes/packets, first/last seen, `reverse_suspect_count`, and up to
5 `record_ref`s. The batch keeps the file SHA-256, the parser name/version, the observation window and the time zone.

**Measured sizing** (500,000 synthetic records with no repetition, i.e. worst case): ~0.6 KB of RAM per
distinct aggregate during import. Parse+validate ran at ~48k records/s and the PostgreSQL commit at ~20k rows/s.
The default `VDM_MAX_TELEMETRY_ROWS` is 2,000,000 (~1.2 GB worst case). Split larger exports, e.g.
per day. Real telemetry repeats conversations and aggregates much better; re-measure with the real sample.
