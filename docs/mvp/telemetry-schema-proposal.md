# Telemetry input: DRAFT v0 (not implemented)

**Status:** proposal for review. The parser is built in Phase 2 **after** the source decision
(reference §14, "Network telemetry": vendor, format, retention).

## Decision needed first: which source actually sees the traffic?

| Source | Sees VM-to-VM traffic in the same VLAN / same ESXi host? | Notes |
|---|---|---|
| Perimeter / inter-zone firewall logs | **No.** Only flows that cross the firewall | Typical web→app→DB in one segment is invisible. Good for north-south and inter-zone flows |
| Physical switch NetFlow/sFlow | Partly. Misses traffic between VMs on the same host and port group | Sampling (sFlow 1:N) also drops rare flows |
| **vSphere Distributed Switch IPFIX** | **Yes**, including intra-host | Agentless, a VDS configuration setting. Needs a VDS (vSphere Enterprise Plus) and an IPFIX collector that can export CSV |
| NSX distributed firewall logs | Yes (if NSX is deployed and rules log) | Rule-level logging must be enabled |

Recommendation: **VDS IPFIX** (or NSX DFW) as the primary east-west source, and firewall logs for inter-zone
and internet flows. If neither VDS nor NSX exists, every report must state that same-segment
dependencies are not observed.

## Canonical flow CSV (target of every vendor parser)

| Column | Required | Notes |
|---|---|---|
| `ts_start` | yes | ISO 8601 **with UTC offset** (`2026-09-01T10:00:00+07:00`). A timestamp without an offset is rejected unless the batch declares a time zone |
| `ts_end` | no | |
| `src_ip`, `dst_ip` | yes | IPv4/IPv6 |
| `src_port`, `dst_port` | dst yes | |
| `protocol` | yes | `tcp`/`udp`/`icmp` or an IANA number |
| `action` | no | `allow`/`deny`. Deny flows are kept but are not counted as working dependencies |
| `bytes`, `packets`, `flow_count` | no | as exported |
| `source_device` | no | firewall/switch name |
| `nat_src_ip`, `nat_dst_ip` | no | post-NAT values where the device logs them |
| `record_ref` | no | original log line / record id for traceability |

Batch metadata (entered at upload): `source_system`, observation window start/end, time zone if
the timestamps lack offsets, and the sampling rate if sampled.

## Storage approach (decision D10)

The raw file is kept with batch metadata (hash, row counts). Rows are **aggregated on import** to
`(batch, src_ip, dst_ip, protocol, dst_port, hour)` with counts, bytes, and first/last seen. Server
vs. client direction is inferred from the well-known/listening port and recorded as an inference.
This keeps PostgreSQL size proportional to distinct conversations, not raw session volume.
