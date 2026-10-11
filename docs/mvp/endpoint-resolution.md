# Endpoint resolution rules (resolver-1.0.0)

Implements approved decision 4. Code: `backend/app/resolution/resolver.py` (pure rules) and
`backend/app/services/resolution.py` (runs a flow batch, stores results). Tests: `tests/test_resolver.py`.

Every distinct IP at either end of a flow batch is resolved **for each hour in which it was observed**,
because the answer can change over time (DHCP, re-used addresses). Consecutive hours with the same
answer are stored as one `endpoint_mapping` row with its time window.

## Rules (first match wins)

| # | Evidence (valid at the observation time) | Result | Confidence |
|---|---|---|---|
| — | Loopback, multicast, broadcast, link-local, reserved | unresolved, class `special` | none |
| R1 | DHCP lease whose MAC is on exactly one inventory VM | resolved `dhcp_lease_mac` | **high**; **medium** if the inventory lists the IP on a different VM (both kept as candidates) |
| R1' | Overlapping leases → MACs of several VMs | **ambiguous** | none |
| R2 | Inventory interface IP on exactly one VM | resolved `inventory_ip` | **high**; **medium** if observed more than `VDM_INVENTORY_STALENESS_DAYS` (default 90) from that VM's last inventory import, or if the VM has no vCenter UUID (name-based identity) |
| R3 | Inventory IP on several VMs (VIP, cluster IP, stale data, overlapping networks) | **ambiguous**, all candidates listed | none |
| R4 | DNS/static (or lease) hostname equal to exactly one VM's DNS name (FQDN) | resolved `dns_fqdn` | **medium** |
| R5 | Only the short host name equals one VM's name or DNS short name | resolved `dns_name_only` | **low** (name-only match, shown for review) |
| R5' | Short name matches several VMs | **ambiguous**; duplicate names are never merged | none |
| R6 | Hostname known but no VM matches | unresolved `dns_unmatched` (evidence kept) | none |
| R6 | Lease MAC not on any VM | unresolved `dhcp_unmatched` | none |
| R6 | Nothing | unresolved `no_match`, class `internal` or `external` | none |

Confidence is an **explainable class, not a probability** (reference §5.1). Every mapping stores
`reason` (human-readable), `evidence` (inventory record / address-record ids), `candidate_vm_ids`, the
time window, the flow volume and `resolver_version`.

## Guarantees

* **No forced matches.** Unresolved and ambiguous endpoints are stored and listed, never assigned to a "best guess".
* **Name-only matches are never high.** A short-name match is `low`; a VM without a vCenter UUID caps an IP match at `medium`.
* **Duplicate names never merge.** Two VMs called `APP01` → ambiguous.
* **Time-relevant.** DHCP/DNS records apply only within `valid_from..valid_to` (inclusive). Inventory interfaces honour their validity fields when set.
* **NAT.** When the source logs `nat_dst_ip`, the translated (internal) address is resolved; the public address is kept on the observation.
* **Re-runnable.** `POST /api/resolution/{batch_id}/run` replaces that batch's mappings, so inventory or DNS/DHCP data imported later is applied. Each run is audited.

## Review

`GET /api/endpoint-mappings?batch_id=…&needs_review=true` lists everything a reviewer should look at:
ambiguous, unresolved internal, and low/medium confidence. `GET /api/endpoint-mappings/summary`
gives the counts and the share of flow endpoints that resolved (dashboard "mapped/unmapped %").

## Known limits

* The inventory snapshot time is the **import** time, not the vCenter export time.
* A DHCP lease without start/end is treated as valid at all times (warned at import).
* Hostnames from DHCP leases count as hostname evidence, but only after R1–R3 have failed.
* Resolution is per hour bucket. A lease that changes in the middle of an hour is evaluated at the start of the hour.
