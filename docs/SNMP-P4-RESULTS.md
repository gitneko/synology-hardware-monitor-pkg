# SNMP P4 — shared alarm reduction and causal ordering

Implemented on 21 October 2026 on branch `snmp`, following P0–P3 and the
`PrimaryProtocol` move into the shared device model. The development executable
still identifies as `0.8.0`, package baseline `0.8.0-0034`. The coordinated
**0.9.0** identities and first installable package remain P6. No SPK, real BMC
fault injection or positive native DSM authentication is claimed here.

## Shared transitions and ordering

`src/alarm.rs` now owns the existing transactional observation, grouping and
acknowledgement reducer. Full polls and trusted partial trap input use this same
path. A trap supplies only its proven component observation and the saved full
containment graph; it does not save a replacement measurement snapshot, change
`last_poll`, reset hardware-log baselines or mark unrelated components Unknown.
Trap repetition alone does not request reminder delivery. Inventory age is checked at processing time; the original receive timestamp remains separate, including when a packet waited behind a submission and a newer poll committed meanwhile.

Every mapped verified fault/recovery hint advances a durable per-device clock in
`snmp_alarm_clock`. The daemon and `poll-once` capture that clock before starting
network reads. At commit, a poll that predates relevant accepted trap evidence
cannot lower the component or its dependent rollups. Useful unrelated data still
commits. The clock survives restart, receipt/history pruning and event-log clear;
it is runtime state excluded from logical app archives. Device revision and the
existing durable restore epoch independently reject obsolete work.

A mapped v3 fault raises/updates the canonical alarm immediately with provisional
trap evidence and requests a bounded confirming primary poll. The confirming
poll does not create a second alarm/automatic submission for the same transition.
Recovery/information/inserted traps are hints: **only a later explicit primary
reading can resolve the fault**. Unknown, missing, incomplete or unsupported
coverage and changed/ambiguous component identities retain it without expiry.
A complete confirming component reading updates source/confirmation; confirmed
OK resolves once. Unrelated hardware alarms remain separate.

The receiver consumer now shares the actual API/SMTP submission gate, acquiring
it before its ingestion gate and transaction. Configuration, acknowledgement,
restore and trap-generated job commits therefore preserve existing submission
semantics. Receipt/evidence/transition/job changes commit atomically. Accepted
input also requests reconciliation after commit, so a poll that raced ahead of
the consumer cannot consume the only pending confirmation request.

## Concrete identity and notification profiles

The numeric allowlist was checked against the exact vendor-authored MIBs already
recorded in [SNMP-P2-SOURCES.json](SNMP-P2-SOURCES.json); proprietary MIBs/PDFs
remain outside the repository. Typed OCTET STRING/integer fields are required;
malformed/duplicate identity bindings are not converted into proof.

| Profile | Recognized notifications and identity |
|---|---|
| Dell iDRAC | Exact system subtree `1.3.6.1.4.1.674.10892.5.3.2.1.0`: fan 2153–2155, temperature 2161–2163, PSU 2185–2187, memory 2265–2267 and physical disk 2297–2299. Fixed failure/warning/information roles follow the individual definitions. Test notification is the separate configuration subtree `.3.2.5.0.10395`. `alertFQDD` is `.3.1.6.0`; `alertMessageID` `.3.1.1.0` supplies a condition type, not an occurrence ID. |
| HPE iLO | Exact canonical `1.3.6.1.4.1.232.0`: fan degraded/failed 6035/6036, inserted hint 6038, PSU OK/degraded/failed 6048/6049/6050. Fan chassis/index and PSU chassis/bay/serial fields are read from their documented table columns. |
| Generic / other OIDs | Unknown diagnostic/event-only input. BMC/ASF PET remains explicitly unsupported. No severity or component is guessed from text or an enterprise-wide prefix. |

Direct changes require a unique current inventory binding for the saved target
and device revision. Inventory is considered usable for at most 15 minutes,
independently of whether measurement data is already stale. Current full polls
replace the mapping set; missing/changed aliases cannot authorize a transition.
For Redfish, only explicit FQDD fields from the resource's Dell OEM data are
persisted as cross-protocol aliases. Names, MemberId, array positions and numeric
SNMP chassis/bay/index values are never guessed to be Redfish identity.

For an SNMP primary, current profile inventory can match a full FQDD, a PSU serial
with its exact SNMP chassis/table locator, or a scoped numeric index. Index-only
matching additionally requires the same authenticated engine ID/boots and current
inventory generation. In particular, an HPE fan's numeric indices cannot directly
update a Redfish component. The current generic Redfish adapter does not establish
an HPE numeric-chassis-to-Redfish crosswalk; even a PSU serial stays event-only
there until adequate scoped identity proof exists. No second SNMP hardware walk
is added to a Redfish primary.

Mapped conditions remain distinct in compact evidence and acknowledgement
signatures. Same-condition input preserves an acknowledgement; a known new or
worsened condition uses the existing invalidation/reannouncement path. Up to 16
condition summaries are retained per component, with an explicit overflow summary
rather than unbounded growth. Evidence is limited to 4 KiB and 4096 component
records per device. An exhausted mapping/evidence capacity falls back to event
history and primary confirmation, without dropping existing active faults.

## Deduplication, event history and provenance

The bounded 4096-entry / 30-second transport duplicate cache still excludes
message/request IDs and source ports. Known fault/recovery/fault sequences for
the same component survive even when uptime and the original fault payload are
identical. A primary-confirmed recovery also ends the mapped duplicate episode when no normal-state trap was sent. This fallback does not promise exact-once delivery for event sources
without a stronger occurrence identifier.

Hardware-log normalization now retains optional record ID, MessageId and
OriginOfCondition, alongside its existing fingerprint/raw historical record.
A separate typed occurrence identity must contain a vendor, unique record ID,
component and generation before automatic cross-source suppression is allowed.
Exact verified occurrence matches cancel only the second automatic submission,
link its provenance and preserve both history records and submitted delivery
history. Synthetic tests cover both arrival orders and absent proof.

**The current native Dell/HPE trap fields do not prove a shared unique log
occurrence ID.** They do not automatically populate this stronger identity.
Equal MessageId, text, severity or nearby timestamps never suppress a hardware
log. Vendor-specific automatic log/trap correlation therefore remains conditional
on proven occurrence metadata, not a claimed feature of every installed firmware.

Accepted unmapped/unknown/test/unverified input uses history kind `snmp_trap` and
CSV/category `trap`. Known verified event-only faults have their profile severity;
all unverified/unknown/test/recovery hints remain non-notifying information.
`selection.snmp_trap` is an independent **default-off** opt-in for verified
fault events, preserving legacy selections. Direct mapped alarms retain the
existing hardware alarm/recovery filters. The dedicated settings/editor controls
and detailed receipt view remain P5.

Event-only history has a seven-day / 10,000-record bound. Pending automatic and
explicitly queued manual submissions are not evicted. If all retained slots are
protected, the normalized receipt records `event_history_full`; it still requests
primary reconciliation. Receipt retention remains seven days / 10,000 records.
Event IDs now advance their durable floor at creation so pruning all rows cannot
reuse a previously allocated identifier.

Dashboard data exposes `last_trap_received`, current/retained `trap_health` and
per-alarm source, provisional state, conditions and confirmation outcome. A known
unacknowledged trap fault remains visible when the measurement snapshot is stale;
it never makes measurements fresh or establishes overall OK. Alarm confirmation
text distinguishes provisional trap evidence. Receiver capability now reports
`health_updates: true` for the implemented trusted mapping path.

History/message context and CSV preserve source, verification, provisional status
and receipt reference. Mail templates additionally accept `{{source}}`,
`{{verified}}` and `{{provisional}}`; existing templates are preserved. Rendered
provisional event messages carry an explicit confirmation-pending suffix in both
languages. Formula-safe CSV escaping and plain-text vendor rendering remain.

## Persistence and verification

This adds one runtime table and a lookup index through the existing additive
schema-2 initializer. Logical format 5 is extended with defaulted JSON fields;
formats 1–4 and existing development format-5 data still import. Imported trap
evidence becomes inactive/non-provisional with `confirmation: restored`; imported
receipts are historical and never replayed as live input. Listener/device pause,
credential re-encryption, acknowledgement review, local engine preservation and
failed-restore rollback retain the P1/P3 contracts.

Passing local checks:

| Check | Result |
|---|---|
| Rust | 164 unit + 9 integration tests, formatting and Clippy with warnings denied. Includes 23 P4 cases covering mapping, arrival orders, rollups/unrelated faults, partial/replaced inventory, acknowledgement, identical fault/recovery/fault payloads, scoped SNMP generation, occurrence proof, bounded retention, restart, restore and the shared submission gate. |
| Actual daemon, native and static musl | Independent Net-SNMP SHA-256/AES-128, a controlled HTTPS Redfish inventory/response and local SMTP. Demonstrates immediate mapped provisional alarm, rejection of old in-flight OK, one submission for trap plus confirmation, poll-owned recovery and a new identical-payload fault occurrence. |
| Receiver/poll regressions | P3 native/static reference cases for v1/v2c/v3, source/security/engine review/restart; P2 actual CLI checks; five P0 harness tests and 20 independent reference cases. |
| Existing application | Redfish/CGI/daemon, pinned legacy TLS and SMTP integration suites; 45 frontend tests, Vite build and 19 Python tests. |
| Static artifact | Generic x86-64 musl executable, no ELF interpreter or dynamic dependencies. No SPK built/published in P4. |

The static P4 load combines valid mapped faults, invalid authenticated-envelope
traffic and unknown source IPs for 60 seconds at approximately 100 packets/second.
It checks automatic polls, actual API scheduling/continued authentication denial,
no duplicate fault submission, and successful local SMTP submissions while the
flood is active. Measurements are in `.build/snmp-p4/reference-musl.json` and its
local evidence summary. This is a development-host test, not NAS capacity,
positive DSM authentication or real-controller acceptance.

Measured on the development host with one synthetic Redfish target/trap context:
6425 total flood packets including warm-up, 4.07 ms maximum
snapshot latency, 0.46 ms maximum denied-API latency,
0.29 daemon CPU seconds during measurement and
10360 KiB peak sampled RSS. Five SMTP submissions cover the intended
fault/recovery transitions; repeated valid fault traffic adds no duplicate job.
These measurements do not establish maximum-device sizing.

A redacted Gitleaks 8.30.1 scan of 192 changed/non-ignored existing candidates,
including the retained vendor tree, found no real secret. Six findings were
classified: four byte-verified source-file hashes and two public RFC 3414
known-answer vectors. Private fixture/runtime state and build outputs remain
ignored and are not release/commit candidates.

The current dependency audit found two newly published TLS advisories in the
previously locked versions. The root and P0 harness locks now select
`rustls-webpki 0.103.16` and `webpki-roots 1.0.10`, the patched releases documented
by [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) and
[RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html).
The subsequent OSV query for 237 exact public versions reports no advisory;
TLS/SMTP regressions were rerun and license notices regenerated.

The vendor checkout already intentionally omitted upstream CI files, examples
and benchmarks. Its production files still match the checksummed published crate
plus the same two patches byte for byte. The provenance manifest now separately
records hashes of omitted non-production files, and reconstruction verifies both
sets and both patch hashes. Production source cannot be declared omitted. No
runtime SNMP library change was introduced in P4.

Reproduce with private temporary loopback fixtures:

```sh
cargo test --locked
cargo build --locked
python3 tools/snmp_p4_integration.py target/debug/hardware-monitor \
  --report .build/snmp-p4/reference-native.json
python3 tools/snmp_p4_integration.py /path/to/static/hardware-monitor \
  --report .build/snmp-p4/reference-musl.json --load-seconds 60
python3 tools/snmp-p0/run.py --offline
```

The reference helpers wait for a nonzero observed agent time: Net-SNMP `snmptrap -Z boots,0` substitutes host uptime instead of encoding zero. This test-sender behavior was independently checked with OpenSSL ASN.1 decoding; production timeliness rules were not relaxed.

Reference prerequisites are Net-SNMP `snmpd`/`snmpget`/`snmptrap` and OpenSSL for
private local test certificates. Fixtures use no production authentication bypass
and send no request to a real controller or recipient. Actual OEM payloads,
FQDD/serial availability, maximum-inventory sizing, DSM firewall/lifecycle,
notifications and safe real fault/recovery acceptance remain the explicit P7 gate.
