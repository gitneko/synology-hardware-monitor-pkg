# SNMP P2 — bounded read-only polling

Implemented on 20 October 2026 on branch `snmp`, on top of P0/P1 and product
baseline `2dcc528` / `0.8.0-0034`. P2 adds actual polling to the development
branch. No SPK is produced here: the coordinated 0.9.0 executable/UI/INFO version
change remains part of preparing the first installable implementation in P6.
Traps, source reduction/enrollment, the SNMP editor and hardware/NAS acceptance
remain P3/P4/P5/P7 respectively.

## Implemented behavior

- The daemon, `poll-once`, `device-test` and administrator API connection test
  dispatch to the selected primary protocol. SNMP credentials are unsealed with
  the polling purpose AAD. Redfish credentials and TLS configuration are not
  used for an SNMP primary. Errors cross the API as fixed translated codes.
- Versions are explicit: v1 GET/GETNEXT; v2c GET/GETNEXT/GETBULK; v3 authPriv with
  SHA-1 or SHA-256 and AES-128. There is no SET surface or automatic protocol,
  context, algorithm or security-level downgrade. Community-mode responses are
  correlated, not cryptographically authenticated.
- Each poll owns its UDP socket. The wrapper verifies the complete peer address
  and uses the library's request/version/community/msgID correlation, including
  registered v3 retry IDs. The unchanged library handles BER, HMAC, privacy,
  request/scoped-context validation and timeliness. Wrong-peer/malformed traffic
  consumes received-byte budget and cannot extend the absolute deadline.
- DNS resolution has a three-second deadline and at most 16 returned addresses;
  the previous selected address is preferred while still in the resolved set.
  IPv4 and IPv6 use matching local sockets. A session does not try a second
  address or send credentials to a guessed target after failure.
- Default request timeout: two seconds, at most one timeout retry. Whole poll:
  60 seconds; connection probe: 15 seconds. Shared hard budgets: 512 transmitted
  requests in v1, 128 in v2c/v3, 4096 decoded varbinds and 4 MiB received bytes.
  Each message is limited to 16 KiB. Discovery, Reports, error responses, splits,
  retries and fallback requests count against the same budgets.
- v1 isolates a valid `noSuchName` error index in the failed GET/GETNEXT leaf and
  retries only remaining OIDs/cursors. It never consumes the error response's
  values as observations. Inconsistent status/index combinations are rejected
  before value consumption. Counter64 and v2 exception values are rejected under
  v1, including in error responses. Missing cursors cannot prove recovery.
- Walks use batches of up to eight independent column cursors. Joins retain the
  complete numeric index tuple and enforce the profile's index arity. Sparse
  rows stay sparse. GETBULK starts with ten repetitions, reduces them for
  `tooBig`/oversized responses and falls back to bounded GETNEXT at one
  repetition. Non-increasing OIDs abort; out-of-subtree/end-of-view finishes
  only its cursor. No enterprise-root/full-tree walk is performed.
- A current typed `sysObjectID.0` and `sysUpTime.0` read is mandatory. Discovery
  or cached inventory alone cannot make a probe/poll succeed. `sysDescr.0` and
  `sysName.0` are bounded descriptive evidence. Later failures preserve validated
  partial data and report incomplete polling; absent/invalid hardware status
  remains unknown and retained faults are not cleared.
- Snapshot metadata includes the selected version/profile, target, system
  identity, authenticated v3 engine ID/boots where applicable, agent epoch,
  per-poll counters and component locators. Capabilities use numeric SNMP
  provenance and nullable HTTP status, preserving the existing snapshot contract.
  `complete` means the requested walks completed within their budgets; an
  unsupported group still means incomplete hardware coverage, not healthy
  hardware. Generic sensor availability never supplies a healthy overall status.
- FQDD/valid unique serial identities use stable keys independent of SNMP
  version. Duplicate alleged identities fall back to generation-scoped index
  keys. Names and row positions are never treated as physical identity. Current
  serial/FQDD values are read every poll before they can authorize recovery.
  Identity records are written in the same revision-checked snapshot transaction
  and bounded to 4096 retained records per device.
- The daemon keeps at most 256 runtime device contexts, each with an engine
  cache of at most two targets. Descriptive inventory refreshes after 15 minutes;
  at most 512 inventory values / an estimated 128 KiB are cached per device.
  Larger inventory is rewalked instead of retained. Health, measurements,
  serial/FQDD identities and generic sensor type/scaling are always read afresh.
  Revision, restore epoch, target and agent-epoch changes invalidate runtime
  state. Uptime uses modular arithmetic: wrap is not an agent reboot and an
  agent reboot is not evidence of a host power cycle. A failed initial read
  discards the target engine-cache entry so the next bounded poll can discover
  a replacement engine, still requiring a fresh authenticated read.
- Device configuration, selected credential ciphertext, revision and runtime
  epoch are loaded from one SQLite read snapshot. Both successful and failed
  results check revision/epoch inside their write transaction. This also protects
  against independent CLI writers and an intervening restore. The API probe uses
  a read transaction while preparing kept credentials.
- The existing four-device concurrency and configured pauses are retained.
  Failed/incomplete polls use exponential delay with positive jitter; the base
  is capped at the larger of 15 minutes and the configured interval. Success
  returns to the configured pause. Deleted/disabled devices lose runtime caches.

## Numeric profiles and evidence

`src/snmp/profiles.rs` is the allowlist and normalizer. Original documents/MIBs
were checked locally; URLs, retrieval hashes, delivery provenance and evidence
limits are in [SNMP-P2-SOURCES.json](SNMP-P2-SOURCES.json). No proprietary MIB/PDF,
raw hardware response or runtime MIB parser is shipped.

| Profile | Current scope |
|---|---|
| Dell iDRAC | Global ObjectStatus, PSU status/rated watts/FQDD, fan probe status/RPM subtype/FQDD, temperature probe status/type/tenths Celsius, memory status/FQDD, controller own/rollup status, physical disks and virtual disks with FQDD. |
| HPE iLO 5 | cpqhlth/cpqsm2/cpqida aggregate conditions, resilient-memory aggregate, PSU condition/serial, fan condition/current RPM, temperature condition/Celsius, controller/physical/logical disk conditions and physical disk serials. |
| Generic | ENTITY-MIB descriptions/class/name/serial joined to ENTITY-SENSOR typed values, scale, precision, freshness and operating status. No inferred hardware thresholds; a non-operational sensor is a warning, available sensors retain unknown hardware health. |

The verification caught distinctions that must remain explicit: Dell probe
statuses include lower-threshold/failure codes beyond ObjectStatus 1–6; Dell
fan readings may be ON/OFF instead of RPM; discrete temperature probes have no
numeric reading; PSU output watts describe rated capacity in tenths of a watt;
HPE temperature `-99` is unavailable; generic sensor scale/precision and update
age must be applied before exposing a reading. No OEM error-count heuristic or
write operation is used.

The pinned client uses its authoritative engine as scoped context engine. A
non-empty context name works; an optional configured context engine ID is an
expected identity and must equal the authenticated engine. Arbitrary proxy
context-engine routing is unsupported and fails closed.

## Dependency and verification

Production uses the published `async-snmp =0.18.1` with default features disabled
and RustCrypto enabled, vendored with its MIT/Apache licenses. The checked patch
stack is P0's receiver API patch plus a small decoded-varbind observation hook
for P2's total budget/type filter. BER/USM/crypto/timeliness implementations are
unchanged. `tools/snmp-p0/prepare.py` reconstructs the published checksummed crate,
applies both patches without fuzz and compares every file against
`vendor/async-snmp-provenance.json`. Existing dependency versions were preserved;
23 additional locked dependency versions were added. Notices were regenerated.

Passing checks on this development host:

| Check | Result |
|---|---|
| Product Rust suite | 129 unit tests + 9 integration tests; includes 17 P2 transport/walk/profile/restart/budget cases. Formatting and Clippy with warnings denied pass. |
| Independent Net-SNMP / actual product CLI | v1, v2c, v3 SHA-1/AES-128, v3 SHA-256/AES-128; actual identity probe, encrypted save/poll, snapshot provenance, wrong-credential rejection and redaction. Passed natively and with the static musl executable. |
| Patched-library P0 regression | 5 harness unit tests + all 20 independent reference cases, including v3 security/context/replay and receiver routing. |
| Existing functionality | Redfish/CGI/daemon, pinned legacy TLS and SMTP integration suites pass; frontend 43 tests, Vite build and 19 Python tests pass. |
| Dependency advisory query | OSV queried for 237 exact public package versions on 20 October 2026; no reported advisories. This does not audit local patches. |
| Secret candidates | Entire changed/non-ignored candidate set including vendored source scanned with Gitleaks 8.30.1. Six classified false positives: four file hashes and two RFC 3414 known-answer vectors in upstream tests; no real credential found. Private runtime state and downloaded references remain ignored. |

The synthetic cases cover sparse two-part indexes, isolated v1 errors, v2 bulk
size reduction, typed/scaled and unavailable readings, duplicate identity,
non-advancing checks, strict peer/version/community correlation, limits,
cancellation, incomplete polling, modular uptime/restart, version changes with
stable FQDD, retained faults and stale restore-epoch results. Both native and
static checks are loopback evidence. No SNMP request was sent to a real BMC/NAS;
actual model/firmware availability, permissions, large-inventory performance,
resource measurements, DSM installation/upgrade and long-running behavior remain
P7 acceptance work. SNMP hardware logs, trap receivers and cross-source alarm
reduction are not claimed by P2.

## Reproduce and use on the development branch

Prerequisites for the independent reference run are `snmpd` and `snmpget` from
Net-SNMP. The test creates only temporary loopback agents, private generated
credentials and temporary product state:

```sh
cargo test --locked
cargo build --locked
python3 tools/snmp_p2_integration.py target/debug/hardware-monitor \
  --report .build/snmp-p2/reference-native.json
python3 tools/snmp-p0/run.py --offline
python3 tools/snmp-p0/prepare.py
```

For an SNMP device JSON, select `primary_protocol: "snmp"`, omit Redfish fields
and provide `snmp_poll` with host/port, explicit security version and profile.
Use the structured `DeviceCredentialsInput` already documented in P1; unlike a
Redfish `device-test`, an SNMP test reads that JSON credential envelope on stdin
and requires `snmp.snmp_poll.action: "replace"`. It does not save credentials or
approve a future trap sender. Existing saved credentials are supported by the
administrator API through the explicit `keep` action.

```sh
hardware-monitor --state ./local-state device-test --file device.json < /path/to/private-credentials.json
hardware-monitor --state ./local-state device-put --file device.json --protocol-secrets < /path/to/private-credentials.json
hardware-monitor --state ./local-state poll-once
```

The production listener remains disabled until P3; no privileged port or DSM
network rule is added by P2. Configuration through the ordinary SNMP web editor
is P5 work. Release metadata and an installable 0.9.0 SPK remain P6 work.
