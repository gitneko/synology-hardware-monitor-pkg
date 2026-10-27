# Implementation status and roadmap

Current package: **0.9.0-0065**. SNMP polling, trap reception, alarm integration,
setup UI, maintained documentation and local package/reference checks are
implemented. The [current acceptance record](VALIDATION.md#current-acceptance)
includes the user's completed core workflow and duplicate-handling acceptance.
APC/Eaton/RFC 1628 UPS profiles ship explicitly untested on real hardware.

## Implemented scope

- Least-privileged DSM 7 x86_64 Rust/Tokio service, SQLite, native session/group
  checks, administrator/viewer API boundary and integrated bilingual Vue window.
- Explicit Redfish or SNMP primary polling, optional independent traps,
  reviewed v3 identity, privileged-port helper and explicit clock compatibility.
- Persistent hardware faults, poll-owned recovery, provisional trap evidence,
  acknowledgement/reset, deduplication/grouping and independent SMTP/desktop jobs.
- Retention, full-history CSV, event clearing and file-backed encrypted streaming
  backup/restore with progress/cancellation and safe paused restoration.
- Local development without DSM/app login, including Redfish/SNMP through normal
  collectors; excluded from SPKs. Static protocol/package and upgrade regressions.

[SNMP](SNMP.md), [Architecture](ARCHITECTURE.md), [Development](DEVELOPMENT.md),
[Compatibility](HARDWARE-COMPATIBILITY.md) and [Validation](VALIDATION.md) own the
maintained contracts. Temporary phase/review/result reports have been consolidated
and removed. Required numeric source records, dependency licenses/checksums,
patch reconstruction and regression harnesses remain.

## Log-query diagnostics and device settings

Implemented after the SNMP merge: disabling Redfish hardware-log reading retires
its query warnings and pending automatic deliveries immediately, including old
states at startup/restore. Real hardware/SNMP faults and history remain intact.
The log-reading controls now appear only for a Redfish primary, including
Redfish with optional traps. Settings survive protocol changes. The user confirmed
installation of 0.9.0-0065 and both reported fixes on the NAS on 27 October 2026.
Local regression coverage and the scope of this confirmation are recorded in the
[implementation record](LOG-QUERY-WARNINGS-FOLLOWUP.md).

## Further validation and release work

These boundaries do not reopen accepted core SNMP checks:

- Broader device/firmware/security coverage, safe multi-fault/partial-recovery
  scenarios, future real UPS tests and explicit iLO license coverage. Record
  actual combinations without borrowing Redfish evidence for SNMP.
- Full DSM Application Privileges/viewer menu integration and directory-service
  groups; additional language/manual-replay and long-running/disk-pressure checks
  listed in [NAS acceptance](NAS-ACCEPTANCE.md).
- Before a commit/push: password/key/runtime-data audit. Before publication:
  review source identity, checked package/checksums, hosted CI results and the
  supported matrix. Local checks do not claim a hosted run or uploaded release.

## Later functionality and prerequisites

| Item | Dependency / acceptance boundary |
|---|---|
| Inform support | Durable ingestion before ACK, retransmission/duplicate and authoritative engine crash/restart review |
| Simultaneous Redfish + SNMP primaries | Explicit source ownership, freshness, precedence and physical cross-source fault matrix |
| Automatic protocol fallback | Deliberate policy for identity, source change, stale state and recovery; no masking TLS/auth/coverage failures |
| Trap-only healthy-state assessment | Independent fault-resolution/freshness semantics; trap silence never means OK |
| Additional vendors / custom MIBs | Reviewed numeric mappings, source/license provenance, fixtures and hardware evidence; no arbitrary runtime scripting |
| Additional security modes | Separate justified compatibility/security review with exact wire tests |
| Forwarding / SNMP SET / power control | Separate feature; current monitoring uses read-only requests |
| Network thresholds / filters | Explicit per-port policy, counter/reset semantics and safe acceptance; current rates are informational |
| Charts / rules / maintenance windows | Separate product design, persistence and alarm-lifecycle work |
| Scheduled app backup | Separate scheduler/delivery/lifecycle design; current export is manual |

No implementation budget is allocated to these future features. Revisit with a
concrete requirement; none is required to use the current bounded SNMP workflow.
