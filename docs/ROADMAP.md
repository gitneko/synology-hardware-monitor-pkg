# Implementation status and roadmap

Current package build: **0.9.0-0056**, documentation updated on 23 October 2026. P0–P6 are implemented and locally validated. P7 is partially confirmed: the user confirmed installation of 0.9.0-0051 and the DSM polling profile on 21 October 2026; other SNMP NAS/device acceptance and the documentation completion/cleanup work remain open.

## Implemented

- Optional local development mode with the complete frontend/backend, persistent private state and real Redfish polling without DSM or application login. Excluded from normal SPKs; see [Development](DEVELOPMENT.md). SNMP remains unimplemented.

- Least-privileged Rust/Tokio daemon, SQLite, integrated DSM 7 window and compiled CGI bridge; device CRUD, checked TLS/private CAs and encrypted credentials.
- Read-only Redfish discovery/polling, standard health/sensors and selected storage/OEM links, log baseline/deduplication and reachability monitoring.
- Explicit SNMPv1/v2c/v3 polling, configurable trap reception, reviewed v3 enrollment, shared provisional alarms/poll-owned recovery, bilingual configuration/diagnostics, schema-2 migration and format-5 archives. Native/static protocol/package reference validation is integrated into the build and CI.
- Persistent alarms, confirmed recoveries, optional reminders, retained faults when observations become unknown, PSU representation deduplication and multi-cause summary grouping.
- Operator acknowledgement of known hardware faults, independent of hardware health, with notification suppression, review after restore and reactivation for new/worsening conditions.
- Independent SMTP and DSM desktop queues, event filters, per-device enablement, SMTP recipient progress, plain/STARTTLS/implicit TLS, editable templates, local timestamps and manual tests.
- Filtered full-history CSV, audited event clearing, encrypted app backup/restore with paused restart and no replay of pending historical jobs.
- German/English interface, Automatic/Deutsch/English preference, independent saved channel languages, localized new event messages/API errors/CSV headings and English documentation. Historical free text and manufacturer logs are preserved.

## Confirmed platform and hardware tests

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). Its functions have been tested with iDRAC7, iDRAC8, iDRAC9 and iLO 5 on the hardware listed in the [README](../README.md).

On RS2421RP+ / DSM 7.4.1-90080, the user confirms installation, the internal window, DSM sign-in, device creation/editing, R340 measurements, explicit PS1 fault handling, Gmail test/reminder email, desktop test/critical reminder with error level and resolved details, and app backup/restore. These reports cover the tested paths, not every possible failure mode. The newly added English paths in build 0017 remain to be accepted on the NAS.

The user also confirms testing of the Dell PowerEdge R420 with iDRAC7 and Dell PowerEdge R330 with iDRAC8. The Dell PowerEdge R340 with iDRAC9 has also been tested. See [Hardware compatibility](HARDWARE-COMPATIBILITY.md) for recorded firmware and evidence.

Authorized testing also verifies the HPE ProLiant DL160 Gen10 with iLO 5 v3.22 using a read-only account: protected Redfish access and complete collector runs with explicit server-certificate pinning. License entitlements and multi-fault behavior were not evaluated.

## Next necessary work

1. **Hardware matrix:** additional model/firmware combinations and explicit iLO license coverage without Advanced; storage/controller/drive faults, sensors and firmware/permission differences. Simultaneous physical faults and partial recovery remain to be tested on real hardware.
2. **NAS language acceptance:** Automatic detection, explicit English/German, error paths, English CSV, SMTP preview/test and the saved desktop language. Confirm an old build-0016 backup can be restored after upgrading.
3. **SNMP — 0.9.0 hardware acceptance:** build 0052 adds [generic availability and network discovery](SNMP-GENERIC-NETWORK-RESULTS.md), with real generic/network NAS/controller acceptance pending. integrated SNMPv1/v2c/v3 polling and optional traps, HPE/Dell/Synology DSM polling profiles, secure device association, confirmation and cross-source deduplication. SNMPv3 is the default; v1/v2c are explicitly selected compatibility modes without automatic downgrade. Configurable unprivileged trap listener (default UDP 1162), separate configurable remote polling port (default UDP 161). Bounded SNMPv1/v2c/v3 polling now runs through the daemon, CLI and API connection test ([P2 results](SNMP-P2-RESULTS.md)); supervised configurable trap reception and saved-target v3 enrollment are implemented ([P3 results](SNMP-P3-RESULTS.md)). Shared alarm integration with provisional trap evidence, sequence barriers and poll-owned recovery is implemented ([P4 results](SNMP-P4-RESULTS.md)). The protocol editor, configurable receiver/test view and bilingual provenance are implemented ([P5 results](SNMP-P5-RESULTS.md)); version/package/static validation is implemented ([P6 results](SNMP-P6-RESULTS.md)); build 0.9.0-0051 installation and the DSM polling profile are user-confirmed ([record](SNMP-SYNOLOGY-RESULTS.md)); the remaining real-hardware matrix stays open in P7. P1 configuration, schema-2 migration and format-5 backups are implemented on the development branch ([P1 results](SNMP-P1-RESULTS.md)). P0 is complete: isolated native/static-musl reference tests and a pinned patched receiver API decision; see [P0 results](SNMP-P0-RESULTS.md). See the [reviewed implementation plan](SNMP-IMPLEMENTATION-PLAN.md) for architecture, migration, staged work and release/hardware gates.
4. **DSM permissions/platforms:** full native Application Privileges enforcement and viewer menu access, DSM 7 upgrade/rollback and directory-service behavior.
5. **Long-running operation:** slow discovery versus fast polling, backoff/jitter, per-log-service baselines and rollover handling, bounded fingerprints, log rotation/crash restart, disk-full behavior, resource measurements and longer outage/recovery tests.
6. **Release preparation:** reviewed supported-platform matrix, dependency/tool provenance, repeatable release pipeline, supply-chain/security review and appropriate signing/distribution.

## SNMP completion: documentation and repository cleanup

P7 explicitly includes documentation completion as well as real NAS/hardware
acceptance. The acceptance matrix covers all implemented profiles, including
generic availability/network discovery and APC/Eaton/RFC 1628 UPS polling.
Documentation cleanup can proceed before the remaining device tests, with
untested combinations and pending checks clearly recorded.

The planned deliverables are a maintained `docs/SNMP.md` setup/operation guide;
consolidated architecture, development, compatibility and validation information;
removal of superseded implementation-plan, review and phase/feature-result files;
and removal of obsolete phase references from project-owned docs/code/tools/CI.
Retain necessary source/license/patch provenance and functioning regression tests.
Repair stale claims, duplicate content and broken/orphan links. Update package
checks that currently require the temporary plan, inspect the cleaned SPK, and
run the affected checks before delivering a new package build.

This work is **planned, not completed**. See the
[detailed completion requirements](SNMP-IMPLEMENTATION-PLAN.md#p7-completion-work-acceptance-and-documentation).
When cleanup is implemented, transfer open acceptance items to the maintained
compatibility/validation records and remove the temporary plan and its links.

## Later extensions

Maintenance windows, flapping/debounce, per-component limits/rules and finer recipient/channel profiles. Historical measurement charts are not implemented; the database currently retains the latest snapshot plus event history. Scheduled app backups, streaming large exports and general migration of future incompatible backup formats remain future work. SNMP-specific deferred scope and its prerequisites are listed separately in the [0.9.0 plan](SNMP-IMPLEMENTATION-PLAN.md#13-deferred-work-and-decision-boundaries).


Build 0054 adds APC/Eaton/RFC 1628 UPS polling. Local reference coverage is
recorded in [UPS results](SNMP-UPS-RESULTS.md); actual UPS model/card/firmware,
native DSM installation and fault/recovery acceptance are pending. New UPS
vendor trap correlation remains outside this polling-profile change.


Build 0055 fixes the locally reproduced direct-upgrade startup timeout and adds
explicit post-install state initialization, a longer readiness budget and DSM
status codes. Direct 0.8.0 upgrade acceptance on the reported DS220+/RS2416RP+
remains open; see [observations and regression evidence](VALIDATION.md#build-0055-direct-upgrade-startup-correction-23-october-2026).
