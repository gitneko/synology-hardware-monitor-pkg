# Implementation status and roadmap

Current package build: **0.8.0-0043**, maintenance and large-backup changes updated on 26 October 2026.

## Implemented

- Optional local development mode with the complete frontend/backend, persistent private state and real Redfish polling without DSM or application login. Excluded from normal SPKs; see [Development](DEVELOPMENT.md). SNMP remains unimplemented.

- Least-privileged Rust/Tokio daemon, SQLite, integrated DSM 7 window and compiled CGI bridge; device CRUD, checked TLS/private CAs and encrypted credentials.
- Read-only Redfish discovery/polling, standard health/sensors and selected storage/OEM links, log baseline/deduplication and reachability monitoring.
- Persistent alarms, confirmed recoveries, optional reminders, retained faults when observations become unknown, PSU representation deduplication and multi-cause summary grouping.
- Independent SMTP and DSM desktop queues, event filters, per-device enablement, SMTP recipient progress, plain/STARTTLS/implicit TLS, editable templates, local timestamps and manual tests.
- Independent configurable event/hardware-log retention (90-day defaults), daily/manual cleanup with preview and per-device disabled/all/latest-N log collection. Fixed audit retention of 10,000 entries.
- Filtered full-history CSV, audited event clearing, disk-backed compressed/encrypted large app backup/restore with progress, cancellation, chunked upload and native file download; paused restart and no replay of pending historical jobs.
- German/English interface, Automatic/Deutsch/English preference, independent saved channel languages, localized new event messages/API errors/CSV headings and English documentation. Historical free text and manufacturer logs are preserved.

## Confirmed platform and hardware tests

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). Its functions have been tested with iDRAC7, iDRAC8, iDRAC9 and iLO 5 on the hardware listed in the [README](../README.md).

On RS2421RP+ / DSM 7.4.1-90080, the user confirms installation, the internal window, DSM sign-in, device creation/editing, R340 measurements, explicit PS1 fault handling, Gmail test/reminder email, desktop test/critical reminder with error level and resolved details, and app backup/restore. These reports cover the tested paths, not every possible failure mode. The newly added English paths in build 0017 remain to be accepted on the NAS.

The user also confirms testing of the Dell PowerEdge R420 with iDRAC7 and Dell PowerEdge R330 with iDRAC8. The Dell PowerEdge R340 with iDRAC9 has also been tested. See [Hardware compatibility](HARDWARE-COMPATIBILITY.md) for recorded firmware and evidence.

Authorized testing also verifies the HPE ProLiant DL160 Gen10 with iLO 5 v3.22 using a read-only account: protected Redfish access and complete collector runs with explicit server-certificate pinning. License entitlements and multi-fault behavior were not evaluated.

## Next necessary work

1. **Hardware matrix:** additional model/firmware combinations and explicit iLO license coverage without Advanced; storage/controller/drive faults, sensors and firmware/permission differences. Simultaneous physical faults and partial recovery remain to be tested on real hardware.
2. **NAS language acceptance:** Automatic detection, explicit English/German, error paths, English CSV, SMTP preview/test and the saved desktop language. Confirm an old build-0016 backup can be restored after upgrading.
3. **SNMP:** SNMPv3 polling and traps, HPE/Dell profiles/OIDs, secure device association and cross-protocol deduplication. Not implemented.
4. **DSM permissions/platforms:** full native Application Privileges enforcement and viewer menu access, DSM 7 upgrade/rollback and directory-service behavior.
5. **Long-running operation:** slow discovery versus fast polling, backoff/jitter, per-log-service baselines and rollover handling, bounded fingerprints, log rotation/crash restart, disk-full behavior, resource measurements and longer outage/recovery tests.
6. **Release preparation:** reviewed supported-platform matrix, dependency/tool provenance, repeatable release pipeline, supply-chain/security review and appropriate signing/distribution.

## Later extensions

Maintenance windows, acknowledgement, flapping/debounce, per-component limits/rules and finer recipient/channel profiles. Historical measurement charts are not implemented; the database currently retains the latest snapshot plus event history. Scheduled app backups and general migration of future incompatible backup formats remain future work. The maintenance/large-backup work originally deferred until after SNMP has been brought forward into master.
