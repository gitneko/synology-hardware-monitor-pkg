# Implementation status and roadmap

Current build: **0.8.0-0017**, documentation reviewed on 18 October 2026.

## Implemented

- Least-privileged Rust/Tokio daemon, SQLite, integrated DSM 7 window and compiled CGI bridge; device CRUD, checked TLS/private CAs and encrypted credentials.
- Read-only Redfish discovery/polling, standard health/sensors and selected storage/OEM links, log baseline/deduplication and reachability monitoring.
- Persistent alarms, confirmed recoveries, optional reminders, retained faults when observations become unknown, PSU representation deduplication and multi-cause summary grouping.
- Independent SMTP and DSM desktop queues, event filters, per-device enablement, SMTP recipient progress, plain/STARTTLS/implicit TLS, editable templates, local timestamps and manual tests.
- Filtered full-history CSV, audited event clearing, encrypted app backup/restore with paused restart and no replay of pending historical jobs.
- German/English interface, Automatic/Deutsch/English preference, independent saved channel languages, localized new event messages/API errors/CSV headings and English documentation. Historical free text and manufacturer logs are preserved.

## Target acceptance already reported

On RS2421RP+ / DSM 7.4.1-90080, the user confirms installation, the internal window, DSM sign-in, device creation/editing, R340 measurements, explicit PS1 fault handling, Gmail test/reminder email, desktop test/critical reminder with error level and resolved details, and app backup/restore. These reports cover the tested paths, not every possible failure mode. The newly added English paths in build 0017 remain to be accepted on the NAS.

## Next necessary work

1. **Hardware matrix:** live iLO 5 3.22 without Advanced, iDRAC7 and additional controller generations; storage/controller/drive faults, sensors and firmware/permission differences. A real multi-fault and iLO test has been proposed for the following week but has not occurred yet.
2. **NAS language acceptance:** Automatic detection, explicit English/German, error paths, English CSV, SMTP preview/test and the saved desktop language. Confirm an old build-0016 backup can be restored after upgrading.
3. **SNMP:** SNMPv3 polling and traps, HPE/Dell profiles/OIDs, secure device association and cross-protocol deduplication. Not implemented.
4. **DSM permissions/platforms:** full native Application Privileges enforcement and viewer menu access, DSM 7 upgrade/rollback and directory-service behavior.
5. **Long-running operation:** slow discovery versus fast polling, backoff/jitter, per-log-service baselines and rollover handling, bounded fingerprints, log rotation/crash restart, disk-full behavior, resource measurements and longer outage/recovery tests.
6. **Release preparation:** reviewed supported-platform matrix, dependency/tool provenance, repeatable release pipeline, supply-chain/security review and appropriate signing/distribution.

## Later extensions

Maintenance windows, acknowledgement, flapping/debounce, per-component limits/rules and finer recipient/channel profiles. Historical measurement charts are not implemented; the database currently retains the latest snapshot plus event history. Scheduled app backups, streaming large exports and general migration of future incompatible backup formats remain future work.
