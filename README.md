# Hardware Monitor for Synology

*This Synology package and code was developed by GPT-6.1 Sol and tested by humans.*

Open-source, cross-vendor server hardware monitoring using Redfish or SNMP on a Synology NAS.

Due to thirdparty package limitations imposed by Synology, this package does not integrate natively into Synology notifications
and instead sends e-mails directly using SMTP, configured by you. DSM desktop notifications are available.
You can choose if you want either, none or both.

**Current build: 0.9.0-0056.** The Package Center title is **Hardware Monitor**.

## Features

- A lightweight Rust/Tokio background service, SQLite persistence and a Vue application inside the DSM 7 desktop. No Task Scheduler or loose polling scripts.
- Read-only Redfish polling with capability discovery, standard/selected OEM storage links, power supplies, fans, temperatures, hardware logs and reachability.
- Explicit SNMPv1/v2c/v3 primary polling with bounded manufacturer profiles, independent encrypted credentials and coverage diagnostics.
- Optional SNMP traps on a configurable UDP port (default 1162), reviewed v3 sender identities and provisional alarms confirmed by primary polling. [0.9.0 development notes](docs/RELEASE-NOTES-0.9.0.md).
- Persistent faults, confirmed recoveries, optional reminders, deduplication and grouping of linked summary alarms without merging independent component faults.
- Acknowledge known hardware faults with a reason: blue status, persistent suppression for email/desktop, automatic summary assessment and reactivation on recovery or worsening. [Acknowledgement rules](docs/ALARM-ACKNOWLEDGEMENT.md).
- Independently configured SMTP email and native DSM desktop notifications, event filters and per-device delivery enablement. Editable templates, local timestamps and test actions.
- Manually resend a recorded event to one saved email recipient, with a current-template preview and separate delivery history, without changing the alarm or original event. [Manual email replay](docs/MAIL-REPLAY.md).
- Filtered full-history CSV, audited event clearing and password-encrypted backup/restore, including device/SMTP credentials. Restore pauses monitoring/delivery and cancels old pending jobs.
- Optional data deletion in the DSM uninstall wizard. Data is retained by default; opt in to remove settings, credentials, history, keys and local upgrade backups. [Uninstall behavior](docs/UNINSTALL.md).
- **German and English:** Automatic/Deutsch/English interface selection, separate saved languages for background channels, localized new event text/API messages/CSV headings and English documentation. Custom templates, vendor text and legacy event text are preserved.

HPE iLO SNMP population, fan units and storage limitations are described in the [HPE profile guide](docs/SNMP-HPE.md).

## Compatibility and evidence

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). Prior Redfish functions have been tested with iDRAC7, iDRAC8, iDRAC9 and iLO 5 on the hardware listed below. SNMP 0.9.0 has local native/static reference evidence. On 21 October 2026, the user confirmed installation of build 0.9.0-0051 and operation of the Synology DSM polling profile; the target model/DSM/security combination was not specified. The remaining NAS/BMC SNMP acceptance matrix stays open in P7.

| Platform | Status |
|---|---|
| RS2421RP+ / v1000 / DSM 7.4.1-90080 | Prior-release installation, internal window, sign-in, device management, notification and backup/restore workflows confirmed by the user |
| Synology DSM SNMP target (model/version/security not recorded) | Build 0.9.0-0051 installation and DSM polling profile confirmed by the user on 21 October 2026 |
| Dell PowerEdge R420 / iDRAC7 | Complete live polling and overall health assessment verified |
| Dell PowerEdge R330 / iDRAC8 | Complete live polling and overall health assessment verified |
| Dell PowerEdge R340 / iDRAC9 | Complete live polling and overall health assessment verified |
| HPE ProLiant DL160 Gen10 / iLO 5 3.22 | Complete live polling and overall health assessment verified |

No universal RAID/OEM or production-reliability claim is made. **The development branch implements SNMPv1/v2c/v3 polling and configurable UDP trap reception with verified v3 enrollment.** Verified, unambiguously mapped traps now share the alarm pipeline with primary polling; the protocol editor, receiver settings, sender review and bilingual diagnostics are implemented. Build 0052 adds [scoped generic availability and network-interface discovery](docs/SNMP-GENERIC-NETWORK-RESULTS.md); optional missing sensor/inventory groups no longer block generic assessment. Build 0054 adds [APC, Eaton and RFC 1628 UPS polling profiles](docs/SNMP-UPS-RESULTS.md). The [Synology DSM polling profile](docs/SNMP-SYNOLOGY-RESULTS.md) adds system/power/fan, disk and RAID status; DSM itself does not support SNMP traps. See [P6 package results](docs/SNMP-P6-RESULTS.md), [P5 UI results](docs/SNMP-P5-RESULTS.md), [P4 alarm results](docs/SNMP-P4-RESULTS.md), [P3 receiver results](docs/SNMP-P3-RESULTS.md) and [P2 polling results](docs/SNMP-P2-RESULTS.md). See [hardware compatibility](docs/HARDWARE-COMPATIBILITY.md), [validation](docs/VALIDATION.md) and [roadmap](docs/ROADMAP.md).

## Getting started

1. Download the checked SPK from the release tagged `latest`: `HardwareMonitor-dsm7-x86_64.spk` for DSM 7 (including v1000 and geminilake). Verify it against `SHA256SUMS`, install through Package Center and open Hardware Monitor from DSM. The first release appears after this repository has been pushed to GitHub and its default-branch workflow succeeds.
2. Add an HTTPS management-controller origin and an account with the required hardware-read permissions. Use a trusted certificate chain/private CA with a matching hostname in Standard mode. For older Dell controllers or the tested iLO factory certificate, explicitly select iDRAC7/8 and iLO compatibility and import the exact server certificate from a trusted source; its fingerprint and validity dates are checked before HTTP credentials are sent.
3. Review current/retained alarms and discovered coverage. Missing or unavailable values do not confirm a healthy state or recovery.
4. If delivery is wanted, enable the device notification option, configure the channel and select events. Configure background languages independently of the interface. Existing templates are not overwritten by a language switch.
5. Download an encrypted app backup and retain its password separately. A restore replaces app data, then leaves devices/channels paused for deliberate review and reactivation.

Administrators manage/export/clear/restore; viewers are read-only. The backend checks native DSM identity/groups. Administrative operations additionally require HTTPS, matching origin, the DSM token and a session-bound package CSRF proof. Credentials are locally encrypted and are not returned to the browser.

## Screenshots

English interface, using synthetic example data; no real credentials or private device data are shown.

![Device overview and component health](docs/images/devices-en.jpg)

![Event history with filters and CSV export](docs/images/events-en.jpg)

## Documentation

- [Architecture and trust boundaries](docs/ARCHITECTURE.md)
- [Device management](docs/DEVICE-MANAGEMENT.md)
- [Languages](docs/LANGUAGES.md)
- [Notification channels](docs/NOTIFICATIONS.md), [SMTP/templates](docs/SMTP.md), [DSM desktop notifications](docs/DESKTOP-NOTIFICATIONS.md)
- [Alarm grouping and multiple causes](docs/ALARM-GROUPING.md)
- [CSV, clearing and backup/restore](docs/BACKUP-RESTORE.md)
- [Development, local checks, SPK builds and GitHub releases](docs/DEVELOPMENT.md)
- [DSM package architecture families](docs/PACKAGE-ARCHITECTURES.md)
- [DSM privilege findings](docs/DSM-PRIVILEGES.md)
- [Validation](docs/VALIDATION.md), [roadmap](docs/ROADMAP.md)
- [SNMP polling and traps: implementation plan for 0.9.0](docs/SNMP-IMPLEMENTATION-PLAN.md), [completed P0 spike](docs/SNMP-P0-RESULTS.md), [P1 model and migration](docs/SNMP-P1-RESULTS.md)
- [0.9.0 release notes](docs/RELEASE-NOTES-0.9.0.md), [P6 package validation](docs/SNMP-P6-RESULTS.md)
- [P4 alarm integration and local reference results](docs/SNMP-P4-RESULTS.md); real NAS/controller acceptance remains P7 in the implementation plan.

Runtime state, passwords, tokens and raw private controller responses do not belong in source archives or fixtures.

## Development

```sh
cargo test --locked
cargo build --locked
npm ci --prefix web --ignore-scripts
npm run build --prefix web
node --test --test-isolation=none web/tests/*.test.mjs
python tools/integration_test.py target/debug/hardware-monitor
python tools/smtp_integration_test.py target/debug/hardware-monitor
```

Integration tests use synthetic loopback servers and OpenSSL-generated test certificates. They do not replace positive DSM/hardware acceptance. NAS packages require a statically linked musl build; do not copy a host-glibc binary into an SPK. Exact commands and toolchain boundaries are in [Development](docs/DEVELOPMENT.md).

## Local development without DSM

Run `python3 tools/dev.py` from the project root, then open <http://127.0.0.1:18774/>. The complete frontend and backend run without an application login or SPK build, with persistent local state and real Redfish connections. Device credentials and certificate checks remain required. This optional mode is excluded from normal DSM builds. SNMP is not yet implemented. See [Development](docs/DEVELOPMENT.md) for requirements and details.
