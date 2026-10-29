# Hardware Monitor for Synology

*This Synology package and code was developed by GPT-6.1 Sol and tested by humans.*

Open-source, cross-vendor server hardware monitoring using Redfish or SNMP on a Synology NAS.

Due to thirdparty package limitations imposed by Synology, this package does not integrate natively into Synology notifications
and instead sends e-mails directly using SMTP, configured by you. DSM desktop notifications are available.
You can choose if you want either, none or both.

**Current version: 0.10.3-0077**. The Package Center title is **Hardware Monitor**.

## Features

- A lightweight Rust/Tokio background service, SQLite persistence and a Vue application inside the DSM 7 desktop. No Task Scheduler or loose polling scripts.
- Read-only Redfish polling with capability discovery, standard/selected OEM storage links, power supplies, fans, temperatures, hardware logs and reachability.
- Explicit SNMPv1/v2c/v3 primary polling with bounded manufacturer profiles, independent encrypted credentials and coverage diagnostics.
- Optional SNMP traps on UDP port (default 1162; [administrative setup for privileged ports](docs/TRAP-PRIVILEGED-PORTS.md)), reviewed v3 sender identities and provisional alarms confirmed by primary polling. [0.9.0 release notes](docs/RELEASE-NOTES-0.9.0.md).
- Persistent faults, confirmed recoveries, optional reminders, deduplication and grouping of linked summary alarms without merging independent component faults.
- Acknowledge known hardware faults with a reason: blue status, persistent suppression for email, desktop and webhooks, automatic summary assessment and reactivation on recovery or worsening. [Acknowledgement rules](docs/ALARM-ACKNOWLEDGEMENT.md).
- Independently configured SMTP email, native DSM desktop notifications and [outgoing HTTP/HTTPS webhooks](docs/WEBHOOKS.md), with event filters and per-device delivery enablement. Webhooks support generic/custom JSON, text, form fields, Discord and Slack, with per-target language, templates, previews and tests.
- Manually resend a recorded event to one saved email recipient, with a current-template preview and separate delivery history, without changing the alarm or original event. [Manual email replay](docs/MAIL-REPLAY.md).
- Separate configurable event/hardware-log retention (90-day defaults), daily and immediate cleanup with preview, and per-device hardware-log reading controls. [Retention rules](docs/HISTORY-RETENTION.md).
- Filtered full-history CSV, audited event clearing and compressed, streaming, password-encrypted multi-GiB backup/restore, including device, SMTP, SNMP and webhook credentials. Background jobs support progress/cancellation; restore pauses monitoring/delivery and cancels old pending jobs.
- Optional data deletion in the DSM uninstall wizard. Data is retained by default; opt in to remove settings, credentials, history, keys and local upgrade backups. [Uninstall behavior](docs/UNINSTALL.md).
- **German and English:** Automatic/Deutsch/English interface selection, separate saved languages for background channels, localized new event text/API messages/CSV headings and English documentation. Custom templates, vendor text and legacy event text are preserved.

See the [SNMP setup and operation guide](docs/SNMP.md) for credentials, profiles, sender verification and troubleshooting.

## Compatibility and evidence

The supported package target is **DSM 7.0+ x86_64** (minimum `7.0-40761`),
including v1000 and geminilake families. Recorded Redfish tests cover Dell
R420/iDRAC7, R330/iDRAC8, R340/iDRAC9 and HPE DL160 Gen10/iLO 5; additional
scoped iLO 6 evidence is recorded separately.

User-confirmed SNMP operation includes Dell iDRAC traps, HPE iLO, Synology DSM,
Generic and Network Generic profiles. Alarm notifications, fault/recovery,
acknowledgement, duplicate handling, trap reception after package/DSM restart,
upgrade **0.8.0-0043 → 0.9.0-0062** and backup/restore are confirmed for the
reported deployment. These results do not certify every model, firmware or
security variant. **APC/Eaton/RFC 1628 UPS profiles are released untested on real
UPS hardware**, with local synthetic/reference coverage only.

See the [protocol-specific hardware matrix](docs/HARDWARE-COMPATIBILITY.md),
[validation and evidence limits](docs/VALIDATION.md) and [roadmap](docs/ROADMAP.md).

## Getting started

1. Download the checked SPK from the release tagged `latest`: `HardwareMonitor-dsm7-x86_64.spk` for DSM 7 (including v1000 and geminilake). Verify it against `SHA256SUMS`, install through Package Center and open Hardware Monitor from DSM. Release assets are updated by the default-branch workflow after its checks succeed.
2. Choose Redfish or SNMP as the primary protocol. For SNMP, follow the [setup guide](docs/SNMP.md). For Redfish, add an HTTPS management-controller origin and an account with the required hardware-read permissions. Use a trusted certificate chain/private CA with a matching hostname in Standard mode. For older Dell controllers or the tested iLO factory certificate, explicitly select iDRAC7/8 and iLO compatibility and import the exact server certificate from a trusted source; its fingerprint and validity dates are checked before HTTP credentials are sent.
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
- [History retention and cleanup](docs/HISTORY-RETENTION.md)
- [CSV, clearing and backup/restore](docs/BACKUP-RESTORE.md)
- [Development, local checks, SPK builds and GitHub releases](docs/DEVELOPMENT.md)
- [DSM package architecture families](docs/PACKAGE-ARCHITECTURES.md)
- [DSM privilege findings](docs/DSM-PRIVILEGES.md)
- [Validation](docs/VALIDATION.md), [roadmap](docs/ROADMAP.md)
- [SNMP setup, profiles, traps and troubleshooting](docs/SNMP.md)
- [Outgoing webhooks](docs/WEBHOOKS.md)
- [0.10.0 release notes](docs/RELEASE-NOTES-0.10.0.md)
- [0.9.0 release notes](docs/RELEASE-NOTES-0.9.0.md)

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

Run `python3 tools/dev.py` from the project root, then open <http://127.0.0.1:18774/>. The complete frontend and backend run without an application login or SPK build, with persistent local state and real Redfish/SNMP connections. Device credentials and applicable certificate checks remain required. This optional mode is excluded from normal DSM builds. See [Development](docs/DEVELOPMENT.md) for requirements and details.
