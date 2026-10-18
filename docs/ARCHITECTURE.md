# Package architecture

Current implementation: 0.8.0-0017.

## Processes and trust boundaries

One statically linked Rust/Tokio executable provides the daemon, compiled CGI bridge, local maintenance commands and service lifecycle. DSM lifecycle hooks are the small scripts required by the package format. Polling runs in the daemon, without Task Scheduler or loose monitoring scripts. Up to four devices are polled concurrently using read-only Redfish HTTPS GET requests. There is no public daemon TCP API and no SMTP server.

The Vue 3 application is served through DSM's package web alias. On DSM 7, a Vue 2 host launcher opens a DSM desktop window containing a same-origin iframe. DSM 6 has a separate legacy launcher profile and remains unverified on the target hardware. Versioned HTML/launcher filenames, hashed assets and positive release timestamps prevent the previously observed stale entrypoint problem.

The CGI bridge forwards requests to a Unix socket. The service authenticates the DSM session through the fixed native `authenticate.cgi` helper, resolves actual groups and assigns administrator or viewer access. Administrators can administer the app; members of `hardware-monitor-viewers` receive read-only data. Every administrative operation also requires HTTPS, a matching Origin, the DSM token and a short-lived package CSRF proof bound to the verified user/session. The complete DSM Application Privileges contract and viewer menu integration are still pending. A desktop icon is not an authorization check.

The optional `X-HardwareMonitor-Language: de|en` header controls presentation only; it cannot grant permissions. Background channel languages are saved separately. See [Languages](LANGUAGES.md).

## Persistent state

SQLite stores devices, AES-256-GCM-encrypted device/SMTP credentials, the latest snapshot, alarm states, hardware-log fingerprints, events, delivery jobs and audit records. The locally generated master key is private to the package identity. The private state directory is `/var/packages/HardwareMonitor/etc/private`; the API socket is outside that private directory. No DSM passwords are stored.

Explicit warning/critical states are retained when a component later becomes unavailable. Unknown values never confirm recovery. Unavailable readings are not treated as current measurements. Explicit resource relationships support grouping of summary notifications while preserving every local state and event. Distinct component faults keep independent transitions and reminders; grouping is a notification policy, not proof of complete physical causality.

SMTP and native DSM desktop delivery have independent durable jobs. A shared gate serializes configuration changes, event clearing and restore against new submissions. Per-recipient SMTP progress survives restarts. SMTP acceptance and DSM command success are submission acknowledgements, not proof of inbox/display delivery. A crash after an external submission but before its local acknowledgement can still produce a duplicate.

Events normally retain up to 90 days of history, while pending jobs are preserved. Active alarm states and hardware-log fingerprints are not yet fully bounded. Audit retention is capped at 10,000 entries. These limits do not constitute complete production hardening.

## Export and restore

CSV uses UTF-8 with BOM, semicolons, quoted fields, spreadsheet-formula neutralization and UTC plus configured local timestamps. Event clearing removes events and their delivery jobs transactionally, preserves active alarms/fingerprints/audit and restarts reminder timing. An event counter avoids reusing cleared event numbers.

App backups use a fixed logical schema, authenticated encryption and password derivation. Import never executes SQL or accepts filesystem paths from the archive. Restore validates inside a transaction, re-encrypts secrets with the local key, preserves/merges audit history, invalidates stale editor/poll revisions, pauses devices/channels and cancels pending historical jobs. See [Backup and restore](BACKUP-RESTORE.md).

## DSM integration evidence

The normal packages request no optional resource workers: `conf/resource` is empty and the service runs as the package identity. The `sysnotify` registration resource was rejected on the tested NAS, including a probe mapped to a registered application. The product uses its own SMTP client and the separately tested `synodsmnotify` desktop command.

Primary references: [DSM application config](https://help.synology.com/developer-guide/integrate_dsm/config.html), [I18N/preloading](https://help.synology.com/developer-guide/integrate_dsm/i18n.html), [desktop notification command](https://help.synology.com/developer-guide/synology_package/show_massage.html), [resource registration](https://help.synology.com/developer-guide/resource_acquisition/sysnotify.html). Documented contracts and actual NAS results are distinguished in [Validation](VALIDATION.md).
