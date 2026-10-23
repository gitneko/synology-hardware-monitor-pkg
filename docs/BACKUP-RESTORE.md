# Backup, restore and event exports

The user has confirmed the build-0016 app backup/restore workflow on the NAS. Build 0017 adds language preferences and structured event context, and can read the previous format. The new migration still needs target acceptance.

The SNMP development branch adds database schema 2 and logical archive format 5; this is not yet an installable SNMP release. See [P1 contracts and validation](SNMP-P1-RESULTS.md).

## CSV and clearing

Administrators can export all retained raw event rows matching the current category/severity/device filters. The export includes rows older than the last 100 shown in the interface and individual summary events. Files use UTF-8 without BOM. Semicolons, quoted fields and a leading apostrophe for formula-like values support safe spreadsheet import. Headings follow the interface language; machine status codes remain stable. New generated messages are localized, while old messages and manufacturer text remain unchanged. Timestamps include UTC and the configured email time zone/format. Limits are 50,000 total retained event rows and 16 MiB of CSV; exports are rejected rather than truncated.

**Clear event log** requires explicit confirmation and affects all devices regardless of filters. It transactionally deletes events and their email/desktop jobs, including pending deliveries. Active alarm states, settings, hardware-log deduplication fingerprints and the audit log remain. The cleared row count is audited. Reminder timing restarts; a new state transition can still create an event immediately. Event numbers continue increasing. Messages already submitted externally cannot be recalled.

## Encrypted app download

The Backup page downloads a `.hmbackup` file after matching password entries. Passwords must have at least 12 characters and at most 1024 UTF-8 bytes. They are not retained or recoverable. Store the file and password separately.

The archive includes devices and credentials, inline certificates, settings/templates/languages, snapshots, alarms, hardware-log fingerprints, events, delivery history and audit data. External CA files used by the CLI are embedded as verified PEM certificate contents. The local master key and SNMP authoritative engine state are not exported: device, SMTP and purpose-separated SNMP secrets travel inside the encrypted archive and are encrypted again with the destination's local key during restore.

The authenticated envelope uses AES-256-GCM, a random 16-byte salt, a random 12-byte nonce and PBKDF2-HMAC-SHA256 with 600,000 iterations. The logical archive format on this development branch is **5**, including alarm acknowledgements, manual email history, SNMP configuration/credentials, identities and retained evidence. Formats 1, 2, 3 and 4 remain readable; missing structures receive safe defaults. Format 4 remains the format of base build 0034. Older apps cannot be assumed to read new archives. The same envelope header is retained; its authenticated payload carries the logical format version. Restore preserves terminal manual submission history, cancels pending manual jobs and discards unconfirmed previews.

Current bounds are 16 MiB of logical backup content and 24 MiB of file data. This is a manual download/upload feature, not a Hyper Backup package adapter or periodic backup service. A downloaded file can be stored as an ordinary file in a backed-up share. DSM users, DSM passwords, NAS configuration and browser language preferences are not included.

## Restore

Select a file, enter its password and choose **Check file and password**. Inspection authenticates/decrypts the file, checks the fixed table/column layout and shows version, date and counts. Application-record validation additionally occurs inside the final restore transaction. Confirm by typing `RESTORE` in English or `WIEDERHERSTELLEN` in German.

Restore replaces devices, settings, alarms and events. Existing audit records are retained and merged with archive audit records, subject to the 10,000-entry audit retention limit. Wrong passwords, damaged archives, invalid records or a configuration-change conflict do not partially replace the database. No imported SQL is executed and no file paths are imported.

After restore, imported alarm acknowledgements retain their attribution and reason but require explicit review and re-acknowledgement before suppression becomes active. All devices, per-device trap inputs and the global SNMP listener are paused, automatic email/desktop delivery is disabled, the desktop recipient must be saved again, and old pending deliveries are cancelled. Stale poll results, queued trap receipts and editor revisions are rejected. P3 holds the receiver ingestion gate during the final restore transaction; successful restore discards old policies, remote-time baselines, duplicates and pending urgent polls. Failed restore retains the prior committed policy. See [P3 receiver evidence](SNMP-P3-RESULTS.md). Review current alarms, credentials and channel settings before deliberately re-enabling monitoring/delivery. Enabling a channel does not replay old events.

## Local upgrade backup

The separate CLI `backup --directory` command makes a private SQLite snapshot and copies its matching master key. It is not the encrypted app archive. The upgrade hook stops the daemon before creating this local snapshot. Protect those files together and retain external CA files separately. A compatible app installation is required for app restore; the archive is not an SPK installer.

Schema-1 databases receive an additional private `pre-snmp-schema1-<random>` SQLite/key backup before the transactional schema-2 migration. Starting with build 0055, the database and matching key are written and synced in a private temporary directory before that complete backup name is published. Normal backup failure removes only the new temporary files; interrupted `.pre-snmp-schema1-*.partial` directories are not complete rollback backups. Post-install initialization performs migration before normal service start; repeat repair keeps existing state and does not rerun a completed schema migration. Retain it for old-version rollback; schema-1 binaries cannot open schema 2. The P4 per-device trap sequence clock is runtime state excluded from logical archives; imported evidence is inactive/non-provisional and never replayed. Local SNMP engine files remain private runtime state, outside logical app backups. An app restore preserves the destination engine identity/counter, and cannot roll it back.
