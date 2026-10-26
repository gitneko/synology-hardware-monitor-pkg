# Backup, restore and event exports

The user has confirmed the build-0016 app backup/restore workflow on the NAS. Build 0017 adds language preferences and structured event context, and can read the previous format. The new migration still needs target acceptance.

## CSV and clearing

Administrators can export all retained raw event rows matching the current category/severity/device filters. The export includes rows older than the last 100 shown in the interface and individual summary events. Files use UTF-8 without BOM. Semicolons, quoted fields and a leading apostrophe for formula-like values support safe spreadsheet import. Headings follow the interface language; machine status codes remain stable. New generated messages are localized, while old messages and manufacturer text remain unchanged. Timestamps include UTC and the configured email time zone/format. Limits are 50,000 total retained event rows and 16 MiB of CSV; exports are rejected rather than truncated.

**Clear event log** requires explicit confirmation and affects all devices regardless of filters. It transactionally deletes events and their email/desktop jobs, including pending deliveries. Active alarm states, settings, hardware-log deduplication fingerprints and the audit log remain. The cleared row count is audited. Reminder timing restarts; a new state transition can still create an event immediately. Event numbers continue increasing. Messages already submitted externally cannot be recalled.

## Encrypted app download

The Backup page downloads a `.hmbackup` file after matching password entries. Passwords must have at least 12 characters and at most 1024 UTF-8 bytes. They are not retained or recoverable. Store the file and password separately.

The archive includes devices and credentials, inline certificates, settings/templates/languages, snapshots, alarms, hardware-log fingerprints, events, delivery history and audit data. External CA files used by the CLI are embedded as verified PEM certificate contents. The local master key is not exported: device and SMTP secrets travel inside the encrypted archive and are encrypted again with the destination's local key during restore.

The authenticated envelope uses AES-256-GCM, a random 16-byte salt, a random 12-byte nonce and PBKDF2-HMAC-SHA256 with 600,000 iterations. The logical archive format is **4**, including alarm acknowledgement records and manual email submission history. Formats 1, 2 and 3 remain readable: absent event context, acknowledgements and manual history are migrated. Older apps cannot be assumed to read new archives. The same envelope header is retained; its authenticated payload carries the logical format version. Restore preserves terminal manual submission history, cancels pending manual jobs and discards unconfirmed previews.

Starting with build 0040, bounds are 128 MiB of logical backup content and 192 MiB of file data (previously 16/24 MiB). Starting with build 0041, export counts the exact serialized JSON size while collecting rows, including escaping and converted credentials/certificates. The previous estimate charged at least 40 bytes per cell and could reject content below the payload limit. Size errors now include the byte count and fixed schema table at rejection; that table identifies where collection stopped, not necessarily the largest table. Counts reported at rejection are a lower bound, not a complete inventory. No record contents or credentials are exposed. The CGI response and upload paths support the larger files; ordinary forms remain limited to 128 KiB. The encrypted archive format is unchanged and existing backups remain readable. The complete archive is still processed in memory, so these are finite resource bounds rather than a streaming implementation. This is a manual download/upload feature, not a Hyper Backup package adapter or periodic backup service. A downloaded file can be stored as an ordinary file in a backed-up share. DSM users, DSM passwords, NAS configuration and browser language preferences are not included.

## Restore

Select a file, enter its password and choose **Check file and password**. Inspection authenticates/decrypts the file, checks the fixed table/column layout and shows version, date and counts. Application-record validation additionally occurs inside the final restore transaction. Confirm by typing `RESTORE` in English or `WIEDERHERSTELLEN` in German.

Restore replaces devices, settings, alarms and events. Existing audit records are retained and merged with archive audit records, subject to the 10,000-entry audit retention limit. Wrong passwords, damaged archives, invalid records or a configuration-change conflict do not partially replace the database. No imported SQL is executed and no file paths are imported.

After restore, imported alarm acknowledgements retain their attribution and reason but require explicit review and re-acknowledgement before suppression becomes active. All devices are paused, automatic email/desktop delivery is disabled, the desktop recipient must be saved again, and old pending deliveries are cancelled. Stale poll results and editor revisions are rejected. Review current alarms, credentials and channel settings before deliberately re-enabling monitoring/delivery. Enabling a channel does not replay old events.

## Local upgrade backup

The separate CLI `backup --directory` command makes a private SQLite snapshot and copies its matching master key. It is not the encrypted app archive. The upgrade hook stops the daemon before creating this local snapshot. Protect those files together and retain external CA files separately. A compatible app installation is required for app restore; the archive is not an SPK installer.
