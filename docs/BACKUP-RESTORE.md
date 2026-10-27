# Backup, restore and event exports

Build **0.8.0-0042** introduces compressed, file-backed backups and restores for large histories. Application backup/restore is user-confirmed for the reported deployment; see the acceptance record below.

SNMP adds database schema 2. Logical archive format 7 combines SNMP with the retention and streaming-backup changes from master. See [Architecture](ARCHITECTURE.md#receiver-identity-and-alarm-ordering).

## CSV and clearing

Administrators can export all retained raw event rows matching the current category/severity/device filters. The export includes rows older than the last 100 shown in the interface and individual summary events. Files use UTF-8 without BOM. Semicolons, quoted fields and a leading apostrophe for formula-like values support safe spreadsheet import. Headings follow the interface language; machine status codes remain stable. New generated messages are localized, while old messages and manufacturer text remain unchanged. Limits are 50,000 total retained event rows and 16 MiB of CSV; exports are rejected rather than truncated.

**Clear event log** requires explicit confirmation and affects all devices regardless of filters. It transactionally deletes events and their email/desktop jobs, including pending deliveries. Active alarm states, settings, hardware-log deduplication fingerprints and the audit log remain. The cleared row count is audited. Reminder timing restarts; a new state transition can still create an event immediately. Event numbers continue increasing. Messages already submitted externally cannot be recalled.

For automatic and immediate age-based cleanup, see [History retention](HISTORY-RETENTION.md). Event and hardware-log retention are independently configurable, both defaulting to 90 days. Audit retention is capped at 10,000 entries.

## Encrypted app download

On the **Backup** page, enter and repeat a password, then choose **Create encrypted backup**. When the job is ready, click **Download completed backup**. A background job creates a consistent SQLite snapshot on disk while ordinary polling can continue. It streams fixed-schema logical records through gzip and separately authenticated AES-256-GCM blocks into a private file. The browser downloads that file directly as `.hmbackup`; neither the browser nor the service holds the complete archive in memory. Progress and cancellation are available.

Starting with build **0043**, the download is an explicit click after the background job completes. The app first reads the current DSM session token and performs an authenticated `HEAD` check of the attachment, without reading its body. HTML login/error pages, JSON denials and expired jobs are shown as an error in the app instead of being offered as `api.html`.

A native browser download cannot add `X-SYNO-TOKEN`. For this navigation only, the app adds DSM's documented `SynoToken` query parameter; the CGI decodes it strictly and forwards it to the same fixed native authentication helper. Cookie, administrator role and job-session checks remain required. Normal API requests and the metadata check continue to use headers. No password or session ID is added to a URL. The token-bearing download URL exists only for the temporary navigation link, which has an explicit `.hmbackup` filename and no-referrer policy. See [Synology's DSM Login Web API Guide](https://global.synologydownload.com/download/Document/Software/DeveloperGuide/Os/DSM/All/enu/DSM_Login_Web_API_Guide_enu.pdf), Making API Requests / SynoToken.

Passwords must have at least 12 characters and at most 1024 UTF-8 bytes. They are not retained or recoverable. Store the file and password separately.

The archive includes devices and credentials, inline certificates, settings/templates/languages, retention policies, snapshots, alarms, hardware logs, events, delivery history and audit data. External CA files used by the CLI are embedded as verified PEM certificate contents. The local master key and SNMP authoritative engine state are not exported: device, purpose-separated SNMP and SMTP secrets travel inside the encrypted archive and are encrypted again with the destination's local key during inspection.

The binary envelope begins with `HWMON-STREAM-1`, uses a random 16-byte salt, a random 12-byte nonce and PBKDF2-HMAC-SHA256 with 600,000 iterations. Its header, block length and sequence number are authenticated. Every block uses a distinct nonce derived from the random per-file nonce and its 64-bit sequence number. Blocks contain at most 64 KiB of compressed content; an authenticated empty final block and physical EOF are mandatory. Reordered, repeated, missing or trailing blocks are rejected. The logical archive format is **7**, including retention policies and SNMP configuration, credentials, identities and evidence. Legacy formats 1–5 and streaming format 6 remain readable; missing structures receive safe defaults. Older apps cannot read the new format. Pending manual jobs are cancelled on restore and unconfirmed previews are discarded.

The former **128 MiB payload / 192 MiB file** limits do not apply to new backups. Multi-GiB logical histories are processed with bounded buffers and a small SQLite cache. One individual logical record is limited to 16 MiB. There is no configured total archive-size cap: encryption uses a fresh nonce for each block instead of accumulating the entire archive under one nonce. Available disk space and filesystem limits still apply. The old JSON/Base64 reader retains its 128/192 MiB limits for compatibility with files created by those releases. The new UI does not use the legacy whole-archive JSON endpoints.

This is a manual download/upload feature, not a Hyper Backup package adapter or periodic backup service. A downloaded file can be stored as an ordinary file in a backed-up share. DSM users, DSM passwords, NAS configuration and browser language preferences are not included.

The binary framing and activation rules are documented in [Streaming archive format](BACKUP-FORMAT.md).

## Jobs and disk space

Jobs are bound to the signed-in administrator's session. Refreshing or revisiting the page can resume observation of an active job or retrieve a completed download/inspection. A partially uploaded file must be selected and uploaded again after leaving the page. A new DSM session cannot access the previous session's jobs.

Up to eight jobs can be retained, with one heavy worker at a time. Successful completed and inactive jobs expire after an hour; cancelled/failed jobs are removed earlier. Private files are swept every minute. Use **Discard temporary backup jobs** to remove session-owned files immediately. A service restart invalidates jobs and removes their private temporary files. Cancelling a running worker removes incomplete output/staging after it stops. A completed database commit remains successful if a cancellation arrives afterward.

Temporary files live beside the application database, on the NAS data volume, with private directory/file permissions. Export needs space for a full SQLite snapshot plus the compressed archive. Inspection needs the uploaded archive plus an expanded staging database. Final restore additionally needs SQLite transaction/WAL space, potentially comparable to the data being replaced and imported. Keep substantial headroom; the service checks free space throughout and keeps a 32 MiB reserve. Filesystem quotas or concurrent disk use can still cause an I/O failure. Failed final restore transactions roll back without replacing live data. SQLite may retain reusable pages/WAL allocation afterward.

## Restore

Select a file, enter its password and choose **Check file and password**. The browser reads and uploads 512 KiB slices with checked offsets and idempotent retries. Inspection authenticates the entire file, checks fixed table/column layout, record bounds and foreign keys, then shows version, date and counts. It writes to a private staging database; the live database remains unchanged. Authentication includes every block tag and the mandatory final marker and rejects truncation or trailing data. Application-record validation additionally occurs inside the final restore transaction.

Confirm by typing `RESTORE` in English or `WIEDERHERSTELLEN` in German. Restore runs in the background, replaces devices/settings/alarms/events atomically and preserves/merges existing audit records subject to their 10,000-entry cap. Configuration changes since inspection require inspection again. Wrong passwords, damaged archives, invalid records, cancellation before commit and configuration conflicts do not partially replace the database. No imported SQL is executed and no filesystem paths are accepted from the archive.

The final transaction pauses ordinary writes and poll-result application; viewing uses a consistent read transaction and job progress/cancellation remain available. Imported alarm acknowledgements retain attribution and reason but require explicit review and re-acknowledgement before suppression becomes active. All devices are paused, automatic email/desktop delivery is disabled, the desktop recipient must be saved again, and old pending deliveries are cancelled. Stale poll results and editor revisions are rejected. Review current alarms, credentials and channel settings before deliberately re-enabling monitoring/delivery. Enabling a channel does not replay old events. Restored retention policies apply at the next manual cleanup or automatic run, first scheduled 24 hours after restore.

Per-device trap inputs and the global SNMP listener are also paused. The receiver ingestion gate covers both legacy and streaming restore; queued trap receipts and pending urgent polls are invalidated by the new runtime epoch. Failed restore retains the prior committed policy. See [receiver and restore boundaries](ARCHITECTURE.md#receiver-identity-and-alarm-ordering).

## Local upgrade backup

The separate CLI `backup --directory` command makes a private SQLite snapshot and copies its matching master key. It is not the encrypted app archive. The upgrade hook stops the daemon before creating this local snapshot. Protect those files together and retain external CA files separately. A compatible app installation is required for app restore; the archive is not an SPK installer.

Schema-1 databases receive an additional private `pre-snmp-schema1-<random>` SQLite/key backup before the transactional schema-2 migration. Starting with build 0055, the database and matching key are written and synced in a private temporary directory before that complete backup name is published. Normal backup failure removes only the new temporary files; interrupted `.pre-snmp-schema1-*.partial` directories are not complete rollback backups. Post-install initialization performs migration before normal service start; repeat repair keeps existing state and does not rerun a completed schema migration. Retain it for recovery and diagnosis; schema-1 binaries cannot open schema 2. It is not a supported DSM Package Center downgrade procedure. The per-device trap sequence clock is runtime state excluded from logical archives; imported evidence is inactive/non-provisional and never replayed. Local SNMP engine files remain private runtime state, outside logical app backups. An app restore preserves the destination engine identity/counter, and cannot roll it back.

## Native acceptance — 27 October 2026

The user confirmed successful application backup/restore and native DSM upgrade
**0.8.0-0043 → 0.9.0-0062**. This confirms the reported workflow, without
asserting a cross-NAS or all-archive-version matrix. DSM Package Center downgrade
from 0.9.0 to 0.8.0 is outside the supported acceptance path, separate from the
transactional recovery and cancellation guarantees described above.
