# SNMP P1 — model, migration and backup contracts

Implemented on 20 October 2026 on branch `snmp`, on top of `2dcc528` and the
completed P0 spike. This is development work for 0.9.0; the package version stays
0.8.0-0034 until the first installable implementation is prepared. Network SNMP
polling, trap reception and the SNMP editor remain P2/P3/P5 work.

## Implemented behavior

- Devices explicitly select `primary_protocol: redfish | snmp`. Legacy JSON
  defaults to Redfish with SNMP absent. Redfish keeps its existing flat fields;
  an SNMP primary has empty Redfish address/user/trust fields and needs no HTTPS
  origin, certificate or Redfish password. Optional `snmp_poll` also holds the
  separately saved agent configuration needed for later Redfish-primary trap
  enrollment; it does not enable a second hardware collector.
- Typed polling/trap security supports explicit v1/v2c or v3 SHA-1/SHA-256 with
  AES-128. V3 fields are rejected under community modes, including extra fields
  on empty tagged variants. User/context lengths are measured in UTF-8 bytes.
  Hosts, IPv4/IPv6, ports, bounded allowlists/engine IDs and request limits are
  validated. Profiles describe intended adapters, not tested hardware support.
- Poll/trap credentials live in `protocol_secrets`, separately encrypted using
  existing vault AES-GCM and AAD `device:<id>:snmp_poll` / `device:<id>:snmp_traps`.
  Redfish device-ID AAD and SMTP AAD are unchanged. Credentials use redacted Debug
  and zeroizing owned strings. Secret bytes are never trimmed or normalized.
  Explicit `keep`, `replace` and `clear` actions have different semantics; an
  enabled input requires credentials, and identity/target/security/context changes
  cannot silently keep old credentials. Sharing is explicit replacement for both
  purposes, never automatic fallback or an alias to the Redfish password.
- Device/config/credential changes commit together under the existing revision
  check and API submission gate. Credential rotation preserves faults/history.
  Primary protocol/host/port/profile replacement clears target-specific snapshot,
  alarms, log baseline and identities while retaining events/audit history.
  Trap-only changes keep the primary snapshot and faults. Every edit invalidates
  old work via device revision and a separate durable receiver epoch.
- Global receiver configuration defaults to disabled, UDP 1162 and IPv4 wildcard;
  ports 1024–65535 and explicit disjoint IPv4/IPv6 address sets are supported.
  P1 API writes can configure a disabled listener but cannot activate one. The
  dashboard explicitly reports unavailable network operation, never a live socket.
- Logical records for component identities, bounded normalized receipts and
  observation evidence have typed restore validation and device foreign keys.
  Event/receipt links use nullable foreign keys with `ON DELETE SET NULL`, so
  clearing history or pruning receipts leaves a restorable archive. No raw
  datagram, USM secret or remote engine-time cache is stored in those rows.
  P3/P4 will produce/use the records and add operational pruning and queue fairness.

## Database and runtime identity

`Store::open` rejects unknown schema versions before running migration DDL. A
schema-1 database receives a private SQLite snapshot under
`private/pre-snmp-schema1-<random>/monitor.db` before migration, plus its matching
`master.key` when present. Files are private and synced. This backup is local
runtime data, not an encrypted app download; retain the pair for rollback.

DDL, legacy config conversion and the schema-2 marker commit in one transaction.
Existing ciphertext, snapshots, event/delivery history, alarm acknowledgement
metadata and device revisions survive. Failure rolls back the migration. A second
open of schema 2 does not convert or back up again. Old schema-1 binaries reject
schema 2; rollback requires the matching old database/key and application.

`snmp-engine.json` is a separate private runtime file. The lifecycle helper
creates an opaque random engine identity once, atomically persists an incremented
boots counter before returning it on restart, and fails closed on malformed,
non-private or exhausted state. Updates use a process lock, synced private
replacement and directory sync. Missing state generates a new identity. The
identifier is opaque; it does not claim an assigned enterprise number. RFC 3411
allows an algorithmic initial identifier and recommends an enterprise-number
layout as an example ([SnmpEngineID definition](https://www.rfc-editor.org/rfc/rfc3411.html#section-5)).

The helper is not started by a network worker in P1. P3 must connect persisted
identity/boots to the selected library's authoritative engine and rollover
callback, share one running identity across rebinds, and compare receiver epochs
before applying queued work. Local file backups cannot provide a hardware
anti-rollback counter; restoring an old authoritative state remains unsupported.

## Logical archives

**Format 5** includes the five new logical tables. Format 4 is already occupied
by mail replay in the current base commit, correcting the earlier SNMP plan's
assumption. Formats **1, 2, 3 and 4** convert to 5 before table validation; the
existing authenticated encryption envelope remains unchanged.

Restore re-encrypts every credential with the destination vault and its original
purpose AAD. It validates configuration, secret type/version, bounds and evidence
references inside the transaction. Invalid input leaves destination data,
revisions, audit cursor and receiver epoch unchanged. Imported devices, per-device
traps, global listener and delivery channels are paused; acknowledgements require
review, receipts become historical and observation evidence becomes inactive.
Pending historical deliveries remain cancelled. Local engine identity/boots and
runtime epochs are absent from the archive; the destination epoch advances and
its local engine file is preserved.

## Development API and CLI

Existing `save` and `test` accept protocol-aware `DeviceInput`; new fields have
legacy defaults. `snmp_secrets` carries the two independent actions, for example:

```json
{
  "snmp_poll": {
    "action": "replace",
    "credentials": {"kind": "community", "community": "synthetic-example-only"}
  },
  "snmp_traps": {"action": "keep"}
}
```

V3 uses `{"kind":"usm","auth_password":"…","priv_password":"…"}`. Keep/clear
accept no credential payload. The corresponding input must be disabled when clearing. The admin dashboard exposes only `has_snmp_poll_secret`
and `has_snmp_traps_secret`; viewer responses also omit security configuration.
New `snmp_receiver_save` takes settings plus revision and uses native admin,
HTTPS/origin/CSRF checks. Enabling is rejected until P3.

`device-put --file <config> --protocol-secrets` reads a JSON credential document
from stdin with optional `redfish_password` and `snmp` (the action object above).
The legacy invocation still reads a Redfish password from stdin. Credentials are
never CLI arguments. Config files contain no secrets. Network `test`/`poll` on
an SNMP primary explicitly return `snmp_not_implemented` until P2, with no Redfish
attempt or protocol downgrade. The current device editor remains Redfish-only.

## Verification

- **121 Rust tests:** 112 unit tests plus nine P1 integration tests. P1 tests cover
  legacy/API/CLI inputs, byte/port/security limits, credential-purpose separation,
  rotation, trap-only edits, target changes, stale work, private backup/idempotent
  migration, failed migration, formats 1–4 conversion, cross-key format-5 restore,
  pause/invalidation, invalid-restore rollback and local engine restart behavior.
- Rust formatting and Clippy with warnings denied pass.
- **43 frontend tests**, frontend build and **19 Python tool tests** pass.
- Existing local Redfish/CGI, legacy TLS and SMTP integration suites pass. CGI
  checks now include legacy defaults and the SNMP configuration/secret-action path.
- The actual product builds for generic static x86-64 musl, with no ELF interpreter
  or runtime library dependencies. A static-binary CLI smoke test saves an SNMP
  device and verifies schema 2 and a credential-free snapshot. No SPK was assembled
  or installed; native DSM upgrade/rollback and real hardware remain P7 acceptance.

All test state and credentials are synthetic and temporary. Product dependency
versions and release metadata were not changed; the P0 SNMP library is still
isolated until production transport integration.

A redacted Gitleaks 8.30.1 scan of all 34 changed/new source, test and documentation files found zero secrets. Ignored runtime state, private migration backups, compiled assets and downloaded dependency sources were excluded. No commit or push was performed.
