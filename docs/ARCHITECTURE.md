# Package architecture

Current version: **0.10.0**. Runtime design is described here; user setup
is in [SNMP](SNMP.md), and tested combinations/results are in
[Compatibility](HARDWARE-COMPATIBILITY.md) and [Validation](VALIDATION.md).

## Processes and trust boundaries

One statically linked Rust/Tokio executable provides the daemon, compiled CGI bridge, local maintenance commands and service lifecycle. DSM lifecycle hooks are the small scripts required by the package format. Polling runs in the daemon, without Task Scheduler or loose monitoring scripts. Up to four devices are polled concurrently using read-only Redfish HTTPS GET requests or bounded SNMP reads, with one selected primary collector per device. Optional supervised UDP trap reception is separate. There is no public daemon TCP API and no SMTP server.

The Vue 3 application is served through DSM's package web alias. A Vue 2 host launcher opens a DSM 7 desktop window containing a same-origin iframe. Versioned HTML/launcher filenames, hashed assets and positive release timestamps prevent the previously observed stale entrypoint problem.

The CGI bridge forwards requests to a Unix socket. The service authenticates the DSM session through the fixed native `authenticate.cgi` helper, resolves actual groups and assigns administrator or viewer access. Administrators can administer the app; members of `hardware-monitor-viewers` receive read-only data. Every administrative operation also requires HTTPS, a matching Origin, the DSM token and a short-lived package CSRF proof bound to the verified user/session. The complete DSM Application Privileges contract and viewer menu integration are still pending. A desktop icon is not an authorization check.

The optional `X-HardwareMonitor-Language: de|en` header controls presentation only; it cannot grant permissions. Background channel languages are saved separately. See [Languages](LANGUAGES.md).

## Controller TLS identities

Standard devices use Rustls with certificate-chain and hostname verification. The explicitly selected iDRAC7 mode uses statically vendored OpenSSL with TLS 1.2 or newer and ECDHE/DHE AES-GCM suites at security level 2. It requires one imported leaf certificate, authenticating its full DER SHA-256 and validity dates before the TLS stream is given to Hyper or any Authorization header is created. This deliberately replaces CA/hostname validation only for the selected device; CA:TRUE and missing SANs in older Dell certificates do not expand trust. No automatic fallback or first-use enrollment occurs. Build 0021 retains one HTTP/1.1 connection for sequential reads within each client, rechecks certificate validity for each request, and verifies identity again on reconnect. An idle disconnect permits one safe GET retry. Every redirected URL retains the same-origin Redfish-path restriction. HTTP bodies, headers, deadlines and connection drivers are bounded; cancellation of an active request drops its connection driver, and client destruction drops an idle driver. Public dashboard output exposes the fingerprint, never the imported PEM or credentials.

## Persistent state

SQLite stores devices, AES-256-GCM-encrypted device/SMTP credentials, the latest snapshot, alarm states, hardware-log fingerprints, events, delivery jobs and audit records. The locally generated master key is private to the package identity. The private state directory is `/var/packages/HardwareMonitor/etc/private`; the API socket is outside that private directory. No DSM passwords are stored.

Explicit warning/critical states are retained when a component later becomes unavailable. Unknown values never confirm recovery. Unavailable readings are not treated as current measurements. Explicit resource relationships support grouping of summary notifications while preserving every local state and event. Distinct component faults keep independent transitions and reminders; grouping is a notification policy, not proof of complete physical causality.

Build 0028 stores local operator acknowledgement separately from hardware health, using a version token per alarm to reject stale actions. The backend derives display/operative summary states from every known faulty descendant, including lower-severity faults omitted by notification grouping. Acknowledgement actions use the shared submission gate, cancel pending jobs transactionally and preserve already submitted history. New/worsening faults and recoveries update the acknowledgement lifecycle during the poll transaction. App archive format 3 includes these records but restores them as requiring review. See [Acknowledgements](ALARM-ACKNOWLEDGEMENT.md).

SMTP and native DSM desktop delivery have independent durable jobs. A shared gate serializes configuration changes, event clearing and restore against new submissions. Per-recipient SMTP progress survives restarts. SMTP acceptance and DSM command success are submission acknowledgements, not proof of inbox/display delivery. A crash after an external submission but before its local acknowledgement can still produce a duplicate.

Build 0022 prioritizes hardware-resource discovery before paths within LogServices. Build 0023 also recognizes older Dell Logs paths. Scan limits are 256 resources, 16 MiB and 4096 items, with a 90-second deadline in Standard and 300 seconds in the explicitly selected iDRAC7/8 profile. Its serialized profile name remains `idrac7`. Poll progress lives outside the timed future: bounded aborts preserve previously validated resource observations and mark the snapshot incomplete with an explicit reason and resource path. A malformed child response is isolated. Failed root access, authentication rejection and certificate identity/validity errors stay fatal. Fatal errors are saved through the existing revision gate using classified diagnostics, never raw internal errors, HTTP bodies or query strings. Incomplete scans do not initialize the hardware-log baseline. The UI labels the timestamp as the last saved poll, which may be partial.

When the root advertises Links/Sessions, the collector creates one temporary authentication session, uses X-Auth-Token for subsequent reads and logs out that owned session after normal completion, error or deadline. Root access still uses Basic authentication once. Controllers without the advertised route, or returning 403/404/405/501 to session creation, retain Basic authentication. Only the two supported same-origin Session collections accept POST, and only a safe child ID returned by that login can be used for DELETE. Session operations never follow redirects or retry a POST. Hardware resources remain GET-only. Tokens are memory-only and sensitive headers, never device configuration, snapshots or backups. Logout is bounded to three seconds; failed logout or process termination relies on controller session expiry. Each device still has one poll at a time and waits the configured pause after completion. iDRAC7/8 freshness allows its full scan budget plus two configured pauses; Standard freshness is unchanged.

Event history and imported hardware logs have independent configurable retention periods, each defaulting to 90 days (0 means unlimited). Daily/manual batched cleanup preserves active alarm states and pending deliveries. Hardware timestamps must be valid RFC 3339; unknown/invalid/future dates are preserved. The same hardware cutoff filters incoming logs to prevent reimport. Reading all/latest N/disabled is configured per device. Audit retention is capped at the newest 10,000 entries; the UI shows 50. See [Retention](HISTORY-RETENTION.md).

## Export and restore

CSV uses UTF-8 without BOM, semicolons, quoted fields, spreadsheet-formula neutralization and UTC plus configured local timestamps. Event clearing removes events and their delivery jobs transactionally, preserves active alarms/fingerprints/audit and restarts reminder timing. An event counter avoids reusing cleared event numbers.

App backups use a fixed logical schema, authenticated encryption and password derivation. Import never executes SQL or accepts filesystem paths from the archive. Restore validates inside a transaction, re-encrypts secrets with the local key, preserves/merges audit history, invalidates stale editor/poll revisions, pauses devices/channels and cancels pending historical jobs. See [Backup and restore](BACKUP-RESTORE.md).

## DSM integration evidence

The normal packages request no optional resource workers: `conf/resource` is empty and the service runs as the package identity. The `sysnotify` registration resource was rejected on the tested NAS, including a probe mapped to a registered application. The product uses its own SMTP client and the separately tested `synodsmnotify` desktop command.

Primary references: [DSM application config](https://help.synology.com/developer-guide/integrate_dsm/config.html), [I18N/preloading](https://help.synology.com/developer-guide/integrate_dsm/i18n.html), [desktop notification command](https://help.synology.com/developer-guide/synology_package/show_massage.html), [resource registration](https://help.synology.com/developer-guide/resource_acquisition/sysnotify.html). Documented contracts and actual NAS results are distinguished in [Validation](VALIDATION.md).

Build 0024 records applicability separately from health in the snapshot's default-empty `assessment_exclusions` map. Unknown observations are neutral only for explicitly Disabled functions, positively empty SimpleStorage device inventories, Storage inventories with empty Drives and a successfully read empty Volumes collection, and status-free PowerControl consumption measurements. An empty Storage inventory can explain its explicitly linked StorageControllers; names and guessed paths never establish that relationship. Missing, inconsistent, paginated or populated inventories and unavailable/offline controllers are not proof of emptiness. Hardware warnings/critical states, missing coverage, stale data and retained faults keep their existing significance. Neutral observations stay Unknown in the alarm state machine, so they do not create fictitious recoveries. The UI shows Not applicable with a reason, excludes those rows from the overall health calculation and requires at least one remaining assessable hardware observation before showing OK. Old snapshots without the map keep their previous behavior.

Build 0030 also follows the standard Storage `Controllers` collection and its observed `Members` to associate standalone StorageController resources with that empty inventory. This fixes the fourth, previously unexplained S140 representation reported on iDRAC9. Legacy embedded StorageControllers without an `@odata.id` use the same fallback key as normalization. A controller remains assessable if any known owning Storage inventory is populated or unproven, if it advertises attached drives/volumes through Links, or if it is unavailable or reports a fault. Equal display names do not merge resources or alarm identities. See the [DMTF Storage definition](https://redfish.dmtf.org/schemas/v1/Storage.v1_14_0.json) for the collection relationship.

Build 0034 adds a separate `absent` applicability reason for explicitly absent components, unless another observation contradicts absence or reports a fault/condition. Raw health remains Unknown, unavailable readings stay suppressed and retained incidents/acknowledgements are not cleared. Untyped members of a typed Power resource's `PowerControl` array can be informational when they contain a finite consumption value and no Status. Arbitrary watt-reading sensors do not inherit this rule. An omitted Volumes property can additionally be neutral for a healthy Enabled Storage resource with a complete empty Drives array and exclusively SATA-capable linked controllers. Every advertised controller representation must be observed and free of contradictory inventory/status; advertised collections must be complete. Null/advertised-but-unread Volumes, missing controller data, other protocols, pagination, malformed counts and fault conditions keep the conservative behavior. Neutral badges explain absence, information or empty controllers without changing vendor component names.

Build 0037 adds an incident-token/device-revision-bound administrator reset. One immediate transaction removes the chosen alarm/acknowledgement, cancels pending automatic jobs for that canonical resource and records an audit entry. Events, measurements, accepted SMTP records and explicit historical replays remain. Automatic delivery gates prevent the next matching email, desktop or webhook job from starting after the reset. The next confirmed faulty poll creates a new incident. See [Alarm reset](ALARM-RESET.md).


Build 0042 uses session-bound background jobs for backup export, upload inspection, restore and cleanup. A file-backed SQLite online snapshot feeds gzip and sequenced, individually authenticated AES-GCM blocks; upload uses checked 512 KiB slices and download uses 64 KiB raw frames through the native CGI/Unix-socket bridge. Inspection fully authenticates before activating a staging database. Final restore uses a single checked transaction on a separate connection, so job status/cancellation do not wait for the shared application mutex. Jobs have opaque random IDs, admin/session checks, private files, a one-worker gate, one-hour expiry and restart cleanup. The old bounded JSON archive API remains only for compatibility. See [Backup and restore](BACKUP-RESTORE.md).
## SNMP transport and credential boundaries

The daemon, CLI and API use the same primary-protocol dispatcher. SNMP reads
use one per-poll UDP socket with exact peer/request/version/community/context
correlation; the pinned library owns BER, USM, HMAC, privacy and time processing.
Polling secrets use vault AAD `device:<id>:snmp_poll`; trap secrets use
`device:<id>:snmp_traps`. Redfish and SMTP scopes remain unchanged. Explicit
keep/replace/clear actions commit with configuration under revision checks;
secret values never appear in dashboards. Changing the primary target/profile
resets target-specific state while retaining event/audit history. Credential
rotation preserves faults. Trap-only changes preserve the primary snapshot.

| Limit | Contract |
|---|---|
| DNS | Three seconds, at most 16 addresses; prefer the prior address while valid; no guessed fallback target after failure |
| Poll / connection probe | 60 / 15 seconds; default request timeout two seconds, at most one timeout retry |
| Per-poll budgets | 512 transmitted requests for v1, 128 for v2c/v3; 4096 decoded varbinds, 4 MiB received bytes, 16 KiB per message; discovery/errors/retries count |
| Walks | At most eight independent column cursors; full index-tuple joins; decreasing OIDs abort; bounded bulk reduction and GETNEXT fallback |
| Runtime polling contexts | At most 256 devices, two cached engines per device; bounded descriptive inventory cache, refresh after 15 minutes |
| Receiver policy | At most 256 enabled devices, 16 source addresses per device and 16 explicit local listen addresses |
| Pre-authentication admission | 200 eligible datagrams/s globally (burst 400), 20/source (burst 40); queues 256 globally, 16/source, round-robin |
| Authenticated ingestion | 50/s globally (burst 100), 10/device (burst 20); 256-item channel to one database consumer |
| Input / duplicates | 16 KiB datagram, 128 total wire bindings including mandatory prefixes; 4096-entry / 30-second semantic duplicate cache |
| Receipts | Seven days, at most 10,000 normalized rows / 4 KiB each; insertion and independent minute pruning |
| Urgent polls | Coalesced, at least ten seconds between starts per device, same four-job pool; regular due polls take priority |

V1 uses GET/GETNEXT, never GETBULK, and rejects Counter64/v2 exception values.
Valid `noSuchName`/error-index isolates only the failed cursor; error payloads
are not observations. Walks never cover an arbitrary enterprise root. A current
typed system identity/uptime exchange is mandatory. Later failure preserves
validated partial data; missing coverage cannot establish recovery. Serial/FQDD
identity and health are always reread, not trusted from descriptive caches.
Uptime wrap is distinct from agent restart and neither proves a host power cycle.
Failure backoff has positive jitter; obsolete results check revision and restore
epoch in the write transaction.

## Receiver, identity and alarm ordering

Unknown sources are rejected before per-source queues and approved-source quota.
Untrusted source/engine/user headers select one bounded credential context;
multiple matches fail. Each approved device has one key set and a bounded remote
engine cache; no password trial occurs. The current library also owns an unused
internal loopback socket per context, in addition to the service sockets. Spoofed
approved-source traffic can still consume verification capacity. Bounds and
measured reference load are not complete UDP DoS protection.

V3 requires authPriv, approved sender identity and fresh authenticated saved-target
bootstrap. Discovery, incoming signatures and unauthenticated Reports cannot
create trust. Bootstrap uses trap credentials, even for a Redfish primary;
an actual successful system read is required. At most two probes run together,
with bounded failure backoff. A ready sender needs no keepalive solely for silence.
Non-authoritative USM time handling permits authenticated advances and rejects
stale input; it is not the responder's symmetric clock test. Empty optional trap
context filters impose no additional context constraint. Changed engine IDs
require new operator review.

The private `snmp-engine.json` is locked, atomically replaced and synced; boots
increments durably once per daemon start. Rebinds share its running identity.
Malformed/nonprivate/exhausted state fails v3 closed. App archives omit local
engine state, remote clocks and urgent queues. The library patch exposes routed
processing and monotonic seeding, a decoded-varbind budget hook and a boolean
polling-hint API; cryptographic/time algorithms remain upstream. Clock-compatible
hints use a disposable remote clock, cannot enter receipt/alarm ingestion and
cannot lower the strict replay baseline. See [operator behavior](SNMP.md#controller-clock-compatibility).

`src/alarm.rs` provides the shared transactional reducer for full polls and
trusted partial trap observations. Receipt/evidence/transition/delivery jobs
commit together under submission/ingestion gates. A durable per-device
`snmp_alarm_clock` prevents a poll started before newer mapped evidence from
lowering that fault or its dependent rollups; unrelated useful data can commit.
A trap never replaces measurements, freshness or log baselines. Recovery requires
fresh explicit covering primary data. Unknown/partial input preserves faults.

Direct mappings require unique current inventory (at most 15 minutes old), the
saved target/revision and actual FQDD/serial/scoped-index proof. Redfish names,
array positions and SNMP row numbers alone are not cross-protocol identity.
HPE index-only input remains event-only for Redfish. Mapping/evidence limits
(4096 records/device, 16 conditions/component, 4 KiB compact evidence) fall back
to event history/primary reconciliation without discarding faults. Exact
cross-source history suppression additionally requires a unique shared occurrence
ID; MessageId/text/time proximity are insufficient. Fault/recovery/fault episodes
survive transport deduplication and acknowledgement follows condition changes.

Receiver reconfiguration closes old sockets before complete-set rebinding;
failure restores old saved configuration/sockets where possible. No atomic or
loss-free rebind is promised. Startup bind errors retry every five seconds while
polling/UI continue; socket failure closes/retries the set, ingestion-task failure
requires restart. Saved and active binding states stay distinct. IPv6 sockets
are IPv6-only. Informs/Reports/responses are excluded and no ACK is emitted.

Schema 2 and logical archive format 8 preserve Redfish/SNMP data and convert
older supported archives. Restore advances the runtime epoch, invalidates queued
work, pauses devices/traps/listener/channels and leaves acknowledgement requiring
review. Failed restore preserves the prior committed policy. Imported receipts
are historical and compact trap evidence inactive; neither is replayed as live
input. Runtime sequence clocks are excluded from logical archives. See
[Backup and restore](BACKUP-RESTORE.md).

`src/snmp/ups.rs` keeps strict numeric UPS contracts. Required alarm walks check
count/descriptor consistency before empty means healthy; conditions, not row
numbers, form acknowledgement signatures. Optional telemetry/phases do not create
thresholds. The [SNMP guide](SNMP.md) describes profile-specific scope and retained
fault rules. Source hashes, licenses and patch reconstruction remain maintained
as described in [Development](DEVELOPMENT.md#snmp-dependency-and-reference-tests).


Package state initialization is explicit in `postinst` (install/upgrade/repair),
using the same `initialize` CLI path as ordinary startup. A schema-1 backup is
synced and published before transactional schema-2 DDL. Startup database
contention has a 30-second busy timeout; normal database operations retain five
seconds. Service start also completes initialization in the controller before
launching the daemon. The subsequent 120-second readiness budget requires an
actual socket connection and is published after listener/shutdown-handler setup.
The migration backup therefore does not consume the daemon readiness budget. DSM stopped
and unknown status codes are 3 and 4 respectively. These paths are covered by
native and static direct-upgrade regressions, separately from NAS acceptance.

## Outgoing webhooks

Outgoing webhooks provide a separate notification transport with per-target filtering, encrypted endpoint secrets, persistent per-event/target delivery jobs and independent workers. Alarm lifecycle cancellation applies to webhook-only selections as well as existing channels. Logical archive format 8 adds endpoint and delivery tables while retaining legacy readers. See [Outgoing webhooks](WEBHOOKS.md) for the format, security, retry and lifecycle contracts.
