# SNMP P3 — supervised UDP reception and verified sender enrollment

Implemented on 20 October 2026 on branch `snmp`, on top of P0–P2 and product
baseline `2dcc528` / `0.8.0-0034`. P3 adds actual trap reception to the daemon.
Direct trap-to-alarm reduction/notifications remain P4, the editor/test view P5,
and the coordinated **0.9.0** executable/UI/INFO version change and first
installable SPK P6. No real NAS/BMC acceptance or package installation is claimed.

P4 follow-up: [shared alarm integration and its verification limits](SNMP-P4-RESULTS.md) are now implemented. The P3 descriptions below record the boundary of that stage.

## Implemented behavior

- The service owns a supervised UDP listener, disabled by default, with
  configurable unprivileged port **1162** and up to 16 disjoint local IPv4/IPv6
  addresses. Remote polling remains separately configured, default port 161;
  standard trap port is 162. Using 1162 avoids privileged binds and changes to DSM services.
  IPv6 sockets are IPv6-only so an explicit IPv4/IPv6 pair can share the port.
- Reconfiguration closes the old socket tasks before binding the replacement,
  supporting wildcard-to-specific-address changes on the same port. A failed
  bind restores the previous binding and leaves persisted settings/revision
  unchanged. Rollback failure is separately reported. Binding failure at startup
  is visible and retried at five-second intervals. A receive-task failure closes
  the socket set before retry; an ingestion-task failure stops acceptance and
  requires a service restart. Successful local bind proves no remote reachability.
- Exact enabled-source IP, explicit version, community or approved engine/user
  identity select one device. Multiple matches are rejected. v1's embedded agent
  address and payload labels never route a packet. Community traps remain
  **unverified**, regardless of the allowlist. v3 requires authPriv, the configured
  SHA-1/SHA-256 and AES-128, approved engine ID, authenticated user and exact
  context name/engine policy. Reports, responses and Informs are not accepted;
  the listener sends no ACK or other protocol response.
- The adapter uses the pinned patched library for bounded framing, full BER,
  USM, HMAC, decryption, context and timeliness validation. Untrusted headers only
  select a candidate; they never establish trust. There is no new BER/crypto or
  timeliness implementation. It rejects messages over 16 KiB without parsing a
  truncated prefix, v1 Counter64/v2 exception values and more than 128 total wire
  bindings, including the two mandatory v2/v3 prefix bindings.
- Canonical OIDs use the library's v1 conversion: generic traps 0–5 become the
  standard notification OID; enterprise-specific traps preserve the complete
  enterprise subtree plus `.0.<specific>`. Network source, wire version and
  uptime survive normalization. The BMC/ASF PET subtree is marked
  `unsupported_pet`; other OIDs remain `unclassified` until P4 profile reduction.

## Freshness and enrollment

The saved trap credentials are decrypted with the trap-specific vault AAD;
polling credentials and Redfish passwords are never substitutes. Before v3
acceptance, a new bounded authPriv GET of `sysObjectID.0` against the **saved**
agent host/port establishes authenticated engine ID/boots/time. Discovery alone
and an incoming signed trap cannot seed the baseline. The fresh observation
must match an explicitly approved engine ID before it is merged into the actual
library receiver. The merge preserves the library's monotonic remote-time rules.

This probe also works for a Redfish primary with a separate saved `snmp_poll`
target and only trap-purpose SNMP credentials: it does not walk hardware tables,
change the primary protocol, save an SNMP snapshot or update the last-poll time.
The probe has an eight-second whole-operation deadline, at most three seconds
for bounded DNS, four seconds per exchange, at most two seconds request timeout,
no timeout retry and the existing transport message/request/byte budgets.
At most two automatic probes run concurrently. Failed probes back off from
20 seconds to five minutes. A ready sender needs no periodic keepalive merely
because no traps arrive.

`snmp_trap_probe` lets an administrator inspect the freshly authenticated saved
target identity before explicitly saving the approved ID. The result has
`approval_required: true`; testing never saves approval. A new engine ID stays
blocked even on the same saved IP/port with the correct passphrases. Same-engine
boots/time advances follow the tested non-authoritative library behavior.
Timeliness failures schedule a coalesced saved-target revalidation; rejected
packet addresses never become probe targets. Unseeded traffic is dropped with
aggregate pending counters; after successful verification one primary
confirmation poll is requested if such traffic was observed. No encrypted/raw
pending packet is retained for later replay.

The daemon durably increments its private local engine boots once per start,
then shares the same library engine/clock across sender contexts and port
changes. A rebind does not increment boots. Invalid local state blocks v3 while
community reception can continue. Logical app restore cannot roll back this
state. The persistence callback verifies the already durable transition; a
future local clock rollover fails closed and requires a durable restart rather
than claiming that an unpersisted transition succeeded.

## Bounded processing and evidence

Unknown source IPs are rejected before allocation of per-source queues or use
of approved verification quota. The pre-authentication limits are 200 eligible
datagrams/second globally (burst 400), 20 per source IP (burst 40), at most 256
queued datagrams globally and 16 per source, served round-robin. Source IPs are
bounded by at most 256 enabled device policies with up to 16 sources each;
omitted devices are counted visibly. The evaluated library strategy owns one
unused ephemeral loopback socket per device context in addition to the at most
16 service sockets. No task is created per datagram. Spoofing an approved IP can
still consume its verification budget; these limits are not a general network
denial-of-service defense.

After verification/association, ingestion has separate device limits of
10/second (burst 20), global 50/second (burst 100), and a 256-item channel to one
fixed database consumer. Decoding/crypto run outside the SQLite mutex. A bounded
4096-entry, 30-second duplicate cache hashes semantic payload, device revision,
restore epoch, canonical OID, version, engine/boots and uptime; request/message
IDs and source ports are excluded. Hash inputs are not stored as raw values.

Accepted diagnostic receipts contain source IP, version, verification, engine
ID/boots where present, canonical OID, uptime, fingerprint and handling marker.
They do not directly change alarms, acknowledgements, notification jobs,
hardware-log baselines or last-poll timestamps. Accepted v1/v2c/v3 input requests
one coalesced confirming **primary** poll. Known-device overflow also requests
reconciliation where association is unambiguous. Urgent starts are at least ten
seconds apart, never parallel on a device, and share the existing four-job pool.
Ordinary due polls take priority over extra trap-triggered polls.

Receipt retention is seven days and at most 10,000 records globally, each at
most 4 KiB, enforced on insertion and by an independent minute timer. Pruning
detaches nullable compact-evidence links before deletion. No per-rejected-packet
history is written. Aggregate counts cover received/rejected/pending/ambiguous,
oversized/limited/dropped, verified/unverified, duplicate/stale/stored, pruning
and I/O/storage errors. Counter lifetime is the running service process.

The ingestion gate serializes receipt verification/commit with logical restore.
Every queued accepted item also checks the current device revision and durable
runtime epoch in its write transaction. Changed configuration/restores rebuild
policies, discard old queued work, trusted baselines, duplicates and urgent work.
The existing restore transaction pauses all device trap inputs and the global
listener; failed restore retains the preceding committed configuration.

## API and verification

The existing local CGI/Unix-socket API exposes these operations on its unchanged
DSM administrator/HTTPS/Origin/token/CSRF path:

| Operation | Behavior |
|---|---|
| `snmp_receiver_save` | Revision-checked validate/bind/persist, with rollback. A queued change completes even if its caller disconnects; after a timeout inspect status/revision before retrying. |
| `snmp_trap_probe` | Saved device ID/revision only; fresh authenticated identity, no approval/config/snapshot mutation. |
| `snmp_receipts` | Optional device filter, 1–100 latest normalized diagnostic receipts. |
| Dashboard `snmp_receiver` | Actual binding/state, counters and per-device verification/last-receipt state; `health_updates: false` makes the P3 boundary explicit. Settings, binding addresses and device identities are administrator-only. |

Fixed error messages have German/English translations. No community, password,
key, raw security payload or raw vendor varbind is returned in these diagnostics.

Passing local checks:

| Check | Evidence |
|---|---|
| Rust | 141 unit + 9 integration tests, formatting and Clippy with warnings denied. P3 covers bind/rebind/rollback/disable, dual IPv4/IPv6, no Inform ACK, routing/canonical OIDs/PET, deduplication, independent retention, stale queued work, urgent-poll gaps and API authorization/status redaction. |
| Actual daemon / independent Net-SNMP | Native and static musl: v1/v2c, v3 SHA-1/AES-128 and SHA-256/AES-128, same username/different engines and secrets, Redfish-primary enrollment, rejection boundaries, restart and explicitly reviewed engine replacement on the same IP/port. |
| Timeliness/library regression | All five P0 harness tests and 20 independent reference cases, including injected-clock long silence/drift, higher boots, stale replay and older seed rollback. This is library/reference evidence, not a long-running real BMC test. |
| Existing behavior | Redfish/CGI/daemon, pinned legacy TLS and SMTP integrations; 43 frontend tests, Vite build and 19 Python tests. |
| Dependencies | Published source plus the same two checked P0/P2 patches reconstruct exactly. No additional dependency version; `socket2` is now a direct dependency for IPv6-only binding. OSV: 237 exact public versions queried, no reported advisory; this does not audit local patches. Notices regenerated. |
| Secrets | Changed/non-ignored candidates including the complete vendor source scanned with Gitleaks 8.30.1. Six classified false positives: four source/file hashes and two public RFC 3414 known-answer vectors; no real credential found. Private temporary/runtime data remains ignored. |

Two local 60-second loads exercise malformed approved traffic, then a separate
static run combines plausible v3 wrong-HMAC traffic with unknown source IPs.
The latter sends approximately 119,000 datagrams and verifies normal polls
advance, snapshot access remains responsive, and actual API requests promptly
retain their authentication denial. Detailed measured values are recorded in
the local reports; these tests do **not** establish positive native DSM login,
maximum-device sizing, vendor interoperability or NAS firewall reachability.
P7 retains actual device/NAS tests, resource sizing, long-running operation and
installation/upgrade acceptance. P4 retains trap alarm semantics and delivery.

Reproduction (temporary private loopback fixtures, no real hardware/recipients):

```sh
cargo test --locked
cargo build --locked
python3 tools/snmp_p3_integration.py target/debug/hardware-monitor \
  --report .build/snmp-p3/reference-native.json --load-seconds 60
python3 tools/snmp_p3_integration.py /path/to/static/hardware-monitor \
  --report .build/snmp-p3/reference-musl.json --load-seconds 60
python3 tools/snmp-p0/run.py --offline
```

The reference script needs Net-SNMP `snmpd`, `snmpget` and `snmptrap`. Its private
database fixture enables settings before daemon startup; production exposes no
test authentication bypass. Reports contain case labels and aggregate timing/
resource measurements only; credentials, packets and private daemon logs stay
inside automatically removed temporary directories.
