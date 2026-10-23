# SNMP P0 — dependency decision and interoperability evidence

Date: **20 October 2026**. Product baseline: branch `snmp`, commit `2dcc528`,
application **0.8.0**, DSM package **0.8.0-0034**. P0 is complete as an isolated
dependency/interoperability spike. The installed product still has no SNMP
collector or listener. Target release remains **0.9.0-0050 or a later unused build**.

Follow-up: [P1 is now implemented](SNMP-P1-RESULTS.md); the remaining-work section below records the P0 boundary at the time of that spike.

## Decision

Proceed with **`async-snmp =0.18.1` plus the small reviewed receiver API patch**,
behind an application-owned transport interface. The unmodified high-level
receiver is unsuitable: its user map is keyed by username and cannot select
different credentials for different devices sharing that username. Its public
receiver API also cannot import authenticated polling time into remote sender
state. The alternative `snmp2` was not implemented or benchmarked; the patched
preferred candidate passed the P0 reference gates, so no fallback is selected.

Use `default-features = false`, **`crypto-rustcrypto` only**. No agent, CLI, MIB
parser, AWS-LC or FIPS feature is enabled. The crate is MIT OR Apache-2.0. Its
RustCrypto feature also compiles MD5/DES primitives; application policy must
continue to expose only SHA-1/SHA-256 and AES-128. Feature selection alone does
not enforce algorithm or minimum wire-security policy.

The [patch](../tools/snmp-p0/patches/async-snmp-0.18.1-routed-receiver.patch)
changes two source files, adding four API capabilities:

1. Import an independently authenticated engine observation with its original
   monotonic observation instant, validating engine ID, boots/time and no future instant.
2. Seed a receiver's remote-engine table using the existing monotonic merge,
   without rolling a newer baseline back to an older observation.
3. Process a caller-routed datagram through the unchanged receiver USM/PDU path,
   size check and cancellation-safe receive gate.
4. Set a bounded remote-engine capacity; per-device contexts use one entry.

The spike uses one external UDP socket and one receiver context per approved
`source IP + engine ID + username`. Each context has exactly one credential set;
no trial of multiple passwords occurs. Its current upstream builder also binds
an unused internal loopback socket per context. This is an explicit resource
cost, bounded to 16 contexts in this spike; it is not a claim of a socketless codec
API. P3 must account for descriptors and context count or obtain a separately
verified socketless builder. The patch retains upstream BER, USM, encryption,
HMAC and RFC 3414 timeliness code; no cryptographic implementation was added.

When first linking this in the product, vendor the exact pinned patched source
with its license/provenance, or use a released upstream version providing the
same tested contract after rerunning P0. Do not add an unpinned Git dependency or
require internet access during package installation. No upstream contribution
or external message was sent as part of P0.

## Reproduction and provenance

[Harness and instructions](../tools/snmp-p0/README.md). Full run:

```sh
python3 tools/snmp-p0/run.py --offline --musl --audit
```

| Item | Verified value |
|---|---|
| Published crate archive SHA-256 | `62c73521f81d79ffef8d7b3d4ece05c5d46f30729526a71af422aa0399cdc0b4` |
| Receiver patch SHA-256 | `408257b3c69f5e87d98e7fde352a73da1276851167dd1055b5c7e7aac4de790e` |
| Spike Cargo.lock SHA-256 | `09370296b2d799e7dd986c37ef46e24093f804d492ebdf1c2f1d0a143f159f00` |
| Toolchain | Rust 1.98.1; Python 3.14; Net-SNMP 5.9.5.2; repository musl 1.2.5 compiler |
| Crypto coexistence | Candidate plus actual `hardware-monitor` library compile in one Cargo graph. All existing product runtime dependency versions match the root lock, including Tokio 1.53.3, ring, OpenSSL, AES-GCM and SHA-2. |
| Static artifact | Generic `x86_64-unknown-linux-musl`, no native CPU tuning, ELF x86-64, no interpreter and no `DT_NEEDED` runtime libraries. |

The runner records binary size/hash, source/patch/lock hashes, tool versions,
case names and advisory timestamp in `.build/snmp-p0/evidence.json`. Reference
reports contain no packets, credentials or controller identifiers. Fixtures use
random generated secrets and loopback processes, no downloaded manufacturer MIBs
or copied controller payloads. The Dell-shaped nested enterprise OID tests only
RFC conversion structure; it is not a Dell profile or hardware-support claim.

## Executed checks

**Five Rust tests**, formatting and Clippy with warnings denied passed. The
independent reference suite passed **20 cases on the native binary and the same
20 on the static musl binary**. Cases group several assertions:

| Area | Demonstrated evidence |
|---|---|
| SNMPv1 polling | Net-SNMP batched GET/GETNEXT; missing OID yields `noSuchName` with error-index 2; bounded removal/retry recovers the two supported OIDs; GETBULK is refused. |
| V1 value restrictions | A typed fake peer sends Counter64 in a v1 envelope. The library accepts the generic inbound type; the application adapter rejects it before consuming values. The adapter also rejects v2 exception types under v1. |
| Response correlation | Wrong peer/source port, request ID and community do not satisfy a request; the later correct response does. This typed synthetic test uses v2c. |
| V3 polling | Independent SHA-1/AES-128-CFB and SHA-256/AES-128-CFB reads, engine discovery and authenticated time. Both wrong authentication and wrong privacy keys return errors with no health values. SHA-256 key MAC length is 24 bytes (HMAC-SHA-256-192). |
| Poll-to-receiver state | Successful independently authenticated polling results seed a newly created receiver context, which accepts a matching reference trap for both algorithms. |
| Device association | Two sender engines share a username with different secrets and different authentication algorithms; alternating traps select the correct context. Unknown source IP, username and engine ID are rejected. |
| Wire policy | Wrong HMAC/key, modified ciphertext, wrong context name/engine, `authNoPriv` and `noAuthNoPriv` are rejected. Only `authPriv` and Trap PDUs are accepted. |
| Time and replay | Injected 90-day-old authenticated observation with a 500-second clock-estimate difference; increasing boots accepted; stale same-boot time and older-boot replay rejected. An older seed cannot roll state back. |
| Bounds and cancellation | 16 KiB datagram cap with limit-plus-one receive buffer; more than 128 varbinds rejected; trailing bytes, truncation, invalid length and 512 nested unexpected SEQUENCEs rejected; 1000 malformed packets followed by a valid trap do not terminate the receiver. Pending native `recv()` cancellation leaves routed reception usable. |
| Inform exclusion | Typed v2c Inform is rejected in the acceptance policy, and its origin socket receives no ACK during the bounded test. The v3 prefilter additionally rejects reportable packets before USM processing. |
| V1 trap conversion | Standard generic traps 0–5 normalize to standard v2 OIDs; nested Dell-shaped enterprise OID preserves the complete enterprise prefix plus `.0.specific`. |

The malformed corpus is a finite regression test, **not** the sustained-load,
fairness, API responsiveness or memory measurement required in P3/P6. USM permits
some authenticated duplicates inside its replay window; application incident
deduplication remains necessary.

## Security review and interpretation

Source review covered the selected receiver, client correlation, decoder,
engine-time merge/step 7(b), key storage and tracing paths. The decoder follows
the fixed SNMP grammar rather than recursively walking arbitrary BER; strings
are bounded by the datagram and OIDs by the upstream 128-arc limit. The varbind
policy executes after decoding, so the byte cap bounds that prior allocation;
128 is an acceptance limit, not a pre-allocation limit.

Structured community/key Debug output is redacted; owned USM key/password
containers use zeroization. Reviewed trace events expose metadata/error kinds,
not password or packet dumps. The harness emits only sanitized error categories.
This is source review plus targeted Debug assertions, not a dynamic audit of
every tracing event. Community storage uses ordinary cloneable bytes, and the
test JSON/Python configuration makes ordinary copies: complete memory erasure
is not established. Production vault/typed-secret integration is required in P1/P2.

An authenticated cache entry alone does **not** prove an `authPriv` read worked:
a validly authenticated error Report can update time when the privacy key is
wrong. Enrollment and the UI device test must require an actual successful
read at the configured security level, not discovery or a populated cache.

OSV checked **234 exact dependency versions**, including the selected upstream
version and product compatibility graph, on 20 October 2026: **zero reported
advisories**. This point-in-time query does not assess the local patch or replace
source review. Dependency notices and a fresh advisory audit remain release gates.

Gitleaks 8.30.1 scanned all **14 changed/new documentation and spike files** with
redacted output: **zero findings**. Runtime directories, downloaded dependency
source, build artifacts and private temporary reference state were excluded;
the source archive is separately checked against its pinned digest. No commit
or push was performed.

## Remaining implementation and acceptance

- **P1:** typed configuration/secrets, migration/archive contracts, independently
  stored local authoritative engine lifecycle, revision/restore boundaries.
- **P2:** production transport wrapper, explicit v1 type validation, bounded
  GETNEXT cursor isolation/full table walks, budgets, profiles and CLI/API probes.
- **P3:** real configurable sockets/port changes, IPv6, persisted local-engine
  boots before use, managed remote enrollment/resynchronization, bounded contexts,
  fair scheduling/rate limits and supervision. The spike uses ephemeral local
  authoritative state and fresh authenticated seed input; it does not prove crash
  persistence, production restore, or traps without an accessible responder.
- **P4–P7:** durable receipts, alarms/deduplication, UI, CI/package integration and
  NAS plus real iDRAC/iLO fault/recovery/firmware acceptance. No real device or NAS
  was contacted, no installable SNMP package built, no product version bumped.

These are subsequent stage responsibilities, not reasons to replace the tested
candidate or to claim the full SNMP feature is already implemented.

P2 follow-up: production now vendors this exact published crate plus the recorded
receiver patch and a small decoded-varbind budget hook. The P0 native reference
suite was rerun against that patch stack. Source reconstruction and checksums are
in `vendor/async-snmp-provenance.json`; see [P2 results](SNMP-P2-RESULTS.md).
