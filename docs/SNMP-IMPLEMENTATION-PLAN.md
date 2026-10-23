# SNMP polling and traps — implementation plan for 0.9.0

Status on **23 October 2026: P0–P6 completed**; P7 real NAS/hardware acceptance is partially confirmed: the user confirmed build 0.9.0-0051 installation and the DSM polling profile on 21 October 2026; the remaining matrix is open. Protocol configuration, schema-2 migration, format-5 archives, bounded polling, supervised trap reception, shared alarm integration, the bilingual SNMP UI and versioned/static package validation are implemented on the development branch. See the [P6 package result](SNMP-P6-RESULTS.md), [P5 UI result](SNMP-P5-RESULTS.md), [P4 result and limits](SNMP-P4-RESULTS.md), [P3 receiver result](SNMP-P3-RESULTS.md), [P2 polling result](SNMP-P2-RESULTS.md) and [P1 result](SNMP-P1-RESULTS.md). Current package: `0.9.0-0056`, built from the `snmp` working tree based on `2dcc528` / `0.8.0-0034`; the manifest records dirty state/content identity. See the [P0 decision and evidence](SNMP-P0-RESULTS.md). Initially reviewed against `2010c46` / `0.8.0-0030`; external-review findings verified on 19 October 2026 against the then-current commit `c37e1cd`, package `0.8.0-0031`. Repository documentation is maintained in English. See the [review verification record](SNMP-REVIEW-VERIFICATION.md) for accepted findings, corrected report claims and evidence limits.

The subsequent [Synology DSM polling profile](SNMP-SYNOLOGY-RESULTS.md) is added in package 0.9.0-0051; it does not add DSM trap support.

Build 0056 corrects [HPE iLO population, firmware-dependent fan units and power/storage context](SNMP-HPE.md), using the supplied iLO 6 capture. Native DSM/live acceptance remains open.

Build 0054 adds [APC, Eaton and RFC 1628 UPS polling](SNMP-UPS-RESULTS.md).

Build 0052 adds [scoped generic availability and network discovery](SNMP-GENERIC-NETWORK-RESULTS.md). This deliberately changes the generic assessment contract; unavailable optional inventory/sensors do not block availability assessment.

Target: **application 0.9.0**, DSM package **0.9.0-0050 or a later unused build number**. Keep the numeric package build counter increasing. Update version metadata with the implementation, before producing its first installable package; the existing 0.8.0 package must not advertise unimplemented SNMP functionality.

## 1. Decisions and release scope

Implement an integrated SNMP collector and UDP notification receiver inside the existing Rust/Tokio daemon. Continue to use SQLite, the encrypted credential vault, DSM authentication, acknowledgements and the existing SMTP/desktop delivery queues.

| Area | Decision for 0.9.0 |
|---|---|
| Polling | One explicitly selected primary collector per device: Redfish or SNMP. No automatic protocol fallback. |
| Traps | Optional independently configured SNMP input for either primary collector. |
| Versions | SNMPv3 `authPriv` is the default. Explicit per-device compatibility options for **v1/v2c polling** and v1/v2c traps. No automatic version downgrade. |
| Cryptography | General preference: SHA-256 with AES-128-CFB. The explicitly selected Dell iDRAC7/8/9 profile visibly proposes SHA-1 (`SHA` in Dell UI) with AES-128 for documented compatibility; preserve manually chosen/saved algorithms. Validate each firmware. No MD5, DES, silent downgrade or v3 `noAuthNoPriv` application traffic. |
| Trap port | Default **UDP 1162**, globally configurable from **1024 through 65535**. |
| Polling port | Remote agent port, configurable per device from **1 through 65535**, default **UDP 161**. Local source port is ephemeral. |
| Initial hardware profiles | Implementation targets: Dell iDRAC7/8/9 and HPE iLO 5. Publish support only for model/firmware/security/coverage combinations that pass P7; existing Redfish tests do not establish SNMP support. |
| Generic devices | Standard identity/uptime discovery and supported standard sensor data only; no promise of complete generic hardware health. |
| Trap consequences | A securely attributed, mapped fault can raise/update an alarm immediately and schedule a confirming poll. Recovery requires a subsequent explicit current-state observation. |
| Installation default | Existing Redfish devices remain Redfish; SNMP and the UDP listener start disabled. |

Release exclusions are listed in section 13. In particular, 0.9.0 does not add simultaneous Redfish and SNMP polling for the same device, a trap-only healthy-state assessment, or Inform acknowledgements.

## 2. Findings in the current source

| Current path | Finding | Required change |
|---|---|---|
| `src/model.rs`: `Device`, validation, timeout/freshness | HTTPS origin and username are mandatory; timeout is derived from the TLS profile. | Add protocol-specific configuration and validation; SNMP-only devices must not require HTTPS, a TLS certificate or Redfish credentials. |
| `src/main.rs`: `collect`, `poll`, `serve` | Calls `Redfish` directly, at most four concurrent device jobs, one job per device, pause after completion. | Dispatch collectors, preserve concurrency/revision guarantees, add supervised receiver and a bounded urgent-poll queue. Update CLI test/poll paths too. |
| `src/api.rs`: `DeviceInput`, `prepare`, `Operation::Test` | Device preparation and testing construct a Redfish client; secrets use the device ID as vault context. | Protocol-specific inputs, separate SNMP credentials, redacted outputs and precise probe results. |
| `src/store.rs`: `apply_revision` | A snapshot updates `last_poll`, replaces the saved snapshot, handles log baseline, alarm transitions and notification grouping together. | **Never pass a trap to this method as a complete snapshot.** Introduce a partial evidence transaction and share the alarm reducer. |
| `src/store.rs`: `save_admin` | Target change means an HTTPS endpoint change; it clears target state and cancels jobs. | Compare protocol, target host/port and identity/profile changes explicitly; distinguish retargeting from credential rotation. |
| `src/identity.rs`, `src/correlation.rs` | Identity evidence is limited to Redfish PSU representations; graph extraction accepts Redfish paths. No reusable cross-protocol FQDD/serial alias index exists. | Persist typed hardware aliases from Redfish discovery and SNMP profiles; add graph construction without weakening the Redfish URL validator. |
| `src/assessment.rs`, `src/acknowledgement.rs` | Redfish applicability and condition fingerprints determine summary/acknowledgement behavior; overall status requires a fresh snapshot. | Keep Redfish-specific applicability in its adapter, add SNMP-specific applicability, and represent trap evidence independently of poll freshness. |
| `src/notification.rs`, `src/history.rs`, `web/src/events.js` | Event category depends on `collector`, `coverage:` and `hardware_log`; some coverage messages explicitly say Redfish. | Keep the primary `collector` key compatible, generalize text and add a consistent trap event classification/filter in backend, CSV and frontend. |
| `src/archive.rs` | Current base already uses logical format 4 for mail replay; formats 1–3 convert forward. | **Format 5** adds SNMP records and purpose-separated credential conversion. P1 implemented this while preserving pause/cancellation/revision guarantees. |
| `packaging/conf/privilege`, `tools/check_spk.py` | Package identity, empty resource configuration, no systemd units/optional workers; packaging checks enforce this. | Use an unprivileged UDP port and retain these tested packaging constraints. |
| `docs/ROADMAP.md` | The earlier planning edit corrected build 0027/acknowledgement drift; current package metadata has since advanced to build 0034. | Keep the current-build marker aligned and link this plan, without rewriting historical acceptance evidence. |

The existing invariants remain acceptance requirements: unknown/missing data cannot clear faults, unrelated physical faults stay independent, credentials never reach dashboard output, and obsolete work cannot overwrite a device edit or restore.

## 3. Ports, listening and DSM operation

The standard remote command-responder port is UDP 161; the standard notification-receiver port is UDP 162 ([RFC 3417](https://www.rfc-editor.org/rfc/rfc3417)). An existing NAS service on 161 does not conflict with outgoing polls using ephemeral source ports. The actual NAS listener state has not been inspected for this plan.

Choose 1162 because it can be bound by the existing package identity. This is a proposed default, not a reserved or guaranteed-free port. Do not disable DSM SNMP, share another daemon's socket, use `SO_REUSEPORT`, install a root receiver, or silently redirect 162.

Global receiver settings:

- `enabled`, `listen_port` and explicit local listen addresses; default address `0.0.0.0`, optional IPv6 `::`. The listener remains closed until enabled by an administrator.
- Support individual NAS management addresses. Use separate IPv4/IPv6 sockets and explicit `IPV6_V6ONLY` behavior to avoid accidental duplicate/overlapping binds.
- Display the exact configured address/port, active runtime address/port, receiver state and sanitized error. Ports below 1024 are rejected with an explanation in this release; do not present 162 as usable without a privileged integration.
- A different port is applied by binding all replacement sockets first, persisting the revisioned configuration, and switching the receiver only on success. If persistence/binding fails, retain the old listener and settings. Same-socket policy changes reuse the socket where possible; changes needing a close/rebind require an explicit failed-state/rollback path, not a second competing receiver.
- A same-port address change between wildcard and individual addresses is an overlapping bind and requires a short close-then-rebind path. Gate ingestion, close the old sockets, bind the complete new address set, then persist/activate it. On any failure close partial replacements and rebind the previous set; keep previous saved settings. If rollback rebind also fails, expose saved versus active state accurately and enter degraded/retry mode. No `SO_REUSEADDR`/`SO_REUSEPORT` workaround or atomic/no-loss promise for this path. Test both address-change directions and rollback failure.
- On restart, a bind failure leaves polling and the DSM UI running. Show trap reception as degraded, retry with bounded backoff, and raise a monitoring warning for affected enabled devices through the existing channel filters. Recovery of this warning does not clear any hardware fault.
- Stop closes sockets and drains/cancels bounded work. Lifecycle hooks remain the existing native daemon control.

The device must send to `NAS-management-IP:configured-port`; changing the application port does not reconfigure a controller. Dell documents `iDRAC.SNMP.AlertPort` for iDRAC7/8 and iDRAC9; HPE documents `Oem/Hpe/SNMPTrapPort`. These are documentation findings, not proof for the installed firmware. A controller's setting may affect all its trap destinations. Record that consequence in setup instructions and verify it before changing a device. ([Dell iDRAC7/8 reference](https://dl.dell.com/topicspdf/idrac7-8-with-lc-v2.20.20.20_reference-guide_en-us.pdf), [Dell iDRAC9 attribute](https://www.dell.com/support/manuals/en-bm/idrac9-lifecycle-controller-v3.2-series/idrac_3.20.20.20_racadm_ar/idracsnmpalertport-read-or-write?guid=guid-b58c9c1f-2dbb-4f43-ae8d-f5851bc7419a&lang=en-us), [HPE network protocols](https://servermanagementportal.ext.hpe.com/docs/redfishservices/ilos/supplementdocuments/networkprotocols))

Document DSM firewall rules for the selected NAS address, UDP port and specific BMC source addresses, plus outbound polls/replies. Do not automatically rewrite DSM firewall rules. If a firmware cannot target a custom port, mark direct reception unsupported for that firmware; polling can still be supported. An external forwarding receiver is a separate deployment option, not a hidden package dependency.

## 4. Library selection and the first implementation gate

Use a small internal transport/codec interface so vendor profiles do not depend directly on a library's PDU types. Do not implement BER, USM or cryptographic algorithms ourselves.

**Preferred evaluation candidate: `async-snmp`, documented version 0.18.1.** Its documented API covers Tokio clients and notification reception. **Alternative: `snmp2`**, with Tokio and a crypto backend; its documented low-level trap decoding needs more receiver lifecycle/security integration. These are source/documentation candidates, not approved production dependencies. Pin the evaluated version in `Cargo.lock`; recheck the actual published source, license and advisories at implementation time. Avoid runtime MIB parsing, CLI and agent features. ([async-snmp](https://docs.rs/async-snmp/0.18.1/async_snmp/), [snmp2](https://docs.rs/snmp2/latest/snmp2/))

P0 must examine the selected crate's exact code and prove:

1. Static generic-x86-64 musl build with the project's Rust toolchain and current crypto dependencies; no runtime Net-SNMP or system OpenSSL dependency.
2. Correct authenticated response correlation, peer checking, USM discovery/time synchronization, reboot behavior and SHA-1/SHA-256 plus AES-128 interoperability against Net-SNMP reference peers. Verify RFC 7860 HMAC-SHA-256-192 rather than assuming that a library's algorithm label proves the correct digest truncation, and RFC 3826 AES-128-CFB wire behavior. ([SHA-2](https://www.rfc-editor.org/info/rfc7860/), [AES](https://www.rfc-editor.org/rfc/rfc3826))
3. V3 traps from **multiple sender engine IDs**, including the same username with different device secrets; credentials must be selected by a bounded approved device identity, not a single global username map. The inspected 0.18.1 builder has `HashMap<Bytes, UsmUser>` and inserts by username, replacing a previous entry with that name. Its direct high-level configuration therefore cannot meet this requirement. P0 must validate a supported lower-level routing/codec path or a narrowly scoped upstream change before approving this candidate. Do not impose unique usernames silently or try every saved password against an incoming packet. ([Pinned receiver source, lines 683 and 871–882](https://docs.rs/async-snmp/0.18.1/src/async_snmp/notification/mod.rs.html#683))
4. Enforced wire security level, permitted PDU types and source/context policy. Configuring keys alone must not permit a lower security level. Reject malformed/trailing data and oversized/deep BER before unbounded work.
5. Bounded receiver memory/CPU, cancellation safety, secret redaction including dependency tracing, and no unbounded engine/user cache created by unauthenticated traffic.
6. SNMPv1 GET/GETNEXT interoperability against a reference agent, including `noSuchName`/`error-index` handling, bounded request splitting and version-specific type/operation restrictions. V1 polling is a required compatibility mode, not a deferred feature.
7. Correct non-authoritative trap timeliness after long silence, increasing engine boots, receiver restart and clock-estimate differences; no symmetric responder-style time-window check for traps. Test with injected clock state rather than waiting months. Prove that managed enrollment/resynchronization initializes the receiver's per-sender state, not just a separate polling client's cache.

The candidate receiver documents automatic Inform responses before delivering accepted notifications to the caller. For 0.9.0, reject Inform PDUs in its acceptance policy before any acknowledgement; do not imply durable Inform ingestion. Its API also requires a persisted local engine when USM users are configured, even for a receiver used only for traps. Include that lifecycle or choose a verified lower-level trap path. ([Receiver contract](https://docs.rs/async-snmp/0.18.1/async_snmp/notification/))

P0 output: a short recorded decision with exact dependency version/features, reference-test results, musl artifact check, gaps and the chosen API boundary. Do not build the rest of the feature around an unverified receiver assumption.

**P0 decision:** use `async-snmp =0.18.1`, `default-features = false`, `crypto-rustcrypto`, with the [checked receiver API patch](../tools/snmp-p0/patches/async-snmp-0.18.1-routed-receiver.patch). A caller-owned socket routes approved source/engine/user identities to bounded per-device receiver contexts; authenticated polling observations seed the actual receiver table through monotonic merge. The original BER/USM/crypto/timeliness implementation remains intact. The spike also proved that inbound v1 Counter64 needs an explicit application filter, and that the receiver envelope excludes the two mandatory v2/v3 varbinds when reporting its payload count. Preserve both contracts. Vendor the pinned patched source with licenses when first adding the production dependency, or reevaluate an equivalent upstream release; do not use unmodified high-level username routing. The prototype uses one unused internal socket per context and ephemeral local authoritative state; P1/P3 must implement the persisted lifecycle and bound resources. Full results, provenance and remaining gates are in [SNMP-P0-RESULTS.md](SNMP-P0-RESULTS.md).

Algorithm defaults must reflect the selected profile. Dell's iDRAC7/8 attribute reference lists None/MD5/SHA; its OpenManage guidance also lists SHA/MD5 for iDRAC9. Use the permitted SHA-1/AES-128 combination as the explicit Dell compatibility proposal, while retaining SHA-256 as the general preference for capable devices. A login-password SHA-256 hash is not evidence of SNMPv3 SHA-256 support. ([iDRAC7/8 authentication attribute](https://www.dell.com/support/manuals/en-ms/idrac8-lifecycle-controller-v2.81.81.81/idrac8_2.81_racadm/idracuserssnmpv3authenticationtype-read-or-write?guid=guid-897c75fa-daff-4e80-a1b8-c82da0f57cbb&lang=en-us), [iDRAC9 incoming-alert compatibility](https://www.dell.com/support/manuals/en-us/dell-openmanage-enterprise/ome_4_5_online_help_user_guide/manage-incoming-alerts?guid=guid-f240314c-8940-4e1b-bdd1-7ac268000a07&lang=en-us))

## 5. Configuration, credentials and persistence

Keep `Device.id`, name, enablement, notifications and repeat policy. Introduce an explicit primary protocol and typed Redfish/SNMP settings. Preserve the existing public Redfish fields while adding the new structure, or provide a tested legacy conversion at every JSON entry point; avoid an unnecessary wholesale API rewrite.

Proposed logical records:

| Record | Contents |
|---|---|
| Device config | `primary_protocol`, existing Redfish config when used, `snmp_poll` when used, independent `snmp_traps` input policy. |
| SNMP poll config | Host/IP, remote port, explicit version (`v1`, `v2c` or `v3`), v3 username/context and auth/privacy algorithms where applicable, profile selection, timeout/retries and discovery policy. No secrets. |
| SNMP trap config | Enabled flag, exact allowed source IPs, accepted versions/security level, approved sender engine IDs/context, credential reference and profile. Sender source port is not fixed to 161/162. |
| `protocol_secrets` | Device ID, purpose (`snmp_poll` / `snmp_traps`), encrypted credential bundle, revision. Community strings are secrets too. |
| `snmp_receiver_settings` | Global address/port/enablement configuration and revision. |
| `component_identity` | Source protocol/profile/version, source URI or table/OID/index, device/chassis scope, stable physical alias (FQDD/serial where proven), inventory generation, poll revision and canonical alarm key. Persist Redfish aliases too. |
| `snmp_receipts` | Bounded normalized accepted trap evidence, occurrence/fingerprint, timestamps, revision, verification/mapping status and linked event ID. No raw packets or communities. |
| `observation_evidence` | Per canonical component: source, poll generation/trap sequence, last validated observation, provisional state and confirmation requirement. |

Use existing AES-GCM vault operations with domain-separated AAD such as `device:<id>:snmp_poll` and `device:<id>:snmp_traps`. Keep Redfish/SMTP ciphertext contexts compatible. Poll and trap credentials may be explicitly shared within a device, but their identity and lifecycle remain separate from the Redfish password. Keep localized keys in bounded memory only; zeroize secrets and clear them from browser forms. API responses expose only configuration and `has_*_secret` flags.

Blank/keep, replace and clear are distinct admin actions. Switching protocol, host, security user/context or credential purpose must never silently reuse a credential for another target. Credential rotation bumps revisions and invalidates clients/caches; changing only credentials does not erase hardware history. A primary target replacement resets target-specific snapshots, aliases, baselines and alarms using the existing retarget semantics, while preserving event/audit history. A trap-policy edit invalidates queued receipts and revalidation work without resetting healthy primary-poll state.

Validate SNMP usernames/contexts/engine IDs by protocol byte limits rather than the existing Redfish character limits; require valid algorithm combinations and sufficiently long auth/privacy passphrases. Support IPv6 addresses explicitly, reject malformed hosts/ports, and never normalize or trim secret bytes. DNS resolution and enrollment must have deadlines and bounded address/candidate counts.

V1/v2c polling uses an encrypted-at-rest community string and does not require v3 usernames, context or auth/privacy fields. These modes send the community and data without encryption or cryptographic integrity; show this explicitly when selected. Correlated responses from the configured peer may update hardware state and confirm recovery under the selected compatibility mode, but must never be labeled cryptographically authenticated. Version selection is deliberate: timeout, unsupported OID or authentication failure must not trigger a downgrade from v3/v2c to v1.

P1 implements an explicit transactional database migration from schema 1 to schema 2 for the new persistent model, with private pre-migration SQLite/key backup. Back up before migration; schema 2 makes old binaries reject the database rather than ignoring new secrets/state. Idempotent reopening must not repeat conversion. Keep old Redfish keys/acknowledgements intact; convert legacy config with SNMP disabled. Validate both web and CLI imports, restored rows and all public redaction paths.

## 6. Polling and vendor profiles

Add `src/snmp/` with `config`, `transport`, `poll`, `receiver`, `normalize`, `identity` and `profiles` modules. Add a small collector dispatcher, retaining the current Redfish implementation and its tests. A trait is optional; two explicit collector variants are sufficient.

Polling flow:

1. Resolve the configured target with a deadline, use explicit IPv4/IPv6 peer addresses, load credentials and perform bounded v3 engine discovery when necessary. An unauthenticated discovery response is a candidate identity, not trusted health data.
2. Read `sysObjectID.0`, `sysDescr.0`, `sysName.0` and `sysUpTime.0`; confirm actual data access and identify the supported profile. A reachable UDP socket or engine-discovery Report is not a successful hardware test. P0 also showed that a validly authenticated error Report can populate engine time when only the privacy key is wrong. Require successful data access at the configured security level, not merely a nonempty authenticated cache, before completing enrollment or a device test.
3. GET known scalars and walk only allowlisted profile table subtrees. For **v1 use GET/GETNEXT exclusively**; never send GETBULK. Batch GETNEXT cursors for up to eight required columns initially; advance/finish each cursor independently, enforce its own column prefix and join results by the complete typed row-index suffix, never by returned position. Adapt batch size on `tooBig`; isolate a failing cursor without discarding unrelated columns. Prefer GETBULK for v2c/v3, adapt `max-repetitions` down on `tooBig`/size limits, and use bounded GETNEXT fallback. No root-tree walk.
4. Require strictly advancing OIDs, correct subtree membership, matching response/request/peer and version-specific community/security/context, and valid typed values. For v2c/v3 handle `endOfMibView`, `noSuchObject` and `noSuchInstance` as coverage/absence evidence, not success or automatic recovery. Apply the v1-specific error rules below instead of expecting these exception values.
5. Normalize into the existing observation/resource model with explicit SNMP provenance, completeness and supported coverage. Keep HTTP fields optional; use an OID capability identifier and protocol-specific outcome codes.
6. Apply under the device revision and poll/trap ordering rules in section 8. Preserve validated partial data when a later table/limit fails.

Initial tunable bounds: 2-second request timeout, at most one timeout retry; 60-second full poll deadline; at most **512 transmitted requests for v1**, **128 for v2c/v3**, and for every version 4096 varbinds and 4 MiB decoded/received data per poll. Count discovery, retries, v1 request splitting and fallbacks against the selected request cap and shared time/data budgets; the larger v1 cap does not extend the deadline. For v2c/v3 start bulk repetition at 10 and lower it on oversized responses; for every version abort non-advancing/repeated walks. Keep the existing 30–86,400-second pause range and four-device concurrency limit. These starting values require P0/hardware measurements before finalization; a profile may justify a bounded higher deadline with matching freshness calculation. Measure v1's higher request count separately and report incomplete coverage when any budget is exhausted.

SNMPv1 compatibility rules ([SNMPv1 protocol](https://www.rfc-editor.org/rfc/rfc1157), [version coexistence](https://www.rfc-editor.org/rfc/rfc3584)):

- A `noSuchName` error applies to the request rather than providing v2-style per-varbind exception results. For a multi-OID GET, validate `error-index`, isolate the failing OID and retry remaining OIDs with bounded splitting. Do not accept the error response's other values as successful observations. Invalid indexes, inconsistent errors or exhausted budgets produce incomplete coverage, not an endless retry.
- For a batched GETNEXT `noSuchName`, validate `error-index`, finish/isolate the identified cursor and retry the remaining cursors within budget; do not stop all columns or consume other values from the error response. For a single cursor this ends its accessible view. Leaving that cursor's allowlisted column subtree also finishes it. Neither case proves that a formerly faulty component is healthy or that all expected rows were read; compare expected coverage and retain unresolved faults.
- V1 has no Counter64 wire type. Skip profile fields requiring it with explicit unsupported coverage; never truncate a Counter64 to 32 bits, fabricate zero or substitute an incompatible OID. Continue collecting supported hardware status/sensor fields. Unexpected v2 exception values or unsupported wire types in a v1 response are invalid data. Enforce this in the application transport adapter: P0 confirmed that the generic library decoder accepts Counter64 even inside a v1 envelope.
- Keep the same canonical component identity and alarm/acknowledgement rules across v1/v2c/v3 where the profile exposes equivalent data. An explicit version change invalidates protocol clients and in-flight work; it does not by itself identify a different physical device or erase retained faults.

Cache validated inventory and v3 engine state by device revision and verified target identity. Revalidate inventory periodically (initially 15 minutes), after a verified management-engine restart or a missing/changed component. `sysUpTime.0` describes the management subsystem, not proof of a host power cycle or target replacement. Its 32-bit TimeTicks wrap at approximately 497.102696 days: compare modular tick deltas with monotonic elapsed time and plausible drift, not just a lower value or a previous value near the maximum. If multiple wraps/resets cannot be distinguished, record uncertainty and rediscover without clearing faults or target identity. Authenticated v3 boots/time provides management-engine generation evidence; plain v1/v2c counters do not gain cryptographic assurance. Row indexes are scoped to inventory generation. Use bounded backoff/jitter after repeated failures and reset it after a successful poll. Keep the displayed configured pause distinct from temporary error backoff. ([TimeTicks definition](https://www.rfc-editor.org/rfc/rfc2578.html#section-7.1.8))

| Profile | Initial coverage and evidence requirement |
|---|---|
| Dell | iDRAC out-of-band MIB, overall/system and storage summaries, PSUs, fans, temperature, memory and supported controller/disk tables. Use explicit service tag/serial/FQDD relationships where exposed; never infer component identity from row number or display text. Dell documents `globalSystemStatus.0` as `1.3.6.1.4.1.674.10892.5.2.1.0`. ([Status group](https://www.dell.com/support/manuals/en-us/openmanage-software-v9.3/snmp_idrac_cmc_9.3_ref_guide/status-group?guid=guid-1a12fe37-b563-42f2-a080-601d10b07e14&lang=en-us)) |
| HPE | Explicit CPQHLTH/CPQSM2/CPQIDA and relevant host-health objects advertised by iLO. Select actual tables/OIDs from the model's MIB kit and live coverage; do not assume OS-agent/AMS data is present. Test PSU/fan/temperature, memory and supported storage conditions separately. |
| Generic | SNMPv2-MIB identity/uptime and positively supported ENTITY-MIB / ENTITY-SENSOR-MIB information. Identity or uptime alone never makes overall hardware health OK. |

Each checked-in profile defines exact numeric OIDs, ASN.1 types, enum-to-health mappings, scaling/unit/sentinel rules, stable identity fields, trap fault/recovery classification and confirmation scope. Include MIB source/version/checksum and sanitized fixtures. Use vendor MIB redistribution only with checked license permission; numeric mappings do not require installing a MIB parser on the NAS. Missing or unsupported fields remain Unknown/unsupported. An enum's `other`, a missing disk, zero-valued sentinel or empty inventory is not a universal healthy state.

P2 implementation details: descriptions/labels are cached for up to 15 minutes; physical serial/FQDD identities, sensor type/scaling and all health/readings are queried in every poll. A fresh current system identity is mandatory. Runtime engine/inventory caches are bounded to 256 device contexts and invalidated by revision/runtime epoch/target changes. `sysUpTime` modular wrap is distinguished from an agent epoch change; it is never evidence of a host power cycle. The production dependency includes a second small transport observer patch so discovery, Reports and error-response varbinds consume the shared 4096-item budget. See the checked patch stack and hashes in `vendor/async-snmp-provenance.json`.

The evaluated client uses the authoritative engine as its scoped context engine. P2 accepts a non-empty context name and an optional expected context engine ID only when that ID equals the authenticated engine; arbitrary proxy context-engine routing is not supported. No fallback to a different context or security version is attempted.

## 7. Trap input and trust boundaries

Receiver pipeline: bounded UDP receive/truncation check → enabled-source IP allowlist → bounded envelope/policy precheck → fair pre-authentication verification budget → full decode/USM verification and exact approved-device association → post-authentication ingestion limits → trap canonicalization/profile normalization → bounded receipt transaction → alarm update/urgent poll.

- Prefer v3 `authPriv`. Match source IP, approved sender engine ID, authenticated user, configured context and required security level. Engine ID by itself is spoofable. Do not route by `sysName`, payload host strings or v1's embedded agent address.
- Learn a sender engine identity through an administrator's successful authenticated probe and save it with the device revision. For Redfish-primary devices this can be a separate SNMP enrollment probe. Manual expected engine-ID entry is allowed but must be verified with matching credentials before health-changing traps are enabled. Unexpected engine-ID changes require deliberate review.
- After receiver restart, re-establish authenticated remote engine time before a trap can change hardware state, or restore a verified non-rollback timeliness baseline. Until then keep receipt diagnostic-only and request a bounded saved-target probe. Do not treat an empty process cache as permission to accept historical fault packets as current evidence.
- For the planned managed bootstrap/revalidation path, a Redfish-primary device must permit authenticated SNMP probes to its separately configured agent address/port (default 161). These are bounded identity/time probes, not a second hardware collector. If the responder is disabled and no valid baseline can be restored, show “SNMPv3 trap verification pending / responder unavailable”; do not silently report active health-changing trap support. Probe-free bootstrap needs a separately validated freshness policy; an incoming HMAC alone cannot establish the age of the first packet after lost state.
- Apply RFC 3414 §3.2 step 7(b) for the non-authoritative receiver: authenticated newer sender time/boots can advance its state; do not apply the authoritative responder's symmetric ±150-second rule. Same-engine-ID boots increments do not require new identity approval. Unknown engine-ID changes still do. No periodic keepalive is required solely because no traps arrived; long silence and clock-estimate differences must pass P0 tests. Resynchronization on an actual failure uses coalesced, bounded saved-target probes, never an address from the rejected packet. ([USM processing](https://www.rfc-editor.org/rfc/rfc3414.html#section-3.2))
- Exact source IP allowlists are independent of polling DNS. Re-resolution must not silently authorize a new trap sender. Ambiguous associations, unknown sources, invalid auth/privacy, wrong context and unexpected versions are dropped with bounded aggregate counters, without generating a device alarm per rejected packet.
- V1/v2c **traps** are opt-in compatibility inputs with exact source/community matching. They provide no cryptographic integrity: retain them as unverified event evidence and trigger a bounded confirming primary poll; they cannot directly change hardware alarm state, confirm identity or clear a fault. This restriction is specific to unsolicited traps; explicitly selected v1/v2c polling still supplies current observations under section 5's compatibility policy.
- A verified but unknown trap OID from an approved device may create a bounded informational/unclassified history entry. It does not prove a hardware fault or healthy state. Known event-only traps use their profile severity and an explicit trap notification filter; unknown and test traps never trigger automatic fault notifications.
- Do not follow addresses, URLs or OIDs supplied by a trap into new network requests. Urgent polling always uses saved device configuration and allowlisted profile queries. No trap-triggered shell commands.
- Traps have no protocol acknowledgement and UDP can lose/reorder them. Receiver counters mean local receipt/processing, not guaranteed delivery. Absence of traps is not evidence of either health or a failed receiver.

Start with a 16 KiB maximum accepted datagram, at most 128 total wire varbinds (including the two mandatory v2/v3 prefix bindings) and 1024 display characters per vendor text field, plus bounded BER nesting/OID/string allocations. Detect truncation using an oversized bounded receive buffer or `recvmsg(MSG_TRUNC)`; never parse truncated prefixes as valid packets. Validate these limits against real vendor messages in P0/P7.

Reject unknown source IPs before they consume approved-sender verification tokens. Use the selected library's bounded framing/envelope parser to precheck version, permissible flags, candidate engine ID/user or community without an unbounded decode or state allocation; these fields remain untrusted until verification. Encrypted v3 scoped context is checked only after successful authentication/decryption. Do not write a second ad hoc BER parser for this prefilter.

Use a bounded queue of 256 accepted items and separate pre-authentication CPU budgets from post-authentication device/ingestion limits. Start verification limits at 200 eligible datagrams/second globally (burst 400), 20/second per approved source (burst 40), with fair scheduling across approved senders. Rejected authentication must not consume another device's authenticated-ingestion quota or grow trusted caches. A spoofed approved IP plus plausible copied headers can still consume verification capacity; allowlists/header checks are not a complete UDP denial-of-service defense. Record this limit and use the scoped DSM/network rules from section 3. Test unknown-source floods separately from plausible approved-source spoofing.

Do not spawn a task per datagram or hold the SQLite mutex while decoding/performing crypto. Coalesce confirming polls to one per device, with at least ten seconds between urgent poll starts and no parallel poll of that device. Normal polls and API/delivery work must continue under a trap storm. Queue overflow/drops are visible and request one later reconciliation for the affected known device, without promising recovery of event-only messages.

Canonicalize v1 Trap-PDU headers before profile lookup: standard generic values 0–5 map to `1.3.6.1.6.3.1.1.5.<generic+1>`; enterprise-specific value 6 maps to the exact received enterprise OID plus `.0.<specific>`. Preserve v1 header time-stamp as uptime and retain wire-version/provenance. V2c/v3 use the validated `snmpTrapOID.0`/uptime prefix. Exact enterprise subgroups matter; do not hardcode one shortened Dell prefix or add a second `.0` to already normalized v2/v3 OIDs. Prefer a tested library conversion (`Notification::trap_oid()` already delegates v1 conversion in the inspected candidate) over duplicate conversion code. Use the canonical OID for profile/semantic matching while preserving version/security evidence in receipt fingerprints. Detect the BMC/ASF PET family `1.3.6.1.4.1.3183.1.1` as a separate unsupported format and suggest the native vendor SNMP alert format; do not feed opaque PET payloads to native iDRAC mappings. ([RFC 3584 §3.1](https://www.rfc-editor.org/rfc/rfc3584.html#section-3.1), [Dell BMC/ASF MIB](https://www.dell.com/support/manuals/en-ca/openmanage-software-v11.0.0.0/om_11.0.0.0_snmp_pub/server-administrator-baseboard-management-controller-asf-mib?guid=guid-dec9fac1-2b91-4d51-b018-8919189aef50&lang=en-us))

## 8. Alarm ordering, confirmation and deduplication

Keep transport receipt, physical component identity, fault condition and event occurrence as separate concepts.

For a mapped v3 fault, use the profile plus verified physical identity to resolve the existing primary collector's canonical component key. On a Redfish device keep its current Redfish key; on an SNMP device use a stable profile/component key, with a scoped index fallback only where no stronger identity exists. Multiple conditions/severities must remain distinguishable in condition fingerprints and acknowledgement lifecycle. Equal labels, equal severity or nearby timestamps do not prove the same fault.

On a Redfish-primary device, a direct component transition additionally requires an unambiguous alias persisted from a valid Redfish inventory for the current target/revision: for example a full Dell FQDD or a non-placeholder serial plus chassis/component scope. Revalidate stale or replaced inventory before using its alias; receiving a trap must not invent it. A MIB chassis/bay/index does not prove equality with a Redfish MemberId or array offset. If the trap only provides such indices or no matching alias exists, retain the receipt and request an urgent Redfish poll; the poll owns component transitions. No SNMP table walk is silently added to a Redfish-primary device.

Match actual trap definitions rather than manufacturer-wide assumptions: Dell documents `alertFQDD`; HPE's 6035 fan trap carries chassis/index, whereas its 6049 PSU trap also documents a serial number. Neither establishes the exact payload emitted by the installed iLO firmware until P7. Missing/ambiguous aliases stay event-only. A successful primary poll that lacks the relevant coverage is not a reason to discard that event; preserve the unconfirmed evidence and apply the explicit event-only notification policy. ([Dell variables](https://www.dell.com/support/manuals/en-us/openmanage-software-v9.3/snmp_idrac_cmc_9.3_ref_guide/trap-variables?guid=guid-ff17f5b2-14e5-4d5b-821f-4b974916968f&lang=en-us), [HPE trap definitions 6035 and 6049](https://support.hpe.com/hpesc/public/api/document/c05315472?v=1632332395000))

| Input | Alarm/result |
|---|---|
| Verified, mapped v3 fault | Raise/update the canonical alarm immediately with provisional trap evidence; enqueue one confirming poll. Existing acknowledgement is reconsidered only for a new/worsened condition. |
| Poll confirms the same fault | Update evidence/freshness; no second transition email/desktop job. |
| V3 fault has no reliable component/confirmation mapping | Retain event-only evidence with provenance and enqueue an urgent primary poll; let that poll own component transitions. Apply the explicit event-only notification policy; do not create an unresolvable component alarm or guess a Redfish association. |
| Recovery/normal-state trap | Record evidence and request a poll; never clear an alarm directly, including v3. |
| Later poll explicitly reports that component/condition OK | Resolve once, provided this poll started after the latest relevant trap and genuinely covers the fault's confirmation scope. |
| Later poll is partial, missing the component, unsupported, timed out or Unknown | Retain the fault and show confirmation pending/unavailable. No expiry-based recovery. |
| Device paused/deleted, target changed, or restore completed | Reject stale queued evidence by device/receiver revision and runtime epoch. No further automatic jobs for the old configuration. |

**Ordering rule:** configuration revisions alone are insufficient. Capture a per-device trap sequence when each poll starts. At commit, a poll cannot lower/clear a component whose relevant trap sequence has advanced since that start. Save useful unrelated observations, retain the newer fault and schedule a subsequent poll. Serialize state transactions, not network traffic; use monotonic local sequencing instead of controller wall-clock timestamps. Test both arrival orders and delayed packets within the USM window.

**Freshness rule:** accepted traps update `last_trap_received` and evidence timestamps, never `last_poll`, the measurement snapshot timestamp or hardware-log baseline. Show “poll data stale” independently from a known current/retained trap fault. Extend backend assessment and `web/src/health.js` so a stale/missing poll does not hide a newly received verified critical alarm; it still cannot produce overall OK. Acknowledgement remains a local operator action, not hardware recovery.

**Receipt deduplication:** use a bounded fingerprint based on device/engine generation, version/PDU class, trap OID, stable component/condition fields and sender occurrence identity (sequence/event ID/uptime where meaningful). Exclude outer v3 message IDs and transport source port, which can change across retransmissions. Initially use a 30-second duplicate window only for profiles without a stronger occurrence identity; document that fallback and preserve distinct fault/recovery/fault occurrences. USM timeliness is not exact-once event deduplication.

**Cross-source event deduplication:** use the canonical alarm transition for mapped poll/trap faults. Link matching Redfish hardware-log records only when the profile has evidence of the same occurrence, such as a stable vendor event/record identifier plus component and generation. `MessageId` usually identifies an event type, not a unique occurrence, and is insufficient alone. Extend `HardwareLog` normalization to preserve these optional identifiers; its current hash cannot generally be matched to a trap. Attach evidence without submitting another automatic message, while preserving raw historical records/delivery history. If proof is absent, show separate provenance and do not suppress a possibly independent fault. UI grouping alone is insufficient because delivery jobs already exist.

Refactor the transactional alarm transition/grouping/acknowledgement code for reuse by full polls and partial trap updates. A trap transaction must not mark unrelated components Unknown, rebuild a partial containment graph, initialize log baselines or discard saved measurements. Pending-job cancellation and the existing submission gate apply to trap-generated jobs exactly as they do to polling jobs.

## 9. API, UI and diagnostics

Extend the existing local CGI/Unix-socket operations; add no public HTTP SNMP management API. All writes/tests continue to require verified DSM administrator access, HTTPS, matching Origin, DSM token, CSRF proof and matching revisions.

- Device editor: primary protocol selector, protocol-specific fields, SNMP profile/version/security/context/port and separate “Receive SNMP traps” configuration. Offer v1/v2c community input or v3 security fields according to the explicitly selected version, with a cleartext/no-integrity explanation for v1/v2c. Redfish credentials/certificates remain visible only where applicable.
- Receiver settings: enablement, local addresses, port, active status and bind failure. A configuration change validates/binds; it does not claim a real controller can reach the NAS.
- Probe output: selected SNMP version, confirmed data access, security assurance, engine identity for v3, detected profile, supported/missing groups and elapsed time. V1/v2c report community-based access without authenticated-message assurance. Explain that identity access alone does not prove complete hardware coverage. Keep within the current 20-second API/25-second browser path by using a dedicated bounded probe, not a full walk.
- For a wrong-digest outcome, suggest checking both the passphrase and SHA-1/SHA-256 selection. A correlated Report containing `usmStatsWrongDigests.0` (`1.3.6.1.6.3.15.1.1.5.0`) is useful diagnostic evidence, not proof of which setting is wrong; an unverified Report cannot change trusted state. Agents may discard failures without a Report, so timeout diagnostics must include security/protocol mismatch as a possibility and never require that Report to arrive. Do not auto-try weaker algorithms or repeatedly retry wrong credentials.
- Expose sender identity changes and missing verification baseline as distinct review-required/pending states, including last accepted trap and rejection counts. Same-engine boots increments, local receiver restart and a genuinely changed engine ID need separate explanations/actions; never silently keep a misleading active badge.
- Trap test view: after the operator sends a controller test trap, show matched source/device, version, security verification, OID, receive time and profile handling. Synthetic loopback tests and real controller receipt must be labeled separately. Test traps do not create hardware alarms.
- Dashboard: primary source, last saved poll, last accepted trap, provisional/confirmed/retained alarm evidence, poll coverage and receiver health. No single “Connected” badge conflates these facts.
- Event history, CSV and mail/desktop templates: preserve source/verification metadata, use a consistent trap category/filter for event-only notifications, and retain existing alarm/recovery/repeat behavior for mapped state changes. Default event-only trap delivery off until deliberately selected; existing selections/legacy archives keep their behavior.
- Add English/German labels/error codes and placeholder parity checks. Preserve manufacturer messages as untrusted plain text; HTML-escape in UI/mail, neutralize CSV formulas, and never expose communities, keys or raw security payloads in diagnostics.

P3 operations: `snmp_receiver_save`, `snmp_trap_probe` for the saved target/revision, read-only receiver status in the dashboard, and bounded `snmp_receipts` inspection (1–100 records). The dedicated probe returns an observed identity with explicit approval still required; it does not save approval. Reuse `save`/`test` for protocol-aware device operations. Keep new admin test actions on the same authorization path and audit them without secrets.

## 10. Retention, backups, restore and rollback

Keep new operational state bounded from the first release. Initial receipt retention: seven days, maximum 10,000 records globally, maximum 4 KiB normalized data per record. Store compact duplicate fingerprints separately (maximum 4096, expire after their window). Aggregate rejection/drop counters; do not persist every rejected packet. Run pruning independently of a successful poll. Record truncation/eviction counts. Existing event/backup limits still apply; never silently omit required archive records to fit an export.

Introduce **logical archive format 5**. P1 corrected the earlier numbering because mail replay already uses format 4. Preserve the authenticated encryption envelope and existing readers' migration path for formats 1/2/3/4. Before fixed-table validation, convert format 4 by adding the new tables/default settings and any required nullable event columns. Test conversion from every currently accepted format. Export SNMP config, encrypted-in-archive credentials, identity mappings and necessary alarm evidence; re-encrypt secrets with destination vault AAD on restore. Include event-linked receipts if needed for historical explanation, but not raw packets or expired caches.

Do not export/replay local engine ID/boots/time, live remote time caches or pending urgent polls. Keep the local engine lifecycle in private runtime state separate from app logical backups: a normal restart atomically increments persistent boots before use; a port rebind reuses the same running engine; loss of authoritative state requires a new engine identity or fail-closed recovery. App restore must not roll back its counters. A native upgrade backup may contain runtime files for disaster recovery, but replaying an older authoritative engine state is not a supported shortcut. ([USM persistence and roles](https://www.rfc-editor.org/rfc/rfc3414))

Restore uses the shared submission gate plus a receiver-ingestion gate/runtime epoch: stop acceptance, invalidate queued datagrams/polls, validate and replace records transactionally, and rebuild clients/policies only after commit. On successful restore pause all devices/channels **and the trap listener**, cancel pending deliveries and leave imported acknowledgements requiring review. On failed restore retain the previous database/configuration and resume its prior receiver policy. Cross-NAS restore uses the destination's local engine identity; this matters for any future Inform support.

Rollback to 0.8.0 requires stopping the new service and restoring its matching pre-upgrade database/master-key backup and old SPK. Do not start an old binary against schema 2 or claim that a format-5 archive is backward-readable. Preserve a copy of the failed/new database for diagnosis. Native DSM upgrade/rollback remains an explicit NAS test.

## 11. Implementation sequence and deliverables

Complete the work in this order; each stage's exit criterion is required before its dependent stages.

| Stage | Work and principal files | Exit criterion |
|---|---|---|
| P0 — dependency and interoperability spike **completed** | Isolated reference harness; library/source/crypto review; musl build; sanitize MIB/fixture provenance. | [Recorded patched API decision and passing native/musl reference tests](SNMP-P0-RESULTS.md); multi-engine/multi-secret traps, non-authoritative time handling, wire security enforcement and cancellation/size limits demonstrated. |
| P1 — data model and upgrade **completed** | `model.rs`, new SNMP config/secrets, `store.rs`, `vault.rs`, `archive.rs`; protocol dispatcher and legacy conversion. | [Implemented and tested](SNMP-P1-RESULTS.md): legacy Redfish records, credentials, snapshots, events and acknowledgements survive migration; formats 1–4 import; failed migration/restore atomic. Network adapters and UI remain subsequent stages. |
| P2 — SNMP polling **completed** | Transport wrapper, v1 GET/GETNEXT and error handling, v2c/v3 bulk discovery, bounded walks and per-profile normalization; `main.rs`/CLI/API test integration. | [Implemented and verified locally](SNMP-P2-RESULTS.md): numeric profiles, bounded reads, sparse/multi-index joins, partial preservation, protocol-independent physical keys and retained faults. Native/static product CLI tested against independent Net-SNMP v1/v2c/v3 authPriv; vendor/NAS acceptance remains P7. |
| P3 — UDP receiver **completed** | Configurable bind/supervision, USM/source policy, canonical OIDs, fair queue/limits, enrollment and receipt retention. | [Implemented and verified locally](SNMP-P3-RESULTS.md): custom port, dual IPv4/IPv6, same-port address changes/rollback; v1 conversion, no Inform ACK; fresh saved-target v3 enrollment for SNMP/Redfish primaries, restart and reviewed engine replacement; bounded storm test with normal polls/API responsive. Long-silence/reboot/replay behavior additionally verified in P0 injected-clock/reference tests. Real BMC/NAS endurance remains P7. |
| P4 — alarm integration **completed** | Shared reducer, evidence/identity mapping, ordering, acknowledgement, notification/CSV categories and known-occurrence correlation. | [Implemented and verified locally](SNMP-P4-RESULTS.md): one submission for a mapped trap/poll transition, old OK cannot clear a newer fault, poll-owned recovery, distinct conditions and unrelated faults retained, scoped identity/generation checks and exact-occurrence contract. Native vendor traps lacking a unique shared log occurrence ID are not guessed to match hardware logs. UI controls are delivered in P5; real device/DSM acceptance remains P7. |
| P5 — UI and localization **completed** | `DeviceEditor.vue`, new receiver settings/test view, `App.vue`, `health.js`, `events.js`, catalogs, template/history/filter changes. | [Implemented and verified locally](SNMP-P5-RESULTS.md): protocol-specific editor including v1, separate secret actions, explicit saved-target sender review, configurable listener/test receipts, event-only opt-in and provenance. Admin/viewer controls, provisional/stale assessment, English/German and placeholder parity tested. Browser checks use a separate synthetic fixture; native DSM and real controller acceptance remain P7. |
| P6 — package/release validation **completed** | Version files, build/test harnesses, static dependency notices, SPK inspection and CI SNMP integration. | [Implemented and verified locally](SNMP-P6-RESULTS.md): matching 0.9.0 / 0.9.0-0050 executable/UI/INFO/manifest, checked static DSM 7 x86_64 SPK, native/static SNMP integration and load checks wired into CI, dependency notices/audits and dirty-source publication rejection. No hosted CI run/publication or P7 hardware acceptance is claimed. |
| P7 — NAS/hardware acceptance and documentation completion **partially confirmed; cleanup pending** | Real NAS/profile acceptance, maintained SNMP setup/operation documentation and repository/package documentation cleanup, as specified below. Includes generic availability, generic network, Dell/HPE/Synology and APC/Eaton/RFC 1628 UPS profiles. | User-confirmed build 0.9.0-0051 installation and DSM polling profile on 21 October 2026 ([record](SNMP-SYNOLOGY-RESULTS.md#user-confirmed-dsm-acceptance-21-october-2026)). Remaining acceptance is recorded per model/firmware/profile; documentation consolidation, removal of temporary reports/phase references and validation of the cleaned package are also required. |

Parallelism within ordinary build/test operations is possible, but P0 findings determine the dependency and P1/P4 contracts. Do not treat frontend completion or passing codec tests as hardware acceptance. If an initial profile fails the required real-device gates, fix it or narrow the published matrix explicitly before release.

### P7 completion work: acceptance and documentation

Added at the user's request on 22 October 2026. The documentation work below is
**planned, not completed**. It can proceed independently of outstanding real-device
checks. Completing documentation does not turn local/synthetic results into
hardware acceptance, and partial hardware acceptance does not complete cleanup.

**NAS and profile acceptance**

- Maintain a central matrix for every implemented profile: generic availability,
  generic network/interface discovery, Dell iDRAC, HPE iLO 5, Synology DSM, APC
  PowerNet, Eaton xUPS and generic RFC 1628 UPS-MIB. Record the actual device,
  management card where applicable, firmware, DSM/package build, selected SNMP
  version/security, exposed data and tested behavior. Extend the original
  RS2421RP+/Dell/HPE target list with the actual DSM, network and UPS targets;
  do not assume all products of a manufacturer expose the same MIB.
- Verify supported polling versions, credentials/security, partial or unsupported
  coverage and profile-specific assessment. Include required versus optional
  groups, previously active interface monitoring, UPS states/units and retained
  faults under missing data. Keep operational confirmation separate from actual
  fault/recovery acceptance.
- For applicable trap paths, verify configured destination port and firewall
  reachability, coexistence with DSM's SNMP service, source/engine enrollment,
  actual device-generated test traps, poll/trap ordering, acknowledgement and
  notification behavior. Record unsupported or unmapped traps explicitly;
  polling-profile acceptance does not imply vendor trap correlation support.
- Include a direct 0.8.0 → 0.9.0 upgrade without any earlier SNMP development
  installation, a first start delayed beyond five seconds, repeated repair and
  unchanged credentials/history/acknowledgements. The 0054 DS220+ startup-timeout
  report and the RS2416RP+ repair requirement remain native acceptance cases
  after the locally validated 0055 correction.
- Check native DSM installation/UI/roles, receiver restart and occupied-port
  behavior, device/agent reboot and resynchronization, upgrade, restore and
  rollback. Record safely authorized fault/recovery scenarios per applicable
  device; obtain separate authorization for device configuration changes or
  physical fault injection.

**Maintained documentation and cleanup**

1. Create `docs/SNMP.md` as the maintained user/operator guide, in English like
   the existing repository documentation. Cover prerequisites and read-only
   permissions; SNMPv1/v2c/v3 and separate polling/trap credentials; remote
   polling port versus local listener port; controller destination/firewall
   setup; source/engine enrollment; every profile's MIB, assessment scope,
   required/optional coverage and limitations; interface discovery/link policy;
   UPS states/units; retained/provisional alarms, acknowledgement and recovery;
   diagnostics, common errors and operational troubleshooting.
2. Consolidate durable technical content into `ARCHITECTURE.md` and
   `DEVELOPMENT.md`, device setup into `DEVICE-MANAGEMENT.md` and the new SNMP
   guide, confirmed combinations/limits into `HARDWARE-COMPATIBILITY.md`, and
   concise current evidence/open checks into `VALIDATION.md`. Keep README and
   release notes concise and consistent with those maintained documents.
   Preserve useful facts and their evidence limits before removing their old
   documents, including reports not yet committed to Git.
3. Remove superseded temporary documents after consolidation: this
   `SNMP-IMPLEMENTATION-PLAN.md`, `SNMP-REVIEW-VERIFICATION.md`,
   `SNMP-P0-RESULTS.md` through `SNMP-P6-RESULTS.md`, and the standalone
   generic/network, Synology and UPS implementation-result reports. Do not
   retain duplicate archive copies in the maintained documentation or SPK merely
   to move the clutter elsewhere. Keep or consolidate source/provenance records
   that remain necessary for maintenance, reproducible checks or licenses;
   preserve required third-party notices and patch provenance.
4. Remove obsolete implementation-phase wording and references throughout
   project-owned README/docs, source comments, test tools, CI and package
   checks. Where file/tool names themselves encode a temporary phase, replace
   them with descriptive names and update all callers as needed. Preserve
   functioning regression fixtures/tests and meaningful technical identifiers;
   do not blindly rewrite external vendor content or historical fixture data.
5. Repair stale or contradictory claims, duplicated sections, broken links and
   orphan references, including references to files already removed from the
   working tree. Distinguish implemented, locally tested, user-confirmed and
   still-unverified behavior in one coherent compatibility/evidence record.
6. Update packaging and validation together with the cleanup. In particular,
   `tools/check_spk.py` currently requires this plan inside the SPK; replace that
   requirement with the maintained SNMP documentation. Review the packaged
   documentation set, check remaining relative links/anchors and obsolete phase
   references, and run affected build/CI/package checks. Create and inspect a
   fresh SPK with a new build number when the cleanup is delivered.

**Completion boundary:** the maintained SNMP guide and consolidated technical/
compatibility documentation are complete, temporary planning/review/result files
and obsolete phase references are removed, and the cleaned source/package checks
pass. Hardware checks are either evidenced or explicitly listed as pending,
unsupported or outside the published support matrix; no unverified combination
is advertised as tested. P7 remains partially complete while required hardware
acceptance or this documentation work is still outstanding. This temporary plan
is removed last, after its durable requirements and remaining checks have been
transferred to the maintained documentation.

## 12. Verification and release acceptance

| Layer | Required scenarios |
|---|---|
| Poll protocol | Correct/wrong credentials, timeout, wrong peer/request/context, truncated/malformed BER, `tooBig`, empty/unsupported groups, sparse/multi-index tables, repeated/non-increasing OIDs, end-of-subtree, budget abort and partial preservation. |
| V1 polling compatibility | GET/GETNEXT with no GETBULK; independent batched column cursors/full row-index joins on sparse tables; correct/wrong community; GET and GETNEXT `noSuchName`, valid/invalid `error-index`, cursor isolation and bounded splitting; end-of-view/subtree; Counter64-only fields unsupported; malformed/v2-only types rejected; 512-request/time/varbind budgets; version change preserves physical fault identity; no automatic downgrade. |
| V3 security | SHA-256/AES-128 and explicitly selected Dell SHA-1/AES-128; wrong-digest Report versus silent timeout; forged/lower-level messages rejected; replay/duplicate/reordered packets; long silence/clock-estimate differences using injected clocks; higher same-engine boots versus changed engine ID; receiver restart with missing baseline/disabled agent; multiple engines sharing usernames with different secrets. |
| Identity/health | Persisted Redfish FQDD/serial aliases versus index-only traps; stale/ambiguous aliases; stable component across discovery/index changes; 497-day wrap, management-agent restart and long ambiguous gaps; enum/sentinel/scaling rules; simultaneous faults; unknown versus empty/not-applicable; unsupported profile never globally OK. |
| Traps | V1/v2c opt-in, v3; standard v1 generic traps 0–5 and enterprise-specific conversion; HPE and nested Dell enterprise OIDs; PET recognized as unsupported; known/unknown/test/recovery OIDs; incorrect community/source, unknown engine, source-port changes, IPv4/IPv6, limits, disabled listener, duplicates, overflow and rate limits. |
| Races and notification | Trap before/during/after a poll, old OK result after newer fault, repeated fault/recovery/fault, acknowledgement/worsening, pause/delete/retarget/credential edit, restore during receive/delivery and restart after event commit. |
| Persistence/export | Schema 1→2, archive 1/2/3/4→5, format-5 cross-key restore, malformed archive rollback, secret redaction, new records/CSV filters, pruning with no successful polls, source evidence and pending-job cancellation. |
| Load | Sustained 100 valid/invalid datagrams per second for at least 60 seconds plus a 1000/second burst; unknown-source traffic cannot consume approved-source verification quotas; plausible spoofed approved-source headers and fairness tested separately; bounded memory/queue, no process exit, measured API/poll/delivery responsiveness and visible drop counters. Adjust limits from measurements; do not claim complete UDP DoS resistance. |
| Regression/package | Existing Rust/Clippy, frontend, translations, HTTPS/legacy TLS, SMTP, acknowledgement/history/backup and package checks; new SNMP harness against the actual static musl binary; no root/systemd/optional resource changes. |

P6 composes the P2/P3/P4 actual-product suites in `tools/snmp_integration_test.py` and retains the isolated `tools/snmp-p0/` source/security regressions. Both are wired into the package/CI checks with explicit reference-tool dependencies. Net-SNMP tooling remains development/CI-only; credentials use private temporary config/stdin, never real secrets on command lines. Deterministically seeded decoder and profile-normalization corpora cover mutated/truncated/random frames, bounds, ambiguous identity and untrusted text; the P0 library harness also verifies valid authenticated reception after its malformed corpus. This bounded regression corpus is not exhaustive fuzzing or a complete security audit. CI contacts no real controller or recipient.

Real-device acceptance must record model, firmware, supported/selected polling versions, SNMP settings/security algorithms, exposed OIDs, received trap metadata and primary-poll results. Include a real v1 polling acceptance case with supported sensor/status data and a missing OID, and record unsupported versions per firmware rather than assuming v1 is available on every controller. For each listed model verify custom trap destination port, a real controller-generated test trap, a safe authorized fault/recovery scenario, reboot/resynchronization and channel behavior. Synthetic fixture events do not establish physical fault interoperability. Verify coexistence with DSM's own SNMP service, firewall reachability, occupied-port behavior, restart/upgrade/rollback and package identity on the NAS. Obtain explicit authorization before controller configuration changes or physical fault injection.

The first installable implementation updates:

- `Cargo.toml` and the root package entry in `Cargo.lock` to `0.9.0`.
- `web/package.json` and both root version fields in `web/package-lock.json` to `0.9.0`.
- `packaging/INFO.dsm7` to `0.9.0-0050` or a later unused monotonically increasing build number; generate fresh versioned HTML/launcher and Vite assets.
- Current-build references in README, architecture/development/roadmap documentation, demo data, actual version assertions and release notes. Keep historical evidence and fixtures with deliberately old versions unchanged.
- Dependency license notices, checked SPK, manifest and checksums through the existing build pipeline. Retain fixed download asset names and the current supported DSM 7 x86_64 target.

Run an explicit password/key/runtime-data audit before commit/push without printing sensitive values. Publish only after all applicable local/package checks and the required NAS/hardware gates pass; report CI/upload/NAS evidence separately. A version bump alone does not satisfy SNMP acceptance.

## 13. Deferred work and decision boundaries

| Deferred item | Dependency and acceptance boundary |
|---|---|
| Inform support | Separate follow-up after receiver review: durable acceptance before success response, duplicate retransmission acknowledgement, authoritative engine lifecycle and crash/restart tests. Do not auto-ACK in 0.9.0. |
| Binding standard port 162 | Separate DSM privilege/socket handoff design and NAS validation; no root/capability/forwarding change included in this release. |
| Redfish + SNMP polling concurrently | Separate source ownership/freshness/precedence design and physical cross-source fault matrix; 0.9.0 uses one primary collector plus traps. |
| Automatic fallback | Needs explicit policy for source change, identity, stale state and recovery; cannot silently mask TLS/auth/coverage failures. |
| Passive trap-only devices | Needs independent assessment and fault-resolution semantics; no trap silence → OK rule. |
| Additional vendors/custom MIB upload | Requires reviewed profile mappings, fixture provenance/license and hardware evidence; no arbitrary runtime MIB scripting. |
| MD5/DES, authNoPriv, AES-192/256 variants | Excluded unless a separate justified compatibility/security review adds a precise tested mode. |
| Trap forwarding, agent/SET/server control | Separate functionality; monitoring performs GET/GETNEXT/GETBULK only. |
| Charts, general rule editor, broad monitoring redesign | Independent roadmap items; no dependency on shipping bounded SNMP polling/traps. |

These items have no allocated implementation budget in 0.9.0. Revisit only with a concrete requirement and their stated prerequisites. The P0 spike is the point to resolve library/security uncertainty before committing to the full implementation.
