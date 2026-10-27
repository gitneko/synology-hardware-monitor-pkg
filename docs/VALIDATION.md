# Validation and evidence boundaries

Current package: **0.9.0-0064**. Local source/reference/package checks,
authorized live read-only collector runs and user-reported NAS acceptance are
separate evidence. The [compatibility matrix](HARDWARE-COMPATIBILITY.md) records
actual combinations; [SNMP](SNMP.md) describes operation and limitations.
Historical results below retain their original versions and dates.

## Current acceptance

The following are **user-confirmed for the reported deployment**, not blanket
coverage of every model, firmware, security variant or physical failure:

| Date | Accepted workflow |
|---|---|
| 21 October 2026 | Installation of 0.9.0-0051 and Synology DSM polling profile |
| 23 October 2026 | Dell iDRAC9 v3 traps after the optional-context correction (0059), immediate mapped alarms and configured email/DSM notification workflow |
| 24 October 2026 | Trap reception, reception after package restart and after DSM reboot, following delivery of compatibility visibility (0061) |
| 27 October 2026 | HPE iLO, Generic and Network Generic SNMP operation |
| 27 October 2026 | Native DSM upgrade **0.8.0-0043 → 0.9.0-0062**, application backup and restore |
| 27 October 2026 | Incorrect credentials, unknown sender, changed Engine-ID checks, fault → recovery, operator acknowledgement and **duplicate handling** |

The changed-ID report describes rejection already on save; it does not establish
a separately observed live replacement-engine datagram test. Generic/Network/HPE
confirmations do not supply an exact model/firmware/security matrix. The DSM
polling target model/version is unrecorded and is not inferred from the hosting
NAS. Backup acceptance does not imply all historical archive variants or
cross-NAS restore. Restart confirmation does not enumerate every port's manual
capability/intervention state.

Duplicate acceptance covers the reported incident workflow: repeated ongoing
fault plus confirming poll does not create another immediate state-alarm
submission; confirmed recovery followed by a new fault creates a new incident.
Periodic reminders remain intentional. The bounded transport cache and positive
shared-occurrence requirement for history suppression are described in [SNMP](SNMP.md#alarms-duplicate-handling-and-notifications).

**Agreed release scope:** APC PowerNet, Eaton xUPS and generic RFC 1628 profiles
ship **untested on real UPS hardware**. No suitable hardware is available;
synthetic/reference coverage is not hardware interoperability. Future hardware
tests are not a blocker for this agreed scope. DSM Package Center downgrade
0.9.0 → 0.8.0 is outside the supported acceptance path, separate from local
failed-migration/restore transaction recovery. No downgrade workaround is offered.

The reported core SNMP acceptance workflow is complete. Broader targets,
unreported security variants, long-running load and full DSM role integration
remain additional coverage, not a reopening of those accepted checks. See
[NAS acceptance](NAS-ACCEPTANCE.md) and [Roadmap](ROADMAP.md).

## Local regression coverage

Independent Net-SNMP agents/traps plus controlled loopback HTTPS/SMTP exercise
the actual product, without contacting a controller, NAS or real mail recipient.
The aggregate wrapper runs the following native and static executable suites:

| Suite | Verified contract |
|---|---|
| Polling | v1, v2c, v3 SHA-1/AES-128 and SHA-256/AES-128, actual probe/save/poll, wrong credentials, sparse walks, budgets, redaction and partial input |
| Receiver | Saved-target enrollment and explicit approval, source/engine/user/context/security rejection, IPv4/IPv6, rebind/rollback, restart, no Inform ACK and bounded receipt retention |
| Alarm / SMTP | Immediate provisional fault, old in-flight OK ordering, one submission for trap plus confirmation, poll-owned recovery, new identical-payload fault and shared submission gates |
| Profiles | Synology enums/zero/sparse rows, Generic optional groups, Network durable active-link baseline/rates/reset/missing input, HPE population/units/capture replay |
| UPS | Three profiles × v1/v2c/v3-SHA1/v3-SHA256; typed states/units, sparse alarms/phases, double-count proof, new-condition acknowledgement, partial retention and recovery |
| Load | Default package build: two 60-second receiver/alarm scenarios, invalid/unknown/spoofed-eligible bursts, continuing polls/API and local SMTP; explicit skip mode is recorded |
| Patched library | Five unit tests and 20 independent reference cases: multi-engine/shared-user routing, wire crypto/security, long silence, injected clocks, monotonic seeding, malformed corpus, cancellation and v1 conversion |
| Persistence / UI | Schema migration, separate secrets, restore gates/epochs, history/CSV, configuration round trips, bilingual/placeholder parity, viewer controls and text escaping |

These are bounded reference/corpus tests, not exhaustive fuzzing, maximum NAS
sizing, complete memory erasure or a full security audit. USM time checks do not
provide exact-once incident delivery. A valid error Report/cache entry alone is
insufficient for enrollment: a real successful read at configured authPriv is
required. Source/patch checksums and required licenses remain maintained;
[Development](DEVELOPMENT.md#snmp-dependency-and-reference-tests) gives reproduction
commands and the patched API boundary.

The 0063 validation baseline passed 234 library tests and three binary tests
(with two intentionally ignored tests in total), ten Rust integration tests,
76 frontend tests, Clippy, the real HTTP regression and static package checks.
Those counts describe that baseline, not a freshly repeated full suite for every
later documentation change. Current cleanup checks and artifact evidence are
recorded under build 0064 below.

## Build 0064: spacing and documentation consolidation

The event-retention note now aligns with the panel title/actions. The saved
sender verification button has a 20-pixel gap before the polling-interval row.
The production UI and both locations were checked in an isolated local browser
with a disabled synthetic SNMP device; all 76 frontend tests passed. No live
controller or NAS configuration was changed. Native DSM appearance of this
specific spacing change is not independently claimed.

The maintained SNMP guide consolidates setup, profile contracts, security,
clock compatibility, alarms, diagnostics and troubleshooting. Temporary phase,
review and feature-result reports are removed after their durable content is
transferred; source/license/patch provenance and regression fixtures remain.
Reference tools have descriptive names; package checks require maintained docs
and validate local documentation links/anchors in source and the SPK. The receiver load fixture also restores its regular poll interval after the
clock-hint case had deliberately postponed it for a day; otherwise its unchanged
60-second automatic-poll assertion necessarily failed. This is a test setup
correction, not a runtime scheduling change. The final
package and tool verification are recorded with the delivered artifact; no
hosted CI run, publication, commit or push is implied by local checks.

## Build 0063: total event count

The former Events counter counted grouped records from the latest-100 dashboard
window. It now uses a separate full retained-table `event_count`, while the header
separates displayed messages, stored events and the latest-100 selection. Store
and full local HTTP regressions check 150 retained records, 50 new records and
clearing to zero while only 100 records load. Retention, CSV and alarms remain
unchanged. Native DSM acceptance of this specific counter correction has not
been separately reported.

## Controller clock compatibility evidence

The reported iDRAC9 firmware **7.00.00.185**, MEM7114 test, used trap boots
**1/time 388** after restart while the authenticated saved-target check reported
**boots 113** (last accepted trap boots 111). The differing trap/responder clocks
explain strict timeliness rejection; this is not an ordinary increasing boots
case or proof that all real hardware-event traps behave identically.

Build 0060 introduced explicit default-off polling hints; 0061 made their
receive time and unconfirmed freshness prominent. Local independent packets
prove the reported tuple triggers a real primary poll only with compatibility
enabled, cannot lower the strict baseline, cannot update accepted receipt time,
and still rejects bad signatures/privacy, unapproved identity, contexts and
lower security levels. Hints are volatile status, never normal receipt/event/
direct-alarm evidence. Subsequent user acceptance is recorded above; no blanket
controller-restart/firmware matrix is inferred.

## HPE capture and direct-upgrade diagnosis

A supplied DL20 Gen11/iLO 6 1.79 capture contained matching sets of 2,041 HPE
OIDs in v2c/v3. The sanitized 69-row fixture preserves types/indexes while
replacing identifiers. Local replay verified one populated/one empty PSU bay,
empty DIMMs, three fan values 7/7/41, poweredOff and unknown empty CPQIDA storage.
Firmware boundaries and original MIB/advisory sources establish percent units
only on identified iLO 5 >=3.06 / iLO 6 >=1.61. Removal history survives process
restart; missing presence cannot recover. Capture replay is not a new BMC query.

The earlier 0054 report was RS2421RP+/DSM 7.4.1 working after prior development
installs, RS2416RP+/7.3.2 working after repair, and DS220+/7.4.1 failing with
startup timeout. A local actual-0054/archived-0018 upgrade with a six-second
SQLite lock reproduced the five-second failure; it does not establish the NAS's
precise latency cause. Build 0055 added explicit post-install initialization,
120-second readiness and 30-second initialization contention budget. The same
local delayed start then succeeded. The actual-product suite covers fresh
install, legacy preservation, repeated repair, delayed start and failed
migration/retry with disabled polling/delivery; it also verifies a complete
synced pre-migration database/key pair. The user's later successful
0043 → 0062 upgrade is accepted, without assigning that result to each earlier
model-specific failure. Package downgrade remains unsupported.

## Historical validation

Reviewed for 0.8.0-0018 on 18 October 2026. Build 0017 passed 50 Rust and 27 frontend tests. Build 0018 changes packaging/CI/documentation and adds seven isolated release-publication tests. Current package hashes and source identity are recorded in `dist/current/latest-assets/build-manifest.json` and `SHA256SUMS`; test output is retained in Actions logs. Source archives intentionally exclude `dist` and private runtime state.

## Current confirmed platform and systems (19 October 2026)

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). The user confirms that its functions have been tested with iDRAC7, iDRAC8, iDRAC9 and iLO 5 on the hardware listed in the [README](../README.md).

- Dell PowerEdge R420 / iDRAC7 2.63.60.62: testing confirmed by the user; hardware readings and fan/redundancy alarms were observed.
- Dell PowerEdge R330 / iDRAC8 2.86.86.86: testing confirmed by the user; the authorized build-0024 collector run completed 116 resources without query failures and the overall health calculation returned OK.
- Dell PowerEdge R340 / iDRAC9 Enterprise: previously demonstrated live discovery and user-confirmed polling, PSU fault and notification workflows.
- HPE ProLiant DL160 Gen10 / iLO 5 v3.22: testing confirmed by the user; authorized read-only session access and complete build-0027 collector runs verified with exact server-certificate pinning.

## Build 0034 iLO applicability (20 October 2026)

Live read-only diagnosis reproduced all 28 unknown rows: four fans and 19 temperature sensors explicitly reported Absent; a finite PowerControl consumption measurement had neither Name/type nor Status; two healthy empty SATA Storage inventories omitted Volumes and each advertised its controller in embedded and standalone forms. The SATA-only protocol arrays and explicit ownership links were read directly. No missing-component inference relies on display names, model names, zero readings or guessed URI prefixes.

The corrected development collector completed 51 available resources in 6.169 seconds with no query failures. It explained all 28 raw Unknown observations as 23 absent, one informational and four empty-controller representations. The actual failed SmartStorage disk remained Critical and the device's overall status remained Critical. Exact certificate pinning preceded authentication; temporary local state had notifications disabled and was removed afterward. Production configuration was not changed.

Local checks passed: 110 Rust tests, 43 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. The sanitized fixture and HTTPS integration cover all 28 rows alongside a real-shaped Critical SmartStorage drive. Negative cases cover contradictory presence, explicit faults/conditions, untyped measurements outside PowerControl, absent/unknown controller evidence, mixed protocols, attached inventory, null/advertised Volumes, paging and invalid counts. Retained faults and their operator acknowledgements survive an absent reading; raw Unknown does not become OK or create recovery. Native DSM installation remains a [target check](NAS-ACCEPTANCE.md#additional-coverage-not-a-reopening-of-accepted-checks).

## Build 0033 manual recorded-event email replay (20 October 2026)

The administrator-only Events action renders the selected recorded event with saved SMTP templates/language/time formatting and one selected saved recipient. A durable, actor-bound preview ID makes confirmation idempotent. Each intentional new preview/job has a new Message-ID; transient retries retain its ID and rendered content. A separate table/history preserves the original event, automatic delivery progress, hardware alarm state and acknowledgement. Automatic/manual SMTP queues alternate when both have work. Settings changes, event clearing and backup restore prevent stale work from being submitted.

Local validation passed 105 Rust tests, 42 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. New cases cover original event identity/time and literal placeholders, one recipient, preview ownership/expiry, duplicate confirmation, stable retry IDs across restart, terminal failures, SMTP-setting changes, clearing, unchanged acknowledged alarms, recovery/log/query events, administrator/CSRF/submission-gate enforcement and archive formats 1 through 4. Restore keeps submitted history but cancels queued jobs and discards previews.

The actual daemon worker passed a loopback SMTP test with automatic email disabled: one manual message reached only the selected synthetic recipient with the expected subject, literal body content and Message-ID; restarting did not resubmit it. The German/English dialog was also exercised with synthetic browser data, including recipient selection, preview, separate history and a simulated lost submission response followed by confirmation of the same ID. Both requests referred to one job. Browser fixture submission does not imply real SMTP delivery; the separate loopback test exercised SMTP. No production recipient or alarm server was contacted. Native DSM installation and parser acceptance remain [target checks](NAS-ACCEPTANCE.md#additional-coverage-not-a-reopening-of-accepted-checks).

## Build 0032 HPE SmartStorage discovery and alarm dependencies (20 October 2026)

An authorized live read-only comparison exposed a discovery gap in the earlier iLO result: the standard Storage view contained two empty embedded SATA controllers, while HPE SmartStorage separately exposed an E208i-p, a RAID-1 logical drive and two SAS disks. The old walker omitted `Links.PhysicalDrives` and `Links.DataDrives`; a disk reporting Critical/Failed was therefore missing from the snapshot despite all discovered resources being available. The logical drive reported Warning/Recovering. Successful coverage of discovered resources is not proof of exhaustive OEM coverage.

Build 0032 follows the advertised physical/data-drive, enclosure and unconfigured-drive inventories. The discovery and dependency graph share an explicit inventory-only HPE link allowlist. HPE SmartStorage, array controllers and logical drives can be grouped to known faulty descendants; independent conditions, contradictory own-health/rollup data and unexplained faults retain the existing safeguards. Reciprocal System/Chassis associations project only the system's HPE storage dependency to the chassis, without adding a reverse System edge or guessing from URI prefixes. Disk labels include the reported position.

The corrected Rust collector completed an authorized live poll in 5.484 seconds: 51 resources available, complete log coverage (290 entries), physical disk `1I:1:1` Critical and disk `1I:1:2` OK. All five linked System/Chassis/SmartStorage/controller/logical-drive summaries grouped to the critical disk. Exact certificate pinning preceded credentials; temporary local state had delivery disabled and was removed afterward. Hardware configuration and production package state were not changed.

Local checks passed: 96 Rust tests, 38 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. The HPE fixture and HTTPS integration test cover the real advertised link structure, physical discovery through either controller or logical-drive membership, both delivery queues, derived summary assessment, independent controller faults, new faults after acknowledgement, missing associations and legacy snapshots. Package integration and checksum results are recorded with the build artifacts. NAS installation and native UI acceptance remain pending; see [NAS acceptance](NAS-ACCEPTANCE.md#additional-coverage-not-a-reopening-of-accepted-checks).

These records apply to the tested systems. Earlier build sections below describe the evidence and outstanding checks at that stage of development; their historical limitations do not replace this current compatibility status. Model/firmware details are maintained in [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

## Build 0031 optional data deletion on uninstall

Package assembly now includes German/English uninstall wizard generators and an opt-in `postuninst` cleanup hook. The checkbox starts unchecked; no selection preserves the existing configuration. The generator selects the native JSON form before DSM 7.2.2 and a Vue 2 JSONP form from 7.2.2 onward, using DSM's trusted version metadata. The hook requires an actual `UNINSTALL`, the expected package identity and the exact `true` choice. It clears only the contents of the validated persistent package configuration directory, including upgrade snapshots and keys, without following nested symlinks or requesting root privileges.

Local source checks passed: 19 packaging/release tests (including ten new uninstall tests) and 38 frontend tests. Uninstall checks cover retention, explicit deletion, upgrade/status guards, invalid inputs, version selection, both localized wizard formats, checkbox changes/reset, hidden files and SQLite sidecars, volume/system configuration layouts, unrelated files, external/dangling symlinks, repeated cleanup and reported deletion failures. SPK validation repeats the uninstall checks against scripts extracted from the built archive. See [uninstall behavior](UNINSTALL.md) and the [pending NAS checks](NAS-ACCEPTANCE.md#additional-coverage-not-a-reopening-of-accepted-checks). No NAS installation, uninstallation or live data deletion was performed; native rendering, choice propagation and lifecycle timing remain pending target acceptance.

## Build 0030 iDRAC9 empty S140 controller

The user supplied a screenshot showing four S140 rows (three Not applicable, one Unknown), plus an OK H330, and identified the unexplained row as `/redfish/v1/Systems/System.Embedded.1/Storage/RAID.Embedded.1-1/Controllers/RAID.Embedded.1-1`. Source inspection found that empty-inventory applicability followed legacy embedded StorageControllers only, although collection already discovered the modern Controllers resources. A synthetic regression with that exact reported URI, four S140 representations and an OK H330 reproduced three exclusions and Unknown overall health before the fix. After following the explicit Controllers collection membership, all four S140 representations are neutral and overall health is OK. These are separate Redfish representations; the fix does not deduplicate rows by name or change persistent alarm keys.

Regression checks also cover missing/unread volumes, inconsistent and paginated inventory, missing collection membership, unrelated controllers, attached drives/volumes advertised through Links, unavailable and fault-reporting controllers, shared controllers with a populated owner, and embedded legacy controllers lacking an odata ID. Existing retained-fault tests continue to verify that neutral Unknown observations cannot establish recovery. The change is evaluated anew on each poll as inventory changes. No production controller or NAS state was accessed or changed during this correction; another poll after installing the update is required for target verification.

Local validation passed: 91 Rust tests, 38 frontend tests, nine packaging/release tests, Clippy with warnings denied, formatting, and the static package Redfish/CGI, pinned legacy TLS and SMTP/queue integration suites. DSM 7 SPK validation and staged checksums passed. A redacted Gitleaks scan of 117 tracked/non-ignored source/document candidates found zero secrets; ignored build/runtime/credential files were excluded. The new local development package is `dist/storage-0030/HardwareMonitor-0.8.0-0030-x86_64-dsm7-development.spk`, SHA-256 `fc757df9e35d8bdf3e34f290272f87694180a1929763634150c6ed672295bfa2`. Prior packages are retained. Installation and the resulting live iDRAC9/NAS status remain to be confirmed by the user.

## Build 0029 acknowledgement across power-on

The user reported PS1 acknowledgement at 18:12:56 while the server was off, followed by automatic invalidation at 18:15:08 on power-on with `Fehlermerkmale geändert`. This identifies the metadata-comparison invalidation path, rather than a confirmed recovery or a resource-alias transition. The exact changing field was not supplied.

A regression test reproduced the loss using the existing sanitized Dell R340 hierarchy: a migrated retained Critical PSU state with an empty comparison baseline, an off snapshot reporting Unknown PSU health, operator acknowledgement, then a powered-on Critical snapshot with usable identity metadata. It failed on build 0028 and passes after the fix. First available metadata is learned instead of treated as a contradiction. Known usable identities/condition details survive missing metadata while a fault remains open. Tests also cover repeated off/on transitions, placeholder serials, later genuine serial changes and new distinguishable conditions; actor/reason/version and both suppressed delivery queues remain intact during baseline enrichment. No production controller or NAS state was changed during this correction.

Local validation passed: 87 Rust tests, Clippy with warnings denied, formatting, nine packaging/release tests, the static package Redfish/CGI, legacy TLS and SMTP/queue integration suites, and DSM 7 SPK validation. A redacted Gitleaks scan of 118 tracked/non-ignored source/document files found zero secrets. The corrected local package is `dist/acknowledgement-0029/HardwareMonitor-0.8.0-0029-x86_64-dsm7-development.spk`. Its checksums were verified. Installation and another physical off/on test on the NAS remain to be performed by the user; already revoked acknowledgements require deliberate re-acknowledgement after upgrade.

## Build 0028 operator acknowledgement

Local checks passed: 84 Rust tests, 38 frontend tests, nine packaging/release tests, formatting, Clippy with warnings denied, and production UI compilation. New tests cover the acknowledgement lifecycle, both queue cancellations, mixed-severity summary assessment, retained unknown readings, condition changes, stale actions, submission-gate serialization, aliases, retarget/delete, event clearing and backup formats 1/2/3 with acknowledgement review and invalid-import rollback. Rust development checks used system OpenSSL; the static DSM package build used the pinned vendored OpenSSL dependency.

The statically linked x86-64 build passed the existing Redfish/CGI, pinned legacy TLS, SMTP/queue integration suites and SPK validation. The locally built package is `dist/acknowledgement-0028/HardwareMonitor-0.8.0-0028-x86_64-dsm7-development.spk`; staged package/manifest checksums were verified. This is a local development build from the working tree, not a published release or an installation on a NAS.

A browser check with synthetic read-only data covered the acknowledgement reason dialog, blue component/system states with raw Critical health retained, derived summary details, and open/acknowledged filters. Positive backend writes and authorization were exercised in Rust tests, not through a native DSM session. A redacted Gitleaks scan of 118 tracked/non-ignored source/document candidates found zero secrets; ignored build/runtime/credential files were excluded. Screenshot and detailed build/test/audit logs are local ignored `.build/ack*` artifacts.

Real NAS installation, actual notification delivery and the faulty-mainboard fan-sensor scenario remain target acceptance work for this build. New hardware-log entries remain independent of component-state acknowledgement. See [Acknowledgement rules](ALARM-ACKNOWLEDGEMENT.md).

## Build 0027 iLO session paths and response diagnostics

Independent testing of an authorized HPE ProLiant DL160 Gen10 / iLO 5 v3.22 established Redfish 1.20.0, successful read-only session login (HTTP 201), and HTTP 200 for Systems, Chassis, Managers and server details. The exact supplied certificate was matched before sending credentials. Standard certificate validation correctly rejected the incomplete issuer chain; its SAN contains the controller DNS name rather than the IP address. No controller configuration was changed.

The original Hardware Monitor pinned probe returned `connection_response_invalid` because the advertised session collection and returned session URL have trailing slashes. That code lacked a specific translated message. Build 0027 accepts a single optional final slash for validation while preserving the exact request path and all existing origin/session-ownership constraints. Invalid-response, response-size and HTTP errors now have specific German/English text. The compatibility-mode label includes iLO without changing the saved profile identifier.

One early regular poll also failed during authentication with a transport error; a subsequent run succeeded. The pinned transport now opens fresh verified connections for authentication writes instead of risking a write on an idle stream. No POST is automatically retried. GET reuse and safe reconnects remain available. Regression fixtures cover servers that reject authentication writes on reused streams, all collection/resource trailing-slash combinations on Standard and pinned transports, correct owned-session logout, mismatched collections, unsafe session IDs and translated diagnostics.

With the final corrected Rust client, the live probe checked all three collections in 1.423 seconds. Two successive full polls completed in 6.582 and 6.573 seconds; each retrieved 42 available resources, 113 observations including coverage records and 421 hardware-log entries, with complete log coverage and no query errors. The controller's hardware states included five Warning and 28 Unknown observations; successful collection does not turn those states into OK. Local test state was temporary and notification delivery disabled. The 67 Rust and 34 frontend tests, formatting and Clippy passed. NAS installation remains to be confirmed.

## Build 0026 DSM 7 packaging scope

Only the DSM 7 x86_64 SPK remains in the maintained build/release set. The legacy INFO/resource/lifecycle files and launcher configuration are removed. Package assembly rejects the retired profile and checks the DSM 7 minimum version, desktop launcher and icon. Release tests cover the three-file asset set, rejection of a retired package in new assets, and cleanup of previously managed package assets only after a successful replacement upload. These release tests use a fake client; no GitHub assets are changed by local checks. The README and active documentation no longer list the former DS220+ target.

The 66 Rust, 34 frontend and nine packaging/release tests passed, along with formatting and Clippy. The earlier combined patch was created before these changes and verified by applying it to its exact base and comparing every resulting tracked file with build 0025.

## Build 0025 query notification selection

Regression checks cover query warning/critical alarms with hardware severity disabled, query exclusion while hardware severity stays enabled, query repeat/recovery switches, exact legacy settings behavior and serialization, both delivery queues, local history retention, restart persistence, and the actual Vue checkbox with saved and legacy choices. This change does not alter collection or controller access.

The 66 Rust and 34 frontend tests passed, as did formatting and Clippy. The new queue regression uses isolated local state and verifies SMTP and desktop job selection without contacting external recipients. No live controller access was needed for this notification-only change; actual NAS acceptance of the new checkbox remains pending.

## Build 0024 applicability

Regression checks cover explicitly disabled functions, preservation of Warning/Critical states, positive evidence for empty controllers and their explicitly linked representations, inconsistent or paginated inventories, unavailable controllers, and PowerControl measurements without health status. Frontend checks cover overall health, neutral reason labels, old snapshots, unsupported reason codes, retained faults, stale data and incomplete coverage. A storage regression confirms that a neutral unknown cannot clear an earlier critical alarm.

The authorized certificate-pinned iDRAC8 2.86.86.86 test with the actual updated Rust collector completed in 70.686 seconds: 116 available resources, 158 observations including coverage, 2939 log entries, complete log coverage and no query failures. The hardware observations contained 37 OK states and four unknowns, all explained by applicability: a status-free PowerControl measurement, Disabled power-supply redundancy, and the empty S130 Storage/StorageController representations. The production frontend overall calculation returned OK with no remaining unexplained unknowns. Temporary local test state was removed. This establishes live collection and calculation; the user subsequently confirmed testing on the PowerEdge R330 with iDRAC8. The 63 Rust, 33 frontend and seven release unit tests passed; formatting and Clippy passed.

## Build 0023 older iDRAC authentication and timing

The user confirmed partial readings on 0022, with a 90-second deadline at an iDRAC7 voltage sensor, and reported the same deadline on iDRAC8 RAID/log resources. The older `/Managers/.../Logs/Lclog` spelling was not recognized by the log-priority classifier; it is now included alongside LogServices paths.

An authorized, certificate-pinned iDRAC8 2.86.86.86 diagnosis compared repeated Basic authentication with one temporary Redfish session. Early Basic reads took roughly 5–10 seconds each. A token-based diagnostic completed 53 hardware resources in about 47 seconds and the whole 114-resource graph in about 117 seconds, including login/logout overhead. The actual corrected Rust collector then completed 114 resources, 156 observations including coverage records, and 2864 hardware-log entries in 78.809 seconds, with every capability available, complete log coverage and an OK collector result. Temporary local test state was removed. Credentials, tokens, raw logs and private diagnostic helpers are excluded from source/package artifacts. This verified that live collection. At that stage, NAS installation of 0023 and complete iDRAC7 collection were still awaiting confirmation; the current confirmed systems are listed above.

Tests cover session login/logout on Standard and pinned transports, token-only subsequent reads, unsupported-session fallback, rejected session POST redirects, unsafe logout locations never becoming hardware DELETE requests, cancellation cleanup, token/credential output exclusion, endpoint confinement and profile-aware freshness. The iDRAC7/8 profile now permits 300 seconds; Standard remains at 90 seconds. Other scan limits and non-overlapping scheduling remain unchanged.

## Build 0022 bounded partial polling and diagnostics

The user confirmed that the 0021 probe reaches all three protected collections, but no complete snapshot newer than 09:03:08 was saved and the generic collector alarm was reconfirmed at 09:39:06. The old message does not establish the failing resource or cause. At that stage, authenticated live collection had not yet been verified by the agent.

The collector previously discarded every reading if any later JSON response was invalid or the 90-second, 256-resource, 16-MiB or 4096-item budgets were reached. The new regression reproduces the discarded poll against the 0021 static binary. Build 0022 gives hardware reads priority over LogServices reads and retains already validated resources on these bounded aborts. Invalid child responses are isolated; root failure, authentication rejection and certificate mismatch/expiry remain fatal. Incomplete results have explicit coverage and collector warnings, never a successful collector status. Limits are unchanged. Hardware-log initialization remains incomplete until a complete scan, so partial initial scans do not replay historical alarms.

The DHE fixture now checks malformed log JSON, a 4097-entry expanded log page, a linked log collection exceeding 256 resources, and an actual 90-second full-poll deadline. Each case must preserve the temperature reading, save a current partial snapshot, retain the incomplete-log flag and expose a classified reason/path. Fatal pin failure is recorded in the active collector alarm with a safe URI and reason. Query strings, raw response bodies and arbitrary internal error strings are excluded from these diagnostics. Unit tests also verify redaction and English rendering.

## Build 0021 iDRAC7 polling correction

The user installed 0020 on the RS2416RP+ / DSM 7.3.2-86009 Update 4. The probe reached the public Redfish root but polling recorded transport errors for Systems, Chassis and Managers. A read-only anonymous reproduction with the old pinned transport returned the root and some HTTP 401 collection responses after roughly four seconds per fresh TLS connection, then hit the ten-second request timeout on another collection. A separate HTTP/1.1 keep-alive comparison returned subsequent root/collection responses within a fraction of a second after the initial handshake. This supports repeated handshake overhead as a contributor; it does not prove authenticated hardware coverage.

The pinned client now reuses its verified connection, discards it on request cancellation/failure, and permits one verified reconnect for an idle disconnect. The DHE-only integration fixture now has a public root, three protected collections and a complete seven-resource graph including a temperature reading. It checks rejected credentials behind the public root, successful probe access to all three collections, a full poll with real measurements using one TLS connection, explicit and silent disconnects, and a certificate change on reconnect rejected before HTTP/auth. Existing wrong/reissued certificate, validity, protocol, redirect and response-size checks remain. The corrected transport also reached the real service root in about eight seconds, then all three protected collections returned anonymous HTTP 401 in 7–26 milliseconds over that same connection. At that stage, live authenticated monitoring and NAS acceptance of 0021 were still awaiting confirmation. See the current confirmed systems above.

## Build 0020 iDRAC7 compatibility

The new mode has 55 Rust unit tests and 29 frontend tests, including rendering the actual device editor. Tests cover exact leaf matching, validity dates, deliberate enrollment, endpoint-bound pin retention, old configurations defaulting to Standard and encrypted backup/restore preserving the pin while pausing devices. The dedicated loopback suite uses a DHE-only TLS 1.2 server and self-signed CA:TRUE certificates without SANs. It verifies rejection before HTTP/auth for a wrong certificate, a reissued certificate sharing the same key, expiry and TLS 1.1; safe redirects, response limits and normal polling are exercised. Both this suite and existing Redfish/SMTP integration checks are mandatory in the static package pipeline.

An anonymous, read-only service-root GET using the new transport against a user-provided Dell R420 / iDRAC7 2.63.60.62 returned HTTP 200 and Redfish 1.0.2 with the exact provided certificate. No device credentials were supplied, and no controller settings were changed. This established TLS/pin interoperability only; authenticated monitoring, hardware-resource coverage and installation of build 0020 on the user's NAS were still awaiting acceptance at that stage.

## Local checks

Rust tests cover health normalization, URI restrictions, unavailable readings, event transitions, preserved faults, PSU identity, explicit relationship grouping, multi-cause/partial recovery, queue progress/cancellation, credential encryption, additive database changes, session/role/origin/CSRF checks, backup atomicity, CSV formula protection and monotonic event IDs.

Language checks cover English event rendering and both saved channel languages, old messages and vendor text staying intact, localized default mail tokens/templates, old settings defaulting to German, language selection/date formatting, translation-key coverage and positional placeholder parity. App backup format 2 includes event context; the reader migrates format-1 event rows from build 0016. Invalid passwords/ciphertext and invalid restored application records fail without replacing the live data.

HTTPS integration runs the real collector, database, daemon and CGI against synthetic loopback resources. It checks TLS trust/name failures, safe redirects, pagination, partial coverage, log baselines, service lifecycle, unauthorized access and reduced diagnostics. A backup request above the ordinary form limit is forwarded, while oversized ordinary forms remain rejected.

SMTP integration uses loopback servers for explicit plaintext, STARTTLS, implicit TLS, credentials, certificate/name failures, no downgrade, durable recipient progress and restart. A synthetic Redfish fault yields one component email, one retained-fault reminder and one recovery after grouping. No real email or desktop notification is sent by these tests.

Package checks inspect the current DSM 7 x86_64 SPK, then execute the extracted static binary locally. They validate archive structure, privileges, empty optional resources, lifecycle, CGI denial, versioned routes/assets, notification texts and new UI actions. They do not simulate DSM's installer, native language renderer or kernel.

## User-confirmed NAS behavior

RS2421RP+ / DSM 7.4.1-90080: package install/run/menu, the internal DSM window, positive sign-in after the cache/session fixes, device CRUD including certificate/address/password changes, Dell R340 readings, PS1 critical state, Gmail test email and automatic reminder email. The user also confirms desktop test and critical reminder with a red error indication and resolved device/message details. Backup and restore from build 0016 have been tested by the user. The user also confirms successful installation of the grouped DSM 7 x86_64 build 0018.

The English additions, new forced-language desktop keys and backup-format migration from build 0017, plus normal operation of grouped build 0018 beyond installation, still need NAS acceptance. No claim is made that local screenshots prove native DSM delivery. Fixtures/screenshots used for UI checks are synthetic. The original server access was read-only; the agent did not change hardware, NAS settings or real alarm delivery.

## Remaining hardware/operational limits

Dell PowerEdge R420/iDRAC7, R330/iDRAC8 and R340/iDRAC9 have been tested as described above. Read-only HPE DL160 Gen10/iLO 5 v3.22 collection is verified in build 0027. Other HPE model/license combinations and simultaneous physical fault scenarios remain unverified. Unknown/null/offline data is deliberately not classified as healthy. No complete RAID/OEM coverage, resource budget, prolonged reliability result or production security audit is claimed. See [Roadmap](ROADMAP.md), [NAS acceptance](NAS-ACCEPTANCE.md) and [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

## Build 0018 release automation

The publisher is exercised with a fake GitHub client: first publish, replacement, source-tag movement, managed-only cleanup, stale commits, immutable releases, checksum/commit mismatch and interrupted uploads. It does not call a live repository during these tests. A hosted Actions run and actual release update remain unverified until the project is pushed to GitHub. The source repository currently has no remote. README screenshots use the production frontend against the read-only synthetic fixture.


## Build 0040: larger encrypted app backups

The 0.8.0 master-based change raises the logical archive limit to 128 MiB and the
file limit to 192 MiB, updates both language catalogs and the upload picker, and
derives the CGI response bound from the archive file bound. The encrypted format
remains 4; the existing legacy-format migration tests still pass.

Local checks on 26 October 2026: 130 Rust tests, 45 frontend tests and 19 Python
tests pass; rustfmt, Clippy for normal and local-dev features, the Vue production
build and the generic x86-64 static musl release build pass. The new regression
exports, authenticates, decrypts and restores approximately 26 MiB of retained
history without losing its contents; the Base64 file exceeds the old 32 MiB CGI
response bound as well as the old 16/24 MiB archive bounds. A separate debug-test
process peaked at 215,152 KiB RSS in 10.61 seconds; this measures that synthetic
fixture only, not maximum-size archives or NAS performance.

The CGI integration regression now forwards a 33 MiB upload and checks an intact
33 MiB download while retaining rejection of ordinary forms over 128 KiB. These
socket-based checks could not run in this restricted environment: TCP socket
creation and Unix socket binding both return EPERM. Package lifecycle verification
and target NAS upload/download acceptance therefore remain pending.


## Build 0041: exact backup sizing and safe rejection details

The build-0040 128/192 MiB bounds remain unchanged. Archive collection now counts
the actual serialized JSON, including null/type wrappers, UTF-8, escapes, array
and table separators, archive metadata, and converted credentials/certificates.
The former per-cell estimate could reject an archive whose JSON fits the bound.
A regression demonstrates this with small records, accepts the exact byte limit
and rejects one byte less. Existing cross-key, legacy-format and large-history
restore tests pass. Serialization also counts bytes before allocating plaintext
for a rejected oversized archive. This remains an in-memory format-4 archive,
not the proposed streaming redesign.

Export-size failures now expose only byte counts, the fixed schema table where
collection stopped, and a fixed phase code. These are lower-bound counts at the
point of rejection; the table is not necessarily the largest contributor. The
API test checks German/English messages and that private error context is never
returned. No database records, paths, device identities or secrets are included.
The actual NAS dataset has not been examined, so the cause of the reported
build-0040 failure remains unconfirmed until the new diagnostic is available.

Local validation: all 132 Rust tests, all 45 frontend tests, 19 Python tests,
rustfmt, Clippy with normal/local-dev features, production Vue build and static
generic x86-64 musl build pass. Socket-based CGI/TLS and native service lifecycle
checks remain blocked by this execution environment's socket restrictions;
NAS acceptance remains pending.


## Build 0042: configurable retention and large file-backed archives

Implemented on the master branch before the SNMP merge; webhook work is excluded. Event and hardware-log retention are separate (90-day defaults, 0 unlimited), with persistent daily scheduling, a first-run/restore review window of 24 hours, and a manual counted preview/confirmation. Hardware-log reading is configurable per device (disabled/all/newest N), independently of storage retention. The fixed 10,000-entry audit cap is documented and visible.

New backups use an online SQLite snapshot, gzip, sequenced individually authenticated AES-GCM blocks, private disk staging, background progress/cancellation, raw file download and checked 512 KiB upload slices. There is no configured overall archive-size cap. Existing encrypted JSON formats 1–4 remain readable. Final restore validates and commits atomically, rekeys credentials and pauses imported monitoring/delivery.

Local checks passed: **147 Rust tests with local-dev enabled**, **48 frontend tests**, **19 Python tool tests**, formatting, Clippy with warnings denied both with/without local-dev, Vue compilation and the generic x86-64 static musl production build. Tests cover independent policies, timestamp edge cases, retained pending automatic/manual submissions, active alarms, snapshot pruning, policy-change interruption and safe baseline renewal when widening hardware retention, persisted daily deadlines, session-bound jobs, upload offsets/retransmission/sealing, cancellation/shutdown/expiry/orphans, consistent snapshots under concurrent writes, old archives, wrong passwords, corruption/truncation/trailing data, reordered/dropped/duplicated authenticated frames, missing final markers, fail-closed readers, a real `SQLITE_FULL` restore rollback, and responsive status/cancellation while the application store is held during restore.

The explicitly selected release-mode large test also passed: **1,800,000 distinct hardware-log rows**, a **2,643,951,616-byte SQLite database** and **2,376,001,980 bytes of logical archive records**, exported, inspected and restored under a different local vault key. Exact history counts, credential re-encryption, restored retention and paused devices were checked. Runtime was 90.45 seconds on this development host; `/usr/bin/time -v` measured **23,720 KiB peak RSS (23.2 MiB)** for the test process, excluding compilation. The final encrypted file was 34,353,208 bytes because this synthetic fixture has repetitive messages; its compression ratio and timing do not predict NAS performance. The test is ignored in the default suite and documented for explicit reruns with adequate disk space.

The installable candidate is `dist/maintenance-0042/HardwareMonitor-0.8.0-0042-x86_64-dsm7-development.spk`. Local socket creation is prohibited (`PermissionError: [Errno 1] Operation not permitted`), so the Redfish/TLS, legacy TLS, SMTP, native CGI transfer and service-lifecycle integration suites cannot complete here. Their test paths remain in the normal unrestricted CI pipeline, including new device selection, raw download and chunk upload checks. These are environment-blocked checks, not passing evidence. Native DSM installation/download/upload and production-data acceptance remain open; see [NAS acceptance](NAS-ACCEPTANCE.md#additional-coverage-not-a-reopening-of-accepted-checks). No real NAS, device, production database or recipient was changed during this implementation.


## Build 0043: native download authentication and attachment preflight

The user reported that downloading a ready build-0042 archive offered `api.html` and then failed. The previous UI used a plain link without the DSM token, unlike its working authenticated API requests. The native GET also parsed everything after `download=` as the job ID, so appending DSM's token required a proper query parser as well.

The corrected flow waits for an explicit download click, obtains the current DSM session token, and makes an authenticated HEAD request. Only a successful binary attachment response starts native browser navigation. HTML login/error pages, JSON responses, missing attachment headers and empty files are rejected in the app with an HTTP status. Navigation adds the documented SynoToken parameter, has an explicit `.hmbackup` filename and no-referrer policy, and does not buffer the archive in JavaScript. Normal API/preflight requests retain header-based tokens. The CGI strictly decodes read-only download parameters, rejects duplicates/unknown fields and conflicting tokens, preserves the cookie, and forwards the token to the fixed native helper. HEAD has GET authentication semantics while both bridge stages omit the body. Administrator and original job-session checks remain enforced.

Validation passed: **148 library tests plus two native bridge tests (150 Rust tests total with local-dev enabled)**, **53 frontend tests**, **19 Python tool tests**, formatting, Clippy with warnings denied with and without local-dev, Vue compilation and the static generic x86-64 musl production build. New tests cover encoded/empty-header token transport, rejected malformed/duplicate parameters and write use, HEAD owner/role checks, HTML/JSON/expired-session rejection, no whole-file buffering, explicit filenames and temporary-link removal. In-memory async transport tests exercise the production bridge helpers: exact 300,000-byte GET transfer, 8-GiB sparse-file HEAD metadata with no body, and truncated-stream failure.

Full loopback/CGI/service integration remains blocked by socket-bind permission (`EPERM`) in this execution environment. The unrestricted integration scripts include actual HEAD/raw-GET requests and query-token forwarding. The new native DSM download still requires target acceptance. The candidate is `dist/download-0043/HardwareMonitor-0.8.0-0043-x86_64-dsm7-development.spk`; existing archive contents/format and retention behavior are unchanged by this fix.
