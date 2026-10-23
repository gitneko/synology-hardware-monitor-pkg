# Validation and evidence boundaries

Current package **0.9.0-0056**: see [0054 UPS results](SNMP-UPS-RESULTS.md), [0052 generic/network results](SNMP-GENERIC-NETWORK-RESULTS.md), [P6 SNMP package validation](SNMP-P6-RESULTS.md) and [release notes](RELEASE-NOTES-0.9.0.md). Source/native/static/package checks are local. The user subsequently confirmed installation of build 0.9.0-0051 and the DSM polling profile on 21 October 2026; the broader P7 NAS/controller matrix remains open. Historical results below retain their original versions and evidence limits.

## Build 0056 HPE iLO population and units (23 October 2026)

The user supplied a DL20 Gen11 / iLO 6 1.79 diagnosis and full SNMPv2c/v3 walks.
Both contain 2,041 HPE OIDs with identical OID sets. The relevant sanitized
69-row subset retains health, population, measurements, ASN.1 types and full
indices while replacing descriptive inventory and identifiers; original walks,
addresses and event logs are not shipped. This verifies the supplied capture,
not a new connection to the BMC. See the [HPE guide](SNMP-HPE.md).

The capture confirms one present and one absent PSU, three unpopulated DIMM
slots, three healthy fans with values 7/7/41, poweredOff(2) and unknown storage
without CPQIDA controller/drive rows. Source review independently confirmed that
the earlier profile omitted PSU Present. HPE's original MIB kit and official
fan-speed advisory confirm the OID-specific enums, binary KiB module sizes and
firmware boundaries. Empty storage remains unknown; power-off is context, not a
proof of why inventory is missing. No live server or NAS settings were changed.

Regression checks cover sanitized capture normalization, firmware boundaries
and ambiguous units, conflicting/malformed presence, DIMM-specific status,
and independent Net-SNMP v1/v2c/v3 replay through the actual CLI/store/alarm path.
Removal history survives separate processes; unknown presence cannot recover,
explicit reinsertion can recover, and absent hardware cannot clear an earlier
component fault. Local checks passed 188 Rust unit and 9 integration tests, 61 frontend tests,
23 Python tests, formatting and Clippy with warnings denied. Native DSM and live iLO acceptance of 0056 remain open.

## Build 0055 direct-upgrade startup correction (23 October 2026)

User-reported build-0054 behavior:

| NAS | Reported DSM version | Observation |
|---|---|---|
| RS2421RP+ | 7.4.1 | 0054 works without repair; earlier SNMP development builds had been installed, so this does not establish a clean direct upgrade. |
| RS2416RP+ | 7.3.2 | 0054 works after package repair. |
| DS220+ | 7.4.1 | 0054 fails even after repair; build 0038 works. User reports `daemon startup timeout`; the full original log is unavailable. |

Source inspection found a fixed five-second start budget covering all initial
state loading, durable schema-1 backup and migration. A controlled local test
used the exact delivered 0054 executable, actual state created by archived
0.8.0-0018 and a six-second exclusive SQLite lock. Startup failed after 5.06 s,
with schema 1 unchanged. Without contention, the direct upgrade succeeded.
This reproduces a specific failure mechanism matching the reported timeout;
it does not establish whether the NAS delay was caused by locks, storage latency,
backup size or another startup operation. No missing directory, ownership or
pre-existing-SNMP prerequisite was demonstrated. No real NAS was changed.

Build 0055 initializes private state explicitly in `postinst` before service
start/repair, allows 120 s for readiness and 30 s for database initialization
contention, reports stopped/unknown DSM status as 3/4 and improves private startup
diagnostics. The listener and shutdown handler precede PID publication; readiness
requires a connectable API socket. Only complete, synced migration backups are
published under `pre-snmp-schema1-*`; a failed temporary backup is cleaned up
without touching previous complete backups.

The same six-second delay succeeded locally with the corrected executable
(about 6.4 s). The five-case actual-product upgrade suite passed using both an
independent legacy schema-1 fixture and state created by the archived real
0.8.0-0018 executable. It covers fresh installation, direct upgrade, repeated
post-install/repair, delayed first start, transactional migration failure/retry,
DSM status codes, unchanged key/device/credential/snapshot/event/queue/settings/
acknowledgement data, a valid schema-1 rollback copy and a disabled trap listener.
The archived binary is 0018, not the user's unavailable 0038 artifact; later
legacy acknowledgement fields are seeded explicitly. These are private synthetic
fixtures with device polling and delivery disabled.

Local validation passed 183 Rust unit and 9 integration tests, 59 frontend tests,
23 Python tests, formatting and Clippy with warnings denied. A new unit test
checks failed backup cleanup, matching key/database copies, private permissions,
preservation of previous backups and retry. The package pipeline runs
`tools/upgrade_integration.py` against the static executable; SPK inspection also
executes the extracted post-install hook twice and checks readiness/lifecycle.
Its manifest records upgrade-suite results and the tested binary hash.

Native 0055 direct-upgrade/repair acceptance on DS220+/RS2416RP+ remains open.
The broader P7 hardware and documentation work remains separate.

## Build 0051 DSM installation and polling profile (21 October 2026)

The user confirmed “Build installiert. DSM Profil ist bestätigt.” This records
successful installation and DSM polling-profile operation. The target model,
DSM version, selected SNMP version/security and individual fault/recovery checks
were not supplied; no broader acceptance is inferred. See the
[DSM profile acceptance record](SNMP-SYNOLOGY-RESULTS.md#user-confirmed-dsm-acceptance-21-october-2026).

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

Local checks passed: 110 Rust tests, 43 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. The sanitized fixture and HTTPS integration cover all 28 rows alongside a real-shaped Critical SmartStorage drive. Negative cases cover contradictory presence, explicit faults/conditions, untyped measurements outside PowerControl, absent/unknown controller evidence, mixed protocols, attached inventory, null/advertised Volumes, paging and invalid counts. Retained faults and their operator acknowledgements survive an absent reading; raw Unknown does not become OK or create recovery. Native DSM installation remains a [target check](NAS-ACCEPTANCE.md#build-0034-ilo-applicability-pending-nas-acceptance).

## Build 0033 manual recorded-event email replay (20 October 2026)

The administrator-only Events action renders the selected recorded event with saved SMTP templates/language/time formatting and one selected saved recipient. A durable, actor-bound preview ID makes confirmation idempotent. Each intentional new preview/job has a new Message-ID; transient retries retain its ID and rendered content. A separate table/history preserves the original event, automatic delivery progress, hardware alarm state and acknowledgement. Automatic/manual SMTP queues alternate when both have work. Settings changes, event clearing and backup restore prevent stale work from being submitted.

Local validation passed 105 Rust tests, 42 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. New cases cover original event identity/time and literal placeholders, one recipient, preview ownership/expiry, duplicate confirmation, stable retry IDs across restart, terminal failures, SMTP-setting changes, clearing, unchanged acknowledged alarms, recovery/log/query events, administrator/CSRF/submission-gate enforcement and archive formats 1 through 4. Restore keeps submitted history but cancels queued jobs and discards previews.

The actual daemon worker passed a loopback SMTP test with automatic email disabled: one manual message reached only the selected synthetic recipient with the expected subject, literal body content and Message-ID; restarting did not resubmit it. The German/English dialog was also exercised with synthetic browser data, including recipient selection, preview, separate history and a simulated lost submission response followed by confirmation of the same ID. Both requests referred to one job. Browser fixture submission does not imply real SMTP delivery; the separate loopback test exercised SMTP. No production recipient or alarm server was contacted. Native DSM installation and parser acceptance remain [target checks](NAS-ACCEPTANCE.md#build-0033-manual-email-replay-pending-nas-acceptance).

## Build 0032 HPE SmartStorage discovery and alarm dependencies (20 October 2026)

An authorized live read-only comparison exposed a discovery gap in the earlier iLO result: the standard Storage view contained two empty embedded SATA controllers, while HPE SmartStorage separately exposed an E208i-p, a RAID-1 logical drive and two SAS disks. The old walker omitted `Links.PhysicalDrives` and `Links.DataDrives`; a disk reporting Critical/Failed was therefore missing from the snapshot despite all discovered resources being available. The logical drive reported Warning/Recovering. Successful coverage of discovered resources is not proof of exhaustive OEM coverage.

Build 0032 follows the advertised physical/data-drive, enclosure and unconfigured-drive inventories. The discovery and dependency graph share an explicit inventory-only HPE link allowlist. HPE SmartStorage, array controllers and logical drives can be grouped to known faulty descendants; independent conditions, contradictory own-health/rollup data and unexplained faults retain the existing safeguards. Reciprocal System/Chassis associations project only the system's HPE storage dependency to the chassis, without adding a reverse System edge or guessing from URI prefixes. Disk labels include the reported position.

The corrected Rust collector completed an authorized live poll in 5.484 seconds: 51 resources available, complete log coverage (290 entries), physical disk `1I:1:1` Critical and disk `1I:1:2` OK. All five linked System/Chassis/SmartStorage/controller/logical-drive summaries grouped to the critical disk. Exact certificate pinning preceded credentials; temporary local state had delivery disabled and was removed afterward. Hardware configuration and production package state were not changed.

Local checks passed: 96 Rust tests, 38 frontend tests, 19 packaging/release tests, formatting and Clippy with warnings denied. The HPE fixture and HTTPS integration test cover the real advertised link structure, physical discovery through either controller or logical-drive membership, both delivery queues, derived summary assessment, independent controller faults, new faults after acknowledgement, missing associations and legacy snapshots. Package integration and checksum results are recorded with the build artifacts. NAS installation and native UI acceptance remain pending; see [NAS acceptance](NAS-ACCEPTANCE.md#build-0032-hpe-smartstorage-pending-nas-acceptance).

These records apply to the tested systems. Earlier build sections below describe the evidence and outstanding checks at that stage of development; their historical limitations do not replace this current compatibility status. Model/firmware details are maintained in [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

## Build 0031 optional data deletion on uninstall

Package assembly now includes German/English uninstall wizard generators and an opt-in `postuninst` cleanup hook. The checkbox starts unchecked; no selection preserves the existing configuration. The generator selects the native JSON form before DSM 7.2.2 and a Vue 2 JSONP form from 7.2.2 onward, using DSM's trusted version metadata. The hook requires an actual `UNINSTALL`, the expected package identity and the exact `true` choice. It clears only the contents of the validated persistent package configuration directory, including upgrade snapshots and keys, without following nested symlinks or requesting root privileges.

Local source checks passed: 19 packaging/release tests (including ten new uninstall tests) and 38 frontend tests. Uninstall checks cover retention, explicit deletion, upgrade/status guards, invalid inputs, version selection, both localized wizard formats, checkbox changes/reset, hidden files and SQLite sidecars, volume/system configuration layouts, unrelated files, external/dangling symlinks, repeated cleanup and reported deletion failures. SPK validation repeats the uninstall checks against scripts extracted from the built archive. See [uninstall behavior](UNINSTALL.md) and the [pending NAS checks](NAS-ACCEPTANCE.md#build-0031-optional-uninstall-cleanup-pending-nas-acceptance). No NAS installation, uninstallation or live data deletion was performed; native rendering, choice propagation and lifecycle timing remain pending target acceptance.

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
