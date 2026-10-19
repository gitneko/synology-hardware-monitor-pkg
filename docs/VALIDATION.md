# Validation and evidence boundaries

Reviewed for 0.8.0-0018 on 18 October 2026. Build 0017 passed 50 Rust and 27 frontend tests. Build 0018 changes packaging/CI/documentation and adds seven isolated release-publication tests. Current package hashes and source identity are recorded in `dist/current/latest-assets/build-manifest.json` and `SHA256SUMS`; test output is retained in Actions logs. Source archives intentionally exclude `dist` and private runtime state.

## Current confirmed Dell systems (19 October 2026)

- Dell PowerEdge R420 / iDRAC7 2.63.60.62: testing confirmed by the user; hardware readings and fan/redundancy alarms were observed.
- Dell PowerEdge R330 / iDRAC8 2.86.86.86: testing confirmed by the user; the authorized build-0024 collector run completed 116 resources without query failures and the overall health calculation returned OK.
- Dell PowerEdge R340 / iDRAC9 Enterprise: previously demonstrated live discovery and user-confirmed polling, PSU fault and notification workflows.

These records apply to the tested systems. Earlier build sections below describe the evidence and outstanding checks at that stage of development; their historical limitations do not replace this current compatibility status. Model/firmware details are maintained in [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

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
