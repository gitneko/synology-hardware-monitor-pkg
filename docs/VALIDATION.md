# Validation and evidence boundaries

Reviewed for 0.8.0-0018 on 18 October 2026. Build 0017 passed 50 Rust and 27 frontend tests. Build 0018 changes packaging/CI/documentation and adds seven isolated release-publication tests. Current package hashes and source identity are recorded in `dist/current/latest-assets/build-manifest.json` and `SHA256SUMS`; test output is retained in Actions logs. Source archives intentionally exclude `dist` and private runtime state.

## Local checks

Rust tests cover health normalization, URI restrictions, unavailable readings, event transitions, preserved faults, PSU identity, explicit relationship grouping, multi-cause/partial recovery, queue progress/cancellation, credential encryption, additive database changes, session/role/origin/CSRF checks, backup atomicity, CSV formula protection and monotonic event IDs.

Language checks cover English event rendering and both saved channel languages, old messages and vendor text staying intact, localized default mail tokens/templates, old settings defaulting to German, language selection/date formatting, translation-key coverage and positional placeholder parity. App backup format 2 includes event context; the reader migrates format-1 event rows from build 0016. Invalid passwords/ciphertext and invalid restored application records fail without replacing the live data.

HTTPS integration runs the real collector, database, daemon and CGI against synthetic loopback resources. It checks TLS trust/name failures, safe redirects, pagination, partial coverage, log baselines, service lifecycle, unauthorized access and reduced diagnostics. A backup request above the ordinary form limit is forwarded, while oversized ordinary forms remain rejected.

SMTP integration uses loopback servers for explicit plaintext, STARTTLS, implicit TLS, credentials, certificate/name failures, no downgrade, durable recipient progress and restart. A synthetic Redfish fault yields one component email, one retained-fault reminder and one recovery after grouping. No real email or desktop notification is sent by these tests.

Package checks inspect both current SPKs (DSM 7 x86_64 and DSM 6 geminilake), then execute the extracted static binary locally. They validate archive structure, privileges, empty optional resources, lifecycle, CGI denial, versioned routes/assets, notification texts and new UI actions. They do not simulate DSM's installer, native language renderer or kernel.

## User-confirmed NAS behavior

RS2421RP+ / DSM 7.4.1-90080: package install/run/menu, the internal DSM window, positive sign-in after the cache/session fixes, device CRUD including certificate/address/password changes, Dell R340 readings, PS1 critical state, Gmail test email and automatic reminder email. The user also confirms desktop test and critical reminder with a red error indication and resolved device/message details. Backup and restore from build 0016 have been tested by the user. The user also confirms successful installation of the grouped DSM 7 x86_64 build 0018.

The English additions, new forced-language desktop keys and backup-format migration from build 0017, plus normal operation of grouped build 0018 beyond installation, still need NAS acceptance. No claim is made that local screenshots prove native DSM delivery. Fixtures/screenshots used for UI checks are synthetic. The original server access was read-only; the agent did not change hardware, NAS settings or real alarm delivery.

## Remaining hardware/operational limits

Live evidence is currently concentrated on Dell R340/iDRAC9. HPE iLO 5, iDRAC7, DSM 6 and simultaneous physical faults remain unverified. Unknown/null/offline data is deliberately not classified as healthy. No complete RAID/OEM coverage, resource budget, prolonged reliability result or production security audit is claimed. See [Roadmap](ROADMAP.md), [NAS acceptance](NAS-ACCEPTANCE.md) and [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

## Build 0018 release automation

The publisher is exercised with a fake GitHub client: first publish, replacement, source-tag movement, managed-only cleanup, stale commits, immutable releases, checksum/commit mismatch and interrupted uploads. It does not call a live repository during these tests. A hosted Actions run and actual release update remain unverified until the project is pushed to GitHub. The source repository currently has no remote. README screenshots use the production frontend against the read-only synthetic fixture.
