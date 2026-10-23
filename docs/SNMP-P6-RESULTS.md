# SNMP P6 — 0.9.0 package and release validation

P6 aligns the local development release to **0.9.0-0050** on 21 October 2026.
Executable/Cargo and frontend/package-lock versions are **0.9.0**; DSM INFO,
versioned HTML/launcher, Vite UI build identity and staged manifest are
**0.9.0-0050**. Build 0050 follows baseline 0034 and was unused in the local
release artifacts. This is an unsigned local development package from the
existing `snmp` working tree. It is not a published GitHub release or a confirmed
NAS installation. [P7 real-device acceptance](SNMP-IMPLEMENTATION-PLAN.md#12-verification-and-release-acceptance)
remains outstanding. See [0.9.0 release notes](RELEASE-NOTES-0.9.0.md).

## Package and pipeline

`tools/snmp_integration_test.py` composes the actual-product P2/P3/P4 reference
suites. It requires Net-SNMP/OpenSSL, checks the binary against the product version,
optionally requires a static x86-64 ELF and records normalized suite results plus
binary SHA-256. It uses private temporary loopback agents/HTTPS/SMTP services,
never an actual NAS/controller or notification recipient. P0 still separately
checks published-crate provenance, both local patches, USM state/timeliness,
malformed frames and a seeded 1000-packet mutational/truncated/random decoder regression corpus. Two product unit corpora separately exercise bounded envelope handling and typed profile normalization; they do not claim exhaustive fuzz coverage.

`tools/build_packages.py` now requires this harness against the **actual static
musl executable**, including both **60-second** receiver/alarm load scenarios,
before assembling a package. Existing Redfish/CGI, pinned legacy TLS and SMTP
regressions remain mandatory. Reference tooling, test credentials and fixtures
are not installed on the NAS. Dependency notices are regenerated for the locked
static dependencies, Vue runtime and musl.

The build refuses mixed executable/Cargo-lock/frontend-lock/INFO versions and a
stale binary or stale UI asset set. `tools/check_spk.py` executes the extracted
product/CGI/lifecycle, checks versioned entrypoints and SNMP settings/provenance UI,
and verifies a fresh schema-2 state has **receiver disabled**, default UDP 1162
and no SNMP credential records. Static x86-64/no interpreter/no dynamic libraries,
regular CGI entrypoint denial, uninstall guards, least-privileged DSM resources
and absence of raw MIBs, private runtime files/reference tooling are checked.
No root/systemd/optional DSM resources were added.

The manifest retains the Git base commit and additionally records
`source_dirty` and a content/mode hash of tracked and non-ignored Git source paths
(including missing tracked files). Sources must remain unchanged throughout the
build/inspection; regenerated notices must be reviewed first if they differ.
Source archives without Git record unknown source identity rather than inventing
a commit. A dirty local package cannot be published by `publish_latest.py` as an
unchanged source commit. The local artifact is expected to be dirty while P0–P6
remain uncommitted; this does not prohibit local package review/acceptance.

CI installs explicit Net-SNMP prerequisites. Core checks run P0 source/security
regressions plus the native product integration; the package job runs the static
suites and both load tests. Normalized native/static reference JSON is retained
as separate Actions artifacts, and the aggregate static result/binary hash is
included in the checked release manifest. The existing three fixed asset names,
read-only build jobs and default-branch-only publisher are retained. Workflow
syntax is checked locally; **no hosted Actions run or publication was triggered**.

## Local verification

The final P6 validation covers:

- 166 Rust unit tests and 9 integration tests; format check, Clippy with warnings
  denied and native/static product builds.
- 55 frontend tests, German/English placeholder parity, locked npm installation
  and production Vite build with the new UI identity.
- 23 Python build/release/uninstall tests, including mixed-version rejection and
  rejection of dirty local publication before any GitHub operation.
- P0: 5 harness unit tests and 20 independent reference cases, including malformed
  input, authenticated multi-sender routing, security levels, long silence,
  restart/changed engine and replay/clock handling.
- Native product: P2 four polling configurations (v1/v2c/v3 SHA-1/v3 SHA-256), P3
  seven receiver/enrollment cases and P4 five alarm/SMTP cases.
- Static product: the same suites plus one 60-second load case each in P3 and P4,
  including an unknown-source burst, malformed/plausible bad-HMAC traffic,
  continuing polls/API and real local SMTP submission counts. Detailed timings,
  memory/CPU samples and case lists are retained in the manifest/reference JSON;
  they do not establish maximum-device sizing or positive DSM authentication.
- Finished SPK inspection, extracted lifecycle/CGI tests, byte-identical staged
  package, manifest checksums, and generated dependency license notices.
- A redacted Gitleaks scan of changed/non-ignored existing source/document files, including retained vendor files, finds no real secret. The six classified findings are four byte-verified source hashes and two public RFC 3414 known-answer vectors. Private runtime/fixture/build state remains excluded.
- Current OSV exact-version audit of 237 public Rust versions and npm audit report
  no known advisory. This is a dependency-database check, not a complete security
  audit or a proof that no vulnerabilities exist.

Output:

- `dist/current/HardwareMonitor-0.9.0-0050-x86_64-dsm7-development.spk`
- `dist/current/latest-assets/HardwareMonitor-dsm7-x86_64.spk`
- `dist/current/latest-assets/build-manifest.json` and `SHA256SUMS`
- `dist/current/snmp-reference*.json`; further local logs/audits in
  `.build/snmp-p6/` (ignored).

Verify the fixed assets with `sha256sum --check SHA256SUMS` inside `latest-assets`.
The manifest binds its static reference evidence to the packaged executable hash;
checksums identify these bytes, not a signature or full reproducible compilation.
No private controller response, runtime key/database or fixture state is a release
candidate. The final redacted password/key audit and artifact hashes are retained
in `.build/snmp-p6/evidence.json` and associated local reports.

## Remaining gate

P7 must verify installation/coexistence with DSM SNMP/firewall, configured custom
ports, native authentication/privileges, restart/upgrade/rollback, actual vendor
payload/identity availability and safe real fault/recovery/channel behavior on
the listed NAS/controllers. P0–P6 synthetic/reference checks do not substitute
for that gate or widen the published model/firmware matrix.
