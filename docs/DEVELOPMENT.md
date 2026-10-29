# Development and package builds

Run commands from the project root. The evaluated toolchain is Rust 1.98.1, Node 26.11.1, npm 12.2.0, Python 3.14 and OpenSSL for local test certificates. Rust 1.98 is the declared minimum; older compilers are not supported. Lockfiles pin dependency versions. The development host is not a DSM kernel emulator.

## Run the complete application locally

```sh
python3 tools/dev.py
```

Open **http://127.0.0.1:18774/**. This builds the frontend and starts the native Rust backend with the `local-dev` feature. Subsequent runs use incremental builds. No DSM, SPK or application login is needed. The local developer has administrator access. Device configuration, encrypted credentials, measurements, alarms, events, SMTP settings, CSV export and backup/restore use the normal application paths. Redfish performs real HTTPS requests to configured devices with the same trust checks and credentials as on DSM.

State is kept in the git-ignored `local-state/` directory and survives restart. `Ctrl+C` stops the server. Use `python3 tools/dev.py --port 18775 --directory /path/to/private-test-state` for another instance. Node/npm, Python and the native Rust build prerequisites are required; the launcher installs locked frontend dependencies if they are missing. No musl/SPK toolchain is needed.

After changing Rust or frontend source, stop and rerun the command. If the frontend is already built, start the backend directly:

```sh
cargo run --locked --features local-dev -- dev
```

The listener binds exclusively to `127.0.0.1`; use the displayed numeric URL. It enforces exact Host, same-origin writes and package CSRF tokens. It does not expose the DSM Unix socket. The `dev` command and authentication adapter are absent from normal builds and SPKs. The normal `serve`/CGI path always requires DSM authentication, even when compiled with `local-dev`.

SMTP sends real mail when configured. DSM desktop notifications are unavailable locally. The local host does not emulate DSM authentication, permissions or package lifecycle. Use separate development data; restoring a backup imports its device and SMTP settings too.

SNMP polling and the configurable trap receiver use the same collectors, credentials, receiver supervisor and alarm store as the DSM service. Live Redfish/SNMP device credentials are still required. The local HTTP integration test checks Redfish and SNMPv1/v2c/v3 polling, receiver configuration and an independently encoded v2c trap. It requires Net-SNMP (`snmpd`, `snmpget`, `snmptrap`). Local reference tests establish protocol behavior, not native DSM or vendor-firmware acceptance.

## Privileged trap ports

See [administrative trap-port setup](TRAP-PRIVILEGED-PORTS.md) for the optional
root-run helper, update behavior and NAS evidence boundary. The service and
package installation continue to use the package identity.

## Local checks

Keep all affected Cargo lockfiles up to date when changing manifests, including
package version bumps. The SNMP reference harness is a separate workspace whose
optional `product-compat` dependency includes the product version in its own
`tools/snmp-reference/Cargo.lock`; a product version bump requires refreshing
both that file and the root `Cargo.lock`. Use Cargo to refresh the affected
lockfiles while preserving existing registry versions, then verify resolution:

```sh
cargo metadata --locked --offline --format-version 1 > /dev/null
cargo metadata --locked --offline --manifest-path tools/snmp-reference/Cargo.toml --features product-compat --format-version 1 > /dev/null
```

Omit `--offline` if dependencies are not cached, retaining `--locked`. Include
the affected lockfiles with the manifest changes. The vendored upstream lockfile
is governed by the provenance workflow below. Repository-wide agent instructions
are recorded in `AGENTS.md`.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo clippy --locked --all-targets --features local-dev -- -D warnings
cargo build --locked --features local-dev
python3 tools/local_dev_integration_test.py target/debug/hardware-monitor
cargo build --locked
npm ci --prefix web --ignore-scripts
npm run build --prefix web
node --test --test-isolation=none web/tests/*.test.mjs
python3 -m unittest discover -s tools/tests -v
python tools/integration_test.py target/debug/hardware-monitor
python tools/legacy_tls_integration_test.py target/debug/hardware-monitor
python tools/smtp_integration_test.py target/debug/hardware-monitor
python3 tools/snmp_polling_integration.py target/debug/hardware-monitor --report .build/snmp-polling/reference-native.json
python3 tools/snmp_receiver_integration.py target/debug/hardware-monitor --report .build/snmp-receiver/reference-native.json --load-seconds 60
python3 tools/snmp_alarm_integration.py target/debug/hardware-monitor --report .build/snmp-alarm/reference-native.json --load-seconds 60
python3 tools/snmp_integration_test.py target/debug/hardware-monitor --report .build/snmp-package/reference-native.json
python3 tools/check_docs.py
python3 tools/snmp-reference/run.py
```

The SNMP reference scripts need Net-SNMP `snmpd`, `snmpget` and `snmptrap`.
They use random private credentials and temporary loopback agents. The polling
suite tests actual CLI reads; the receiver suite adds daemon reception, saved
sender enrollment, explicit review, restart and bounded load. The alarm suite
uses controlled local HTTPS/SMTP for partial alarms, old in-flight OK,
confirmation/recovery and actual submission counts. The aggregate wrapper also
runs Synology, Generic/Network, UPS and HPE suites. OpenSSL creates disposable
certificates. See [coverage and evidence limits](VALIDATION.md#local-regression-coverage).

Integration tests use temporary loopback HTTPS/SMTP servers and synthetic credentials. They do not contact real recipients or modify servers. OpenSSL is a test dependency, not a runtime requirement of the static SPK. Positive native DSM authentication cannot be established on an ordinary Linux host; the normal DSM service has no authentication bypass; the optional local HTTP adapter is tested separately.

Translation calls use a shared German-to-English catalog in `web/src/en.json`. The frontend handles live language selection and locale formatting; Rust uses the same catalog for fixed API messages and CSV headings. Structured event rendering is in `src/i18n.rs`. Add parity/placeholder checks and preserve vendor text when extending translations. Native notification keys exist in both DSM language directories, including fixed English/German sections for saved channel preferences.

## Local device maintenance

Copy `device.example.json` and use an HTTPS origin such as `https://bmc.example/`. Passwords are read from stdin, never from URL or command arguments:

```sh
read -r -s -p 'Device password: ' device_password; printf '\n'
printf '%s' "$device_password" | target/debug/hardware-monitor --state ./local-state device-put --file device.json
unset device_password
target/debug/hardware-monitor --state ./local-state poll-once
target/debug/hardware-monitor --state ./local-state snapshot
```

Use the web device editor for ordinary NAS administration. A private PEM CA is supported, while hostname verification remains mandatory. `repeat_seconds: null` disables reminders; configured reminders must be at least 300 seconds apart.

```sh
mkdir -p local-runtime
target/debug/hardware-monitor --state ./local-runtime/private --socket ./local-runtime/api.sock service start
target/debug/hardware-monitor --state ./local-runtime/private --socket ./local-runtime/api.sock service status
target/debug/hardware-monitor --state ./local-runtime/private --socket ./local-runtime/api.sock service stop
```

Normal service startup already processes saved SMTP/desktop channel settings. The legacy `--notify-dsm` switch is not used by the package and is not a requirement for these channels.

## Build the DSM 7 SPK

On an x86_64 Linux development machine (Ubuntu 24.04 is used by CI), install Rust 1.98.1 via rustup and Node 26 with npm. The toolchain also needs a C compiler, make, binutils, curl, Perl, Python 3 and OpenSSL:

```sh
sudo apt-get update
sudo apt-get install -y build-essential binutils curl perl python3 openssl snmp snmpd patch
rustup toolchain install 1.98.1 --component rustfmt --component clippy
rustup override set 1.98.1
rustup target add x86_64-unknown-linux-musl
sh tools/bootstrap_musl.sh
python3 tools/build_packages.py
```

OpenSSL is built from the Cargo.lock-pinned vendored source and linked statically; Perl is required for its build. The legacy TLS integration suite includes DHE-only TLS 1.2, exact certificate pinning and rejection before HTTP authentication.

The bootstrap downloads musl **1.2.5**, verifies its pinned SHA-256 and builds it inside `.build/`. The package command builds the Rust executable with an explicit generic x86-64 CPU baseline, installs locked frontend dependencies, builds Vue, regenerates dependency license notices, runs the real static binary against synthetic HTTPS/SMTP and independent Net-SNMP agents/traps (including two 60-second load cases), then checks the finished DSM 7 SPK. It fails on any failed stage. No NAS, device or real recipient is contacted. It rewrites the generated `THIRD_PARTY_NOTICES.txt`; review that diff when dependencies change.

Output in `dist/current/`:

- `HardwareMonitor-<version>-x86_64-dsm7-development.spk` (version from `packaging/INFO.dsm7`): one DSM 7 package for both Intel geminilake and AMD v1000 platforms.
- `latest-assets/`: fixed-name copies `HardwareMonitor-dsm7-x86_64.spk`, `build-manifest.json` and `SHA256SUMS`, ready for release upload.

The JSON manifest records the source base commit (when available), dirty state/source content hash, package hashes, version, archive timestamp and aggregate static SNMP evidence/binary hash. Dirty local builds are reviewable but the publisher rejects them before any GitHub operation. Sources must remain stable throughout a build; if generated notices change, review them and rebuild. `snmp-reference*.json` outside `latest-assets` retains the detailed local reports. Verify release downloads with `sha256sum --check SHA256SUMS` from the asset directory. Build logs remain the detailed evidence; a manifest is not a signature or a production certification.

In `build-manifest.json`, `packages` maps each SPK filename to its SHA-256 hash;
`packages_md5` and `packages_sha1` map the same filenames to MD5 and SHA-1 hashes
for compatibility with tools that require those formats.

The supported release set contains **one DSM 7 x86_64 SPK**. `tools/build_spk.py` still accepts explicit `--arch v1000` or `--arch geminilake` for focused diagnostics. Its default is `x86_64`; only the DSM 7 profile is accepted. For example, after the main build:

```sh
python3 tools/build_spk.py --profile dsm7 --arch x86_64 --binary target/x86_64-unknown-linux-musl/release/hardware-monitor
package_version=$(sed -n 's/^version="\(.*\)"/\1/p' packaging/INFO.dsm7)
python3 tools/check_spk.py "dist/HardwareMonitor-${package_version}-x86_64-dsm7-development.spk"
```

Do not package a binary dynamically linked against the development host's glibc. The assembler rejects dynamic/wrong-CPU executables. Never enable `target-cpu=native` or platform-specific CPU flags for this shared package. The musl compiler and bundled C code use the same baseline. Runtime CPU detection in dependencies is distinct from requiring a newer CPU at startup. See [Architecture family decision](PACKAGE-ARCHITECTURES.md).

For controlled archive timestamps set a fixed, positive `SOURCE_DATE_EPOCH` for all packages of one release. CI uses the source commit timestamp; local builds default to the build time. This controls archive metadata, not full compiler reproducibility. Vite embeds the INFO version; the assembler rejects stale assets. Increment the DSM 7 INFO build number for every installable update (including a rolling release); replacing a GitHub asset alone does **not** increase DSM's installed package version. The package title remains **Hardware Monitor**, and packages remain unsigned development builds.

## GitHub Actions and the rolling `latest` release

The workflow in `.github/workflows/check.yml` runs on pushes, pull requests and manual dispatch. Rust/translation/frontend, patched-library source/security/corpus and native SNMP checks must pass before it builds the static binary and DSM 7 SPK. Package generation requires Net-SNMP and runs static polling/receiver/alarm suites; normalized native/static SNMP reports are retained separately for 14 days. The checked release files are retained as the `checked-spks` Actions artifact for 14 days, including on pull requests.

Only a push/manual run on the repository's **default branch** can publish. The publication job has `contents: write`; test/build jobs have read access only. No PAT or NAS/SMTP credentials are needed: GitHub's built-in token is used. Publication is serialized and refuses an older build if the default branch has already advanced. The `latest` tag is moved to the built commit so GitHub's source downloads match the SPKs. Checksums and the manifest are validated again before any write.

The existing development release is updated with `gh release upload --clobber`: the same three asset names are replaced. Old package/manifest assets managed by this workflow, including the retired package asset, are removed after a successful upload; unrelated assets are preserved. No release is changed by local tests. The tag is `latest`, and the release is marked **prerelease** because these are development packages; this is separate from GitHub's stable-release “Latest” badge. A permanent download link has the form `https://github.com/OWNER/REPO/releases/download/latest/HardwareMonitor-dsm7-x86_64.spk`.

Asset replacement is not atomic. A failed upload can leave incomplete or temporarily mismatched assets; the workflow fails and must be rerun, and downloaders should verify checksums after a successful run. Immutable releases cannot be reused; the publisher refuses them before moving the tag. Repository rules must allow updating `latest` and release assets.

After pushing this project to GitHub, enable Actions and allow the workflow token to write repository contents/releases in repository or organization policy. Local validation did not dispatch a hosted Actions run or publish release assets; local workflow syntax validation does not establish a successful hosted run. A manual dispatch on a feature branch builds artifacts but does not publish.

## Tagged GitHub releases

The separate `.github/workflows/release.yml` workflow builds and publishes when a tag is created on GitHub or an existing tag is pushed. New tags emit both `create` and `push`; only the creation event builds that new tag. Branch events and the reserved rolling `latest` tag are excluded.

For example, after committing the intended package version, create and push a release tag:

```sh
git tag v0.10.0
git push origin v0.10.0
```

The workflow checks out the tagged commit and runs the same pinned musl/static SPK build and integration/package checks as the existing package job, including both SNMP load cases. Only a successful build permits the release job to run. It verifies checksums and creates a release for the existing tag with generated release notes, attaching `HardwareMonitor-dsm7-x86_64.spk`, `build-manifest.json` and `SHA256SUMS`. The build job has read access; only the release job receives `contents: write` through GitHub's built-in token. No additional secret is needed.

Runs for the same tag are serialized. Rerunning the workflow or pushing an updated tag uploads the checked assets to the existing release with `--clobber`; existing release notes are preserved. Immutable releases reject replacement uploads. The workflow does not move tags or change package versions: update the version metadata and DSM build number before tagging an installable update. Packages retain their existing unsigned development status and hardware acceptance boundaries.

## README screenshots

`python3 tools/preview_ui.py` serves the production UI with read-only synthetic data at `http://127.0.0.1:18773`. Choose English, capture the device and event views, and save images in `docs/images/`. This screenshot-only server denies writes and never runs as part of an SPK. It does not establish DSM authentication or hardware interoperability. Browser-owned file-picker text follows browser/OS language independently of the app.

The pre-upgrade hook stops the service and creates a private SQLite/master-key snapshot through the old CLI. The new package post-install hook runs `hardware-monitor initialize` before service start on install, upgrade and repair. This initializes/migrates the database and records diagnostics in private `service.log` without starting polling or delivery. Service start also reconciles private state in its controller before launching the daemon, so its 120-second socket-readiness budget starts after migration and the protected backup are complete. Initialization uses a 30-second database busy timeout before returning to the five-second runtime setting. Explicit native commands take precedence over inherited CGI markers, and lifecycle scripts unset `GATEWAY_INTERFACE`, including calls to an older pre-upgrade executable. DSM service status is 0 when running, 3 when stopped and 4 when status cannot be determined. This local backup is not the password-encrypted app download. See [Backup and restore](BACKUP-RESTORE.md). DSM package downgrade is unsupported. Earlier NAS acceptance did not cover the subsequently reported 1.1-GB migration exceeding the readiness deadline. Build 0077 adds large-database and delayed-initialization regressions. The user subsequently confirmed the reported NAS repair/update as working; broader target acceptance remains separate.

## SNMP interaction fixture

`node tools/snmp_ui_preview.mjs` serves the actual Vite UI at `http://127.0.0.1:5185/snmp-preview`, with disposable synthetic configuration/diagnostic responses. `?role=viewer` selects read-only fixture data. This is a separate loopback-only test server, never a product authentication bypass or SPK component; no BMC, NAS or mail recipient is contacted. Its supported writes mutate only in-memory fixture data. The optional `.build/snmp-ui/ui-requests.json` records action names, versions, secret actions and engine approvals without secret values. Keep all captures/reports ignored. Browser checks verify interaction and escaping; native authentication is covered separately by backend boundary tests and requires DSM acceptance. See [Validation](VALIDATION.md#local-regression-coverage).

For a local package needed before the two 60-second SNMP load scenarios finish,
`python3 tools/build_packages.py --skip-load-tests` keeps all functional and
package checks, records `skipped_checks` and runs the SNMP wrapper with load
duration zero. CI/default builds retain both load scenarios. Subsequent load
validation can use the delivered executable with
`python3 tools/snmp_integration_test.py /path/to/hardware-monitor --require-static --load-seconds 60 --report /path/to/report.json`.


The static SNMP package gate also runs `tools/snmp_ups_integration.py` through
`tools/snmp_integration_test.py`: 3 UPS profiles × v1/v2c/v3-SHA1/v3-SHA256.
Its synthetic numeric fixtures run behind independent Net-SNMP; they verify real
CLI probe/poll/store/alarm/recovery paths without real UPS power controls.


`python3 tools/upgrade_integration.py target/debug/hardware-monitor --report .build/upgrade-native.json`
checks direct schema-1 upgrade, repeat post-install/repair, delayed startup and
failed migration retry with synthetic private state. The optional
`--legacy-binary /path/to/archived/hardware-monitor` creates the baseline with a
real 0.8.0 executable. Native CI and package generation run the independent legacy
schema fixture; the package manifest records the static upgrade-suite evidence.

## Large backup regression

The default Rust suite covers staged restore, authentication, corruption/truncation/trailing data, cancellation, actual SQLite disk-full rollback, consistent online snapshots and session-bound job/offset handling. The larger on-disk test is deliberately ignored by default. Run it in release mode on a filesystem with at least 25 GiB free:

```sh
cargo test --release --locked --lib stream_archive::tests::multi_gib_history_roundtrip_with_bounded_memory -- --ignored --exact --nocapture
```

It creates 1.8 million synthetic log entries, over 2 GiB of logical records, and verifies complete cross-key restore and paused devices. For a useful peak-RSS measurement, compile with `cargo test --release --locked --lib --no-run`, then invoke the reported unit-test executable directly under `/usr/bin/time -v` with the same `--ignored --exact` selector. Timing Cargo itself would include compiler memory. Compression ratio and runtime depend on the fixture and host; NAS acceptance remains separate.

## SNMP dependency and reference tests

Production pins `async-snmp =0.18.1`, defaults disabled, `crypto-rustcrypto` only,
with MIT/Apache-2.0 licenses in the vendored source and generated notices. The
upstream high-level username map cannot select different device secrets sharing
a username. Application-owned routing therefore selects a single approved
source/engine/user context, without trying passwords.

`vendor/async-snmp-provenance.json` records the published crate SHA-256 and the
explicit checksummed patch stack in `tools/snmp-reference/patches/`:

- Routed datagram processing, monotonic authenticated remote-engine observations
  and bounded remote cache access.
- A decoded-varbind hook for shared polling budgets and v1 type checks.
- A boolean authenticated polling-hint API using disposable remote clock state;
  normal strict receiver state and cryptographic/time algorithms are unchanged.

`python3 tools/snmp-reference/prepare.py` reconstructs the pinned archive, applies
patches without fuzz and compares the complete production tree against recorded
file hashes. Only listed upstream examples/benchmarks/CI are omitted; production
sources/licenses remain byte-identical to the reconstructed result. Neither
Net-SNMP nor patch/download tooling is installed or run on the NAS.

`python3 tools/snmp-reference/run.py --offline --musl` checks formatting, Clippy,
unit tests, product dependency alignment, independent native/static Net-SNMP
cases and ELF linkage. Add `--audit` for an online OSV query of public dependency
names/versions only. That is a point-in-time advisory lookup, not an audit of the
local patches. Without `--offline`, preparation may download the pinned crate.
Keep generated reports, temporary secrets and build data ignored. Harness-only
synthetic identifiers can retain historical names; they are fixture data, not
implementation-phase dependencies.

Numeric mappings are sourced in `docs/SNMP-SERVER-SOURCES.json`,
`SNMP-SYNOLOGY-SOURCES.json`, `SNMP-GENERIC-NETWORK-SOURCES.json` and
`SNMP-UPS-SOURCES.json`. They record retrieval hashes, units and provenance;
manufacturer MIB/PDF archives and private raw walks are not shipped. The network
profile is independently written from standard contracts; no Zabbix template is
imported or loaded. Extend numeric mappings with typed fixtures and independent
reference coverage, then record real hardware evidence separately.

`python3 tools/check_docs.py` validates repository-local Markdown links and heading
anchors. CI and package generation run it; SPK inspection checks the packaged
README/docs set too. The SPK must include the maintained SNMP guide and source
records, and exclude temporary planning/result reports and reference tooling.

Outgoing webhook integration (isolated HTTP/HTTPS recipients, no real destinations):

```sh
cargo build --locked --features local-dev
python3 tools/webhook_integration_test.py target/debug/hardware-monitor
```
