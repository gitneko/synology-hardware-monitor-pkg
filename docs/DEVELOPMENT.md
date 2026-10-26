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

SNMP polling/traps are not implemented in the current application. The local mode does not claim SNMP support; SNMP integration requires its own implementation and protocol/device acceptance tests.

## Local checks

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
```

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
sudo apt-get install -y build-essential binutils curl perl python3 openssl
rustup toolchain install 1.98.1 --component rustfmt --component clippy
rustup override set 1.98.1
rustup target add x86_64-unknown-linux-musl
sh tools/bootstrap_musl.sh
python3 tools/build_packages.py
```

OpenSSL is built from the Cargo.lock-pinned vendored source and linked statically; Perl is required for its build. The legacy TLS integration suite includes DHE-only TLS 1.2, exact certificate pinning and rejection before HTTP authentication.

The bootstrap downloads musl **1.2.5**, verifies its pinned SHA-256 and builds it inside `.build/`. The package command builds the Rust executable with an explicit generic x86-64 CPU baseline, installs locked frontend dependencies, builds Vue, regenerates dependency license notices, runs the real static binary against synthetic HTTPS/SMTP servers and checks the finished DSM 7 SPK. It fails on any failed stage. No NAS, device or real recipient is contacted. It rewrites the generated `THIRD_PARTY_NOTICES.txt`; review that diff when dependencies change.

Output in `dist/current/`:

- `HardwareMonitor-0.8.0-0040-x86_64-dsm7-development.spk`: one DSM 7 package for both Intel geminilake and AMD v1000 platforms.
- `latest-assets/`: fixed-name copies `HardwareMonitor-dsm7-x86_64.spk`, `build-manifest.json` and `SHA256SUMS`, ready for release upload.

The JSON manifest records the source commit (when available), package hashes, version and archive timestamp. Verify release downloads with `sha256sum --check SHA256SUMS` from the asset directory. Build logs remain the detailed evidence; a manifest is not a signature or a production certification.

The supported release set contains **one DSM 7 x86_64 SPK**. `tools/build_spk.py` still accepts explicit `--arch v1000` or `--arch geminilake` for focused diagnostics. Its default is `x86_64`; only the DSM 7 profile is accepted. For example, after the main build:

```sh
python3 tools/build_spk.py --profile dsm7 --arch x86_64 --binary target/x86_64-unknown-linux-musl/release/hardware-monitor
python3 tools/check_spk.py dist/HardwareMonitor-0.8.0-0040-x86_64-dsm7-development.spk
```

Do not package a binary dynamically linked against the development host's glibc. The assembler rejects dynamic/wrong-CPU executables. Never enable `target-cpu=native` or platform-specific CPU flags for this shared package. The musl compiler and bundled C code use the same baseline. Runtime CPU detection in dependencies is distinct from requiring a newer CPU at startup. See [Architecture family decision](PACKAGE-ARCHITECTURES.md).

For controlled archive timestamps set a fixed, positive `SOURCE_DATE_EPOCH` for all packages of one release. CI uses the source commit timestamp; local builds default to the build time. This controls archive metadata, not full compiler reproducibility. Vite embeds the INFO version; the assembler rejects stale assets. Increment the DSM 7 INFO build number for every installable update (including a rolling release); replacing a GitHub asset alone does **not** increase DSM's installed package version. The package title remains **Hardware Monitor**, and packages remain unsigned development builds.

## GitHub Actions and the rolling `latest` release

[The workflow](../.github/workflows/check.yml) runs on pushes, pull requests and manual dispatch. Rust/translation/frontend checks must pass before it builds the static binary and DSM 7 SPK. The checked release files are retained as the `checked-spks` Actions artifact for 14 days, including on pull requests.

Only a push/manual run on the repository's **default branch** can publish. The publication job has `contents: write`; test/build jobs have read access only. No PAT or NAS/SMTP credentials are needed: GitHub's built-in token is used. Publication is serialized and refuses an older build if the default branch has already advanced. The `latest` tag is moved to the built commit so GitHub's source downloads match the SPKs. Checksums and the manifest are validated again before any write.

The existing development release is updated with `gh release upload --clobber`: the same three asset names are replaced. Old package/manifest assets managed by this workflow, including the retired package asset, are removed after a successful upload; unrelated assets are preserved. No release is changed by local tests. The tag is `latest`, and the release is marked **prerelease** because these are development packages; this is separate from GitHub's stable-release “Latest” badge. A permanent download link has the form `https://github.com/OWNER/REPO/releases/download/latest/HardwareMonitor-dsm7-x86_64.spk`.

Asset replacement is not atomic. A failed upload can leave incomplete or temporarily mismatched assets; the workflow fails and must be rerun, and downloaders should verify checksums after a successful run. Immutable releases cannot be reused; the publisher refuses them before moving the tag. Repository rules must allow updating `latest` and release assets. Keep immutable, versioned releases separate if added later.

After pushing this project to GitHub, enable Actions and allow the workflow token to write repository contents/releases in repository or organization policy. No remote is configured in the supplied local repository yet, so an actual hosted Actions run/publication has not been verified. A manual dispatch on a feature branch builds artifacts but does not publish.

## README screenshots

`python3 tools/preview_ui.py` serves the production UI with read-only synthetic data at `http://127.0.0.1:18773`. Choose English, capture the device and event views, and save images in `docs/images/`. This screenshot-only server denies writes and never runs as part of an SPK. It does not establish DSM authentication or hardware interoperability. Browser-owned file-picker text follows browser/OS language independently of the app.

The upgrade hook stops the service and creates a private SQLite/master-key snapshot through the CLI. This local backup is not the password-encrypted app download. See [Backup and restore](BACKUP-RESTORE.md). Full rollback behavior, crash restart, resource measurements and directory-service group resolution still require target acceptance.
