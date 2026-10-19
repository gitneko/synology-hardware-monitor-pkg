# DSM 7 x86_64 package

## Decision

The maintained release contains one SPK for Synology DSM 7.0 and later with `arch="x86_64"`. The minimum DSM version remains **7.0-40761**.

Synology documents architecture-family selectors in its [INFO necessary fields](https://help.synology.com/developer-guide/synology_package/INFO_necessary_fields.html), and lists **geminilake** and **v1000** in the **x86_64** family in [Appendix A](https://help.synology.com/developer-guide/appendix/platarchs.html). This is an architecture-family selector, not `*` or `noarch`. The package contains an x86_64 executable.

## Shared executable

- The daemon and CGI use the same statically linked `x86_64-unknown-linux-musl` executable. No model-specific libraries, kernel modules or Synology SDK binary dependencies are shipped.
- SQLite, TLS dependencies and musl are bundled. Package checks reject an ELF interpreter or dynamically needed libraries.
- Rust and C use the generic x86-64 CPU baseline, without native tuning. The musl compiler uses the same baseline.
- DSM helpers are discovered at runtime; paths and desktop registration use the DSM 7 package profile.

Architecture-family eligibility does not certify every physical model, firmware, kernel or native helper. ARM/i686 NASes cannot use this binary. See the [compatibility evidence](HARDWARE-COMPATIBILITY.md).

## Validation boundary

Local checks inspect the INFO architecture and minimum DSM version, static executable, lifecycle, CGI denial, UI paths and native text resources. The static binary also runs against loopback Redfish/TLS and SMTP/queue fixtures. These checks do not emulate DSM's installer or establish compatibility on every NAS.

The user confirmed installation of the grouped build-0018 package on the RS2421RP+. Other models require their own acceptance. Package identity stays `HardwareMonitor`, preserving the normal upgrade path and existing application data.

The assembler retains explicit `v1000`/`geminilake` architecture overrides for focused DSM 7 diagnostics. Release automation builds and publishes only `HardwareMonitor-dsm7-x86_64.spk`, `build-manifest.json` and `SHA256SUMS`.
