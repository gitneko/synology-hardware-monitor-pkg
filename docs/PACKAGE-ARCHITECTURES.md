# Shared DSM 7 x86_64 package

## Decision

From build **0018**, publish one DSM 7 SPK with `arch="x86_64"`. It replaces the separate v1000 and geminilake release files. Keep DSM 6.2 as a separate `geminilake` SPK for the intended DS220+ target. DSM 6 and DSM 7 still have different minimum/maximum versions, desktop registration and lifecycle profiles.

Synology defines `arch` as the installable CPU architecture list, explicitly shows a family value in its [INFO necessary fields](https://help.synology.com/developer-guide/synology_package/INFO_necessary_fields.html), and lists both **geminilake** and **v1000** in the **x86_64** family in [Appendix A](https://help.synology.com/developer-guide/appendix/platarchs.html). This is an architecture-family selector, not the literal `*` character and not `noarch`. The latter is inappropriate for a package containing an x86_64 executable. The guide documents family selectors for DSM 7; this decision does not assert that older DSM releases reject them, only that the untested DSM 6 profile remains conservative.

## Why the application can share one executable

- The daemon and CGI are the same statically linked `x86_64-unknown-linux-musl` executable. There are no model-specific shared libraries, kernel modules or Synology SDK binary dependencies.
- SQLite is bundled; TLS dependencies and musl are built into the executable. Package checks reject an ELF interpreter or dynamically needed libraries.
- The supported build command explicitly uses the generic **x86-64** CPU baseline for Rust and C. It does not compile for the developer's native Intel/AMD CPU. The pinned musl build uses that baseline too.
- DSM helpers and package paths are selected by DSM profile and discovered at runtime; they do not depend on the v1000/geminilake string.

The arch selector permits installation across a family; it does not certify every model, firmware, kernel or DSM helper. Other x86_64 NASes are candidates, not automatically accepted targets. ARM/i686 NASes cannot use this binary. Rust lists the [musl target](https://doc.rust-lang.org/rustc/platform-support.html) separately from glibc, which is why the NAS's glibc version does not select our build.

## Validation boundary

Local checks inspect the shared INFO value, the CPU/static ELF properties, both finished DSM profiles, lifecycle, CGI rejection, UI paths and native text resources. The real static binary also passes loopback Redfish/TLS and SMTP/queue integration. These checks do not emulate DSM's installer or prove instruction/kernel compatibility on all NASes.

The RS2421RP+ was previously accepted using the model-specific v1000 SPK. The user has now confirmed successful installation of the grouped build-0018 SPK on the RS2421RP+. Normal operation of that build and a geminilake/DS220+ check remain separate acceptance items. Package identity remains `HardwareMonitor`, so an upgrade preserves the existing package data. Build 0018 increases the INFO version so it can be installed as an update to 0017.

The assembler retains explicit v1000/geminilake overrides for diagnosis. Release automation emits only the grouped DSM 7 package and the separate DSM 6 geminilake package.
