# Synology DSM polling — 0.9.0-0051

Implemented on 21 October 2026 for explicitly selected `synology_dsm` polling.
The application stays **0.9.0**; the DSM package advances from build 0050 to
**0051**. On 21 October 2026, the user confirmed installation of this build
and confirmed the Synology DSM polling profile on the real deployment.
P7 is partially confirmed; broader hardware/security/fault/recovery acceptance
remains open.

## User-confirmed DSM acceptance (21 October 2026)

The user reported: “Build installiert. DSM Profil ist bestätigt.” This confirms
installation of build **0.9.0-0051** and operation of the **Synology DSM polling
profile** on the user's deployment. This is user-reported real-device evidence,
separate from the local synthetic/reference tests below.

The report does not specify the polled NAS model, DSM version, SNMP version or
security selection, nor an individual sensor inventory. These details remain
unrecorded; earlier host-platform evidence is not assigned to the polling target.
No physical fault/recovery, firmware/security matrix or trap acceptance is
inferred from this confirmation. The broader P7 matrix remains open.

## Sources and scope

The official [Synology SNMP MIB guide](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/DSM/All/enu/Synology_DiskStation_MIB_Guide.pdf)
and its linked [official MIB archive](https://global.download.synology.com/download/Document/Software/DeveloperGuide/Firmware/SynologyOS/All/enu/Synology_MIB_File.zip)
were downloaded and compared. The numeric allowlist, types, units and enum
interpretation are recorded in [source checksums](SNMP-SYNOLOGY-SOURCES.json).
No vendor MIB, ZIP or PDF is distributed or loaded at runtime.

The guide introduction states that DSM does not support SNMP traps. Accordingly,
DSM is offered as a **polling profile** in the editor. No guessed Synology trap
mapping or DSM trap option is added. Unknown vendor input remains event-only
under the existing trap policy. This profile covers DSM, not DSM Enterprise,
APM, SRM, UPS, SMART attributes, HA, expansion chassis or utilization metrics.

| Numeric OID (under `1.3.6.1.4.1.6574`) | Coverage and interpretation |
| --- | --- |
| `.1.1.0` | System partition, normal 1 / critical 2; never treated as a full hardware rollup. |
| `.1.3.0`, `.1.4.1.0`, `.1.4.2.0` | Power supply summary, system fan and CPU fan; normal 1 / critical 2. Missing or invalid states stay unknown; no inference that a missing fan is physically absent. |
| `.1.8.0` | Optional overheating status, normal 1 / critical 2; omitted when unavailable on older DSM. |
| `.1.2.0` | System temperature, typed Celsius reading; informational without an invented threshold. Missing/invalid reading stays unknown. |
| `.2.1.1` columns 2/3/5/6/12/13/14 | Disk label/model, deployment, Celsius temperature, preferred name, optional physical health and optional real serial. |
| `.3.1.1` columns 2/3 | RAID/pool/volume name and status. Degraded 11 is warning, crashed/read-only 12 is critical, normal 1 is OK. |

Disk deployment 1–3 does not itself imply a hardware fault: initialized and
uninitialized are allocation states, shown in the label. Deployment 4/5 is
critical. Optional physical health (DSM 7.1+) maps 1 to OK, 2 to warning and 3/4
to critical. A reported fault dominates missing/invalid counterpart data.
Missing optional health on older DSM uses deployment status, which offers less
health coverage; a present malformed/new health enum cannot fall back to OK.

RAID maintenance values 2–10 and 13–20 are shown by name with unknown assessment.
They do not generate a hardware fault solely for routine work such as scrubbing
and cannot confirm recovery of an earlier failure. Value 21 and unrecognized or
incorrectly typed values stay unknown. Removed/missing disks or storage objects
cannot be declared recovered from absence; Synology notes missing storage may
not appear in the RAID table. Use DSM Storage Manager for full storage coverage.

Only typed integer temperatures in the conservative operating range 1–150 °C
are displayed; 0, negative sentinels, wrong types and extreme values are omitted.
No threshold is inferred from a raw temperature. The optional thermal status is
a separate manufacturer alarm signal.

Table rows join on a validated single nonnegative index, including zero and
sparse indices. Names and serials are reread every poll. Disk names, IDs and
RAID names are not physical identity proof. Without a unique real serial, keys
remain scoped to the current polling generation and index, as in existing OEM
profiles. Replacements with no serial proof require review; an index is not a
cross-protocol identity. Unique optional serials use the existing stable key;
duplicated or placeholder serials cannot merge components. The guide labels
serial column 14 as Integer, while the authoritative MIB defines OCTET STRING;
the implementation accepts the MIB's bounded text type only.

## Local verification

- 169 Rust unit tests and 9 integration tests pass, including the new DSM enum,
  sparse row, duplicate/unique serial, wrong type, temperature and partial-data
  regressions. Formatting, warnings-denied Clippy and vendor checksum validation
  pass. Existing vendor source/patches remain byte-identical.
- 56 frontend tests pass in the full shared-runtime test run, including DSM
  configuration round trip, selected profile rendering, translated guidance and
  translation placeholder parity. 23 Python release/build/uninstall tests pass.
- The actual native product CLI is checked against independent Net-SNMP with a
  test-only numeric `pass_persist` fixture. Four configurations cover v1, v2c,
  v3 SHA-1/AES-128 and v3 SHA-256/AES-128. Each checks connection test, persisted
  profile/table capabilities, zero/sparse rows, power/disk/RAID faults, actual
  alarm persistence, scalar recovery, maintenance and missing scalar/row status.
  v1 also exercises absent newer optional fields through its error-index path.
- The same DSM suite is mandatory in the aggregate reference wrapper used by
  native CI and the static SPK build. Existing Redfish/CGI, legacy TLS, SMTP,
  SNMP P2/P3/P4 functional suites remain package build gates. For this delivery,
  the user requested skipping the two 60-second load cases until after the SPK
  is delivered. `--skip-load-tests` records the omission in the manifest; the
  standard build/CI default still runs both. A later load report is supplemental
  evidence and does not change the already-delivered package or manifest.
- The assembled static DSM 7 x86_64 SPK is inspected for executable/UI/INFO version
  consistency, the DSM selector, default-disabled receiver, package lifecycle,
  uninstall guards and absence of test tooling/MIB files. Text/source secret
  scans and locked dependency advisory checks are retained under ignored
  `.build/snmp-synology/`; no real secret was found. No commit/push/publication
  is part of the local build procedure. The subsequent user-confirmed NAS
  installation/profile result is recorded separately above.

Package: `dist/current/HardwareMonitor-0.9.0-0051-x86_64-dsm7-development.spk`.
The generated manifest records source content identity, static executable hash,
all reference suite results and package checksum. Build 0050 evidence is retained
in [the historical P6 report](SNMP-P6-RESULTS.md). Native DSM/model/firmware
matrix coverage and real physical fault/recovery still require P7 acceptance;
installation and DSM profile operation are user-confirmed above.
