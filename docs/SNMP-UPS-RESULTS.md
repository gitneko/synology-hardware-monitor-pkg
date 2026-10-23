# UPS polling profiles — build 0.9.0-0054

Implemented on 22 October 2026, product version **0.9.0**. This is source and
local reference evidence. **No real UPS, management-card firmware or native DSM
acceptance is claimed.** Existing DSM/Synology profile confirmations retain their
original build and scope.

## Profiles and assessment

| Selection | Numeric contract | Assessment and optional data |
|---|---|---|
| UPS · Generic (RFC 1628), `ups_generic` | `1.3.6.1.2.1.33` | Required battery/output states and active alarm evidence; optional self-test result, battery charge/runtime/voltage/current/temperature, time on battery, frequency and discovered input/output phase measurements |
| APC UPS, `apc_ups` | PowerNet `1.3.6.1.4.1.318.1.1.1` | Required basic battery/output states; optional battery replacement, diagnostics and the documented 64-character ASCII state flags; optional charge/runtime/temperature/load/voltage/current/frequency |
| Eaton UPS, `eaton_ups` | xUPS `1.3.6.1.4.1.534.1` | Required output state and active alarm evidence; optional ABM/battery failure/presence/aging/low-capacity/test states; charge/runtime/temperature/voltage/current/frequency/load and discovered input/output phases |

The existing generic SNMP availability profile is unchanged. These are separate,
explicit UPS profiles, with no manufacturer-name guessing, fallback MIB probing,
SNMP security downgrade, arbitrary MIB import or runtime MIB files. See
[source provenance and checked numeric roots](SNMP-UPS-SOURCES.json).

Application severity policy derives from the documented state, rather than
claiming that every MIB supplies a severity: utility output is healthy; battery
operation and bypass warn; low/depleted/faulted/disconnected/missing batteries,
output loss and explicit serious faults are critical. AVR boost/trim are normal
regulation. Eaton parallel/efficiency/ESS modes documented in the checked MIB
are normal. Unrecognized values/modes or wrong types remain unknown. Tests or
control operations in progress do not by themselves confirm fault recovery.
Battery replacement or aging warns where explicitly reported.

Optional absent telemetry and phase tables do not block assessment. Required
missing state and genuine walk failures still do. A selected profile's green
state covers its assessed MIB states, not every internal UPS component. In
particular APC basic-only agents have less coverage than agents exposing the
optional PowerNet state flags. Modern Eaton battery flags are optional on older
xUPS implementations. Legacy MGE/MG-SNMP-UPS-MIB, PDUs, switched outlets, parallel
module topology and every possible enterprise variant are outside this change.

## Measurements and alarm lifecycle

Values use exact MIB types and units: APC runtime is TimeTicks converted to
seconds, RFC runtime stays minutes, Eaton runtime is seconds; RFC currents and
battery voltage use tenths, Eaton base current/voltage use whole units. Signed
charging current remains signed. APC unsupported temperature/runtime sentinels
are hidden; malformed/out-of-range telemetry remains informational without an
invented measurement alarm threshold. UPS-reported alarms are authoritative
inputs to the existing alarm pipeline.

RFC and Eaton alarm tables are sparse and legitimately empty. The poll reads
the Gauge32 count before and after the descriptor walk. A completed walk,
matching counts, row count and valid unique descriptor OIDs are needed to prove
an empty/complete alarm set. Empty, missing, malformed, duplicate, truncated or
changing evidence cannot fabricate recovery. Known critical evidence still
raises critical status during an incomplete scan; partial lower-severity data
cannot downgrade a retained critical aggregate. Unknown active descriptor OIDs
warn when the scan is complete.

The assessed alarm summary includes the active conditions. Its acknowledgement
fingerprint follows sorted condition OIDs, not recyclable alarm row numbers;
APC uses documented flag positions. New causes invalidate acknowledgement even
when aggregate severity stays the same. The existing transactional store retains
faults through partial input and records recovery once fresh evidence confirms
normality. Enum-based state changes also carry condition fingerprints.

These profiles are **read-only polling**. They neither switch UPS power nor
request shutdown/self-tests, and introduce no vendor UPS trap-to-component
mapping. Existing separately configured trap reception remains available with
its existing verification and event-only behavior for unmapped traps.

## Validation

- **182 Rust unit tests + 9 integration tests** passed, including seven new UPS
  tests for enum/type differences, units/sentinels, sparse phase/alarm indices,
  zero-count proof, malformed/duplicate/count-race evidence, APC bit positions,
  and stored acknowledgement/new-cause/partial/recovery behavior.
- **59 frontend tests** passed, including explicit selection and bilingual labels
  for all three profiles. The editor explains scope and read-only behavior.
- **23 Python tests** passed; formatting and Clippy with warnings denied passed.
- Independent Net-SNMP reference test: **12 actual-product configurations**,
  each profile using v1, v2c, v3 SHA-1/AES-128 and v3 SHA-256/AES-128. Actual CLI
  probe/save/poll/store paths covered healthy and fault states, optional fields,
  sparse phases, retained faults under incomplete evidence and exactly one
  confirmed recovery. Unknown active alarms and APC sentinels were also checked.
  Runtime credentials are random/private and excluded from reports.
- The package pipeline now includes this UPS reference suite against the actual
  static executable, alongside the previous SNMP/Redfish/TLS/SMTP gates. Package
  contents, source/binary identity and checksums are recorded in
  `dist/current/latest-assets/build-manifest.json` and `SHA256SUMS` after a
  successful build. The bundled JavaScript must contain all three profiles.
- As requested, the two 60-second load scenarios are deferred until after SPK
  delivery and are recorded as skipped in the initial build manifest.

Real device acceptance should record UPS model, network card, firmware, exposed
MIB, SNMP version, ordinary/multi-phase readings and safely observed fault and
recovery states. No real-device acceptance can be inferred from the synthetic
reference agent.
