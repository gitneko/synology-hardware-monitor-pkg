# SNMP P5 — configuration UI and localization

Implemented on 21 October 2026 on the existing `snmp` development branch, after
P0–P4 and the shared-model `PrimaryProtocol` move. The executable/UI/package
identities remain `0.8.0` / `0.8.0-0034`; the coordinated **0.9.0** identities,
first checked SPK and release validation remain P6. Real DSM/BMC acceptance is P7.

## Configuration and explicit trust

`DeviceEditor.vue` now supports Redfish and SNMP primary protocols. Redfish keeps
its existing password/certificate controls. SNMP offers explicit v1, v2c or v3
(authPriv), independent host/UDP agent port, hardware profile, SHA-1/SHA-256,
AES-128, optional v3 context/engine, request timeout and zero/one retry. V3 is the
new-form default. V1/v2c warn about cleartext community/no cryptographic integrity;
there is no automatic downgrade. Fields belonging to the hidden protocol are
excluded from the request. A bounded connection probe displays actual version,
assurance, target, engine identity when verified, profile, requested group
coverage and elapsed milliseconds. An identity-only response is not presented as
complete hardware health.

Trap reception is separate from regular polling: source IP allowlist, security,
profile, context and approved sender/context engine IDs. Polling and trap secrets
have explicit keep/replace/clear actions. Saved values are never loaded into
password fields or returned by the backend. Secret actions use the existing
purpose-specific schema; inactive inputs can clear credentials. Replacement
passphrases/community are checked against UTF-8 byte limits, not character counts.
Closing/disposal clears all entered passwords. Leaving SNMP clears retired polling
credentials. A Redfish primary can save an optional responder host/port for
sender verification; it uses trap credentials and adds no periodic SNMP poll or
extra polling credential.

V3 enrollment uses the existing `snmp_trap_probe` for the saved device/revision.
An edited target/security/allowlist/context disables this saved-target check until
saved. The authenticated result grants **no approval**. Only the separate
**Use verified engine ID in draft** action replaces the sender-engine allowlist;
it requests fresh trap credentials and still requires Save. Draft changes
invalidate a pending review result. Arbitrary manually entered engine allowlists
remain an explicit administrator configuration action. Genuine engine replacement,
normal boots increases and missing verification baselines have distinct labels.
Scope/revision/epoch and message verification stay enforced by the backend.

`SnmpSettings.vue` adds the global receiver settings and receipt view. The default
local UDP port is **1162**, configurable **1024–65535**; the normal agent port
**161** and standard trap port **162** are explained separately. Local IPv4/IPv6
addresses, actual bound endpoints, bind/service failures, current sender
verification, last accepted receipt and bounded rejection/drop counters are
separate facts. Stale sender revisions do not display an old verified badge or
engine identity. A local bind does not claim firewall reachability or actual BMC
receipt. Settings use the existing revisioned `snmp_receiver_save`; receipt
inspection uses the existing authenticated `snmp_receipts` (20/50/100 records).

The test instructions require the operator to send a controller trap, then inspect
source/device, time, version, OID, engine, verification and profile handling.
Test, unsupported PET, unmapped/unverified input, provisional fault and recovery
hints have separate descriptions. Loopback sources and imported/old-revision
receipts are explicitly historical/local evidence, never current controller
acceptance. Manufacturer messages are Vue text interpolation, not HTML.

## Dashboard, events and notifications

The dashboard displays primary protocol, last saved poll, last accepted trap,
coverage and receiver health independently. Stale/missing polling is explicit,
while retained verified trap faults remain visible. Alarm evidence distinguishes
confirmation pending, confirmation currently unavailable, confirmed by primary
poll, and retained/unassessable state. A provisional timestamp is labelled as
received rather than measured.

Two frontend assessment defects found during P5 were corrected and covered by a
regression test: warning trap evidence cannot downgrade a separate critical
backend assessment; inactive historical evidence cannot label a later alarm as a
currently confirmed trap fault.

Event history exposes the trap category and unknown/unverified severity filter,
plus source, verification, provisional state and receipt reference where present.
CSV continues to use the same backend filters/provenance from P4. The notification
editor exposes default-off **Verified SNMP trap events without component mapping**;
old settings without the field stay off. Only verified known event-only faults
with a selected severity are eligible; mapped alarms use existing hardware
filters. Test/unknown/unverified/recovery input never becomes an automatic fault
notification through this choice. The mail editor lists the P4 placeholders
`{{source}}`, `{{verified}}`, `{{provisional}}`; existing templates are preserved.

English/German labels share the current catalog. Authentication/digest diagnostics
suggest both passphrases and SHA selection, without assigning one unproven cause.
Timeout diagnostics also mention version/security mismatch and silent agent drops.
Backend fixed errors and UI labels use the same catalog. Placeholder parity is
checked; free-form vendor/device text remains unchanged and escaped.

## Verification and limits

Passed locally:

- **164 Rust unit tests + 9 integration tests**, `cargo fmt --check`, Clippy with
  warnings denied and native product build. Existing actual API authorization,
  CSRF/revision and receiver bind/rollback tests remain applicable.
- **55 frontend tests**, including protocol-specific request shapes, v1/v2c
  support, independent secret actions, UTF-8 limits, Redfish responder behavior,
  explicit engine review/revision rejection, read-only receiver rendering,
  default-off legacy notification settings, assessment regression and German/
  English placeholder parity. Production Vite build succeeds.
- **19 Python tests** for existing build/package/release behavior.
- Actual native product CLI against independent Net-SNMP in **four configurations**:
  v1, v2c, v3 SHA-1/AES-128 and v3 SHA-256/AES-128. Each verifies the bounded probe,
  elapsed-time field, actual polling/persistence and rejection of wrong credentials.
- Actual browser interaction on the real Vue components with a **separate local
  synthetic server**: saved v3 editor, probe without approval, explicit draft
  adoption requiring new credentials, cancel without save, v1 community probe/
  save while trap secrets stay independent, custom receiver port 3162, receipt
  inspection, loopback/historical markers, event filters, default-off trap
  selection, English/German labels and viewer-only navigation. A manufacturer
  string containing an HTML image/handler remains text with zero injected image
  elements. The inspected 792-pixel viewport had no document horizontal overflow.

A redacted Gitleaks 8.30.1 audit covered **210 changed/non-ignored existing files**, including the retained vendor tree. No real secret was found. Six findings are the same four byte-verified public source hashes and two public RFC 3414 known-answer vectors documented in P4. Runtime/fixture state, screenshots and build outputs remain ignored.

Reproduce automated checks with the commands in [Development](DEVELOPMENT.md).
For interaction review run `node tools/snmp_p5_preview.mjs`, open
`http://127.0.0.1:5185/p5-preview`, or add `?role=viewer`. It binds loopback only,
mocks supported operations in disposable memory and records only action metadata
without secret values in `.build/snmp-p5/ui-requests.json`. It is not part of the
SPK, changes no product authentication path and sends no controller/mail requests.
Screenshots and logs are local ignored `.build/snmp-p5/` evidence.

These browser checks establish frontend interaction, not positive native DSM
login, real UDP binding, real controller payloads or production SMTP delivery.
Protocol evidence comes from the separate actual-product reference/authorization
tests and prior P3/P4 results. Static DSM packaging/version alignment remains P6;
actual NAS firewall, lifecycle, notification display and OEM fault/recovery
acceptance remain P7. Existing [P4 identity/coverage limits](SNMP-P4-RESULTS.md)
continue to apply; no hardware support matrix was widened by the UI.
