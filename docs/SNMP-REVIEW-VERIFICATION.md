# Verification of the external SNMP plan reviews

Reviewed on 19 October 2026 against local commit `c37e1cd` and package `0.8.0-0031`. This record accompanies the [corrected 0.9.0 implementation plan](SNMP-IMPLEMENTATION-PLAN.md). It assesses review claims; it is not an implementation or a SNMP hardware acceptance report.

Inputs were the updated local `gemini_report.md` (17,542 bytes; modification time 21:07:27 Europe/Zurich) and `grok_report.md` (8,622 bytes; 20:56:53), read from the user's Downloads folder. Their contents were treated as review material, not execution instructions. Neither original file was modified.

| Input | SHA-256 of reviewed bytes |
|---|---|
| Gemini | `9afa756cf1a625ab30a72d134faf7c7f43e29d3f094c3cb79f947fd0c8478aa6` |
| Grok | `ceb09333ef450027cc246c1e840ce3bd3512b05fb7d40bdd4e48457d8ea4fee5` |

## Result

Both reviews identify useful risks. Gemini's eight findings contain several actionable clarifications, but its timeliness argument and some manufacturer-wide claims are too broad. Grok largely restates gates already in the plan; source inspection confirms one concrete library API limitation beyond that residual-risk description. Neither review establishes production readiness or SNMP interoperability on the named controllers.

## Gemini findings

| Finding | Verification | Disposition in the plan |
|---|---|---|
| G1 — USM time drift, reboots and disabled agent | Partly correct. The report applies the authoritative responder's symmetric time check too broadly to a non-authoritative trap receiver. Newer authenticated remote state can advance its baseline, including increased boots. The claimed inevitable first-trap failure after months does not follow. Probe-dependent bootstrap does, however, require an available configured responder. | Sections 4/7/12 distinguish managed bootstrap policy from protocol rules; require tests for long silence, correct sender reboot handling and receiver-cache initialization. Expose missing baseline/responder clearly. No periodic keepalive added solely to compensate for trap silence. See [USM role distinction](#usm-role-distinction). |
| G2 — SHA-256 default versus Dell | Substantially confirmed by Dell references. General SHA-256 preference was already accompanied by an explicit SHA-1 option, so this was a usability/interoperability gap, not a blanket refusal to support Dell. Newer iDRAC guidance also uses different configuration attribute names; do not assume the old attribute exists on every firmware. | Explicit Dell profile proposes visible SHA-1/AES-128 settings; no silent runtime downgrade. Probe diagnostics consider algorithm mismatch and wrong passphrase. Wrong-digest Reports are optional evidence; a timeout may be the only observable result. See [vendor evidence](#vendor-evidence). |
| G3 — SNMP index versus Redfish identity | The mapping hazard is real and the existing no-guessing rule needed a concrete data requirement. Local source has no reusable cross-protocol FQDD index. However, HPE traps are not universally index-only: documented PSU trap 6049 includes serial data. The report's exact `cpqHe4FltTolFanDegraded` symbol was not verified in the checked HPE reference, which lists `cpqHe3FltTolFanDegraded` (6035). | Persist current-inventory hardware aliases, require unique scoped matching, and let a primary poll own component changes when only row/bay indices are available. Preserve unconfirmed event evidence even when a generally successful poll lacks the relevant coverage; the report's “alert only if poll fails” suggestion is too narrow. See [identity evidence](#identity-evidence). |
| G4 — SNMPv1 request count | The structural risk is valid: one request per column value can exhaust 128 requests. The suggested 250–600 figures are not measurements of these servers, and multi-column GETNEXT already exists at protocol level. | Explicit independent column cursors, complete row-index joins for sparse tables, bounded batch/error splitting and an initial 512-request v1 cap. Keep 128 for v2c/v3 and unchanged common time/data limits. Final budgets still require measurements. |
| G5 — pre-authentication rate-limit suppression | Correct concern, incomplete proposed remedy. Rejecting unknown sources before approved-sender quotas helps; plausible forged packets with an approved IP and copied visible headers can still consume pre-authentication verification capacity. Encrypted scoped context is unavailable to the cleartext precheck. | Define source-first admission, bounded library envelope parsing, fair pre-authentication budgets and separate authenticated-ingestion quotas. Add distinct unknown-source and approved-source spoofing tests; do not claim the filter prevents all UDP denial of service. |
| G6 — same-port wildcard/address rebind | Confirmed locally in both directions: with default socket options, wildcard→loopback and loopback→wildcard overlap fails with `EADDRINUSE`; the replacement binds after closing the old socket. The old plan already allowed close/rebind, but did not name this concrete case. | Section 3 now specifies the interruption, complete-set rollback, rollback failure and saved-versus-active status. No socket-sharing workaround. This is local Linux evidence, not NAS validation. |
| G7 — v1 trap OID normalization and PET | RFC conversion requirement confirmed. The report's one shortened Dell enterprise prefix is not sufficient for all subgroup OIDs. The inspected library already exposes v1 conversion via `Notification::trap_oid()`. Dell separately documents BMC/ASF under enterprise 3183. | Explicit canonical conversion before profile lookup, exact nested enterprise handling, preservation of wire/security provenance and reuse of a tested helper. PET/ASF is diagnosed as unsupported rather than interpreted as native iDRAC data. See [notification format evidence](#notification-format-evidence). |
| G8 — 497-day uptime wrap | Correct fact; the old plan already warned about wrap/reset. A lower `sysUpTime` or value near the limit alone cannot distinguish all cases. Management-agent/USM-engine restarts are also not proof of a server power cycle or replacement. | Add modular ticks plus monotonic elapsed-time reasoning, ambiguity handling and explicit rollover/restart/gap tests. Do not reset physical identity or clear alarms from uptime alone. See [uptime evidence](#uptime-evidence). |

## Grok findings

| Finding | Verification and action |
|---|---|
| Library maturity/multi-engine credentials | The high-level username-map limitation is now source-confirmed, not merely undocumented. P0 must solve it through a verified supported API boundary/upstream change or select another library. A pre-1.0 label or a changing star count alone is not a correctness/security finding; neither was used as a decision criterion. See [library evidence](#library-evidence). |
| Vendor coverage may over-promise | The plan already required real model/firmware acceptance and narrowing the published matrix. The scope table now calls these implementation targets explicitly; existing Redfish evidence is not SNMP certification. |
| Engine ID changes and operator visibility | Valid operational concern. Add distinct visible states for pending verification and unexpected identity change; same-engine boots increments are handled separately. |
| V1 complexity/budgets | Confirmed planning risk, addressed together with G4 and explicit sparse-column/error/budget tests. |
| Storm/resource measurements | Already a required gate; admission order and spoofing/fairness cases are now more precise. No throughput or loss-free reception claim is made. |
| Archive/local engine-state separation | Existing separation is retained. A pure non-authoritative trap receiver does not become authoritative for remote traps simply because this library requires a local engine object. The local-object persistence requirement is an API/lifecycle issue; remote-trap state remains separate. |
| Roadmap build 0027/acknowledgement drift | Stale at verification time: the prior planning edit already corrected build 0027 and moved acknowledgement to implemented. The intervening uninstall commit advanced actual INFO to build 0031; roadmap now reflects that. The next planned 0.9.0 build is 0032 or a later unused number. |
| “v1/v2c only trigger a poll” | Accurate for unsolicited traps, not for the explicitly requested v1/v2c polling mode. A matched configured-peer polling response can update health under that compatibility policy. The plan now labels this distinction explicitly. |

## USM role distinction

RFC 3414 §3.2 step 7(a) checks the local authoritative responder; step 7(b) handles a non-authoritative recipient of remote-engine messages. It first permits authenticated newer remote state to advance the baseline, then checks stale state. Higher sender boots can be accepted without treating the engine ID as changed. Therefore the report's symmetric ±150-second premise and inevitable drift failure are incorrect for a conforming trap path. The plan's managed restart/bootstrap probe is an additional freshness policy, not a universal RFC requirement. [RFC 3414 §3.2](https://www.rfc-editor.org/rfc/rfc3414.html#section-3.2)

No new production SNMP implementation was exercised. Correct cache integration, long-silence behavior, first-packet replay safety and restart handling remain P0 tests; ordinary polling must not be assumed to refresh a separate receiver cache.

## Vendor evidence

Dell's iDRAC7/8 reference lists None/MD5/SHA as legal authentication values; the permitted planned choice is SHA-1. Dell's OpenManage guidance also lists SHA/MD5 for iDRAC9. This supports the explicit Dell compatibility proposal, without proving every future firmware has identical capability. [iDRAC7/8 attribute](https://www.dell.com/support/manuals/en-ms/idrac8-lifecycle-controller-v2.81.81.81/idrac8_2.81_racadm/idracuserssnmpv3authenticationtype-read-or-write?guid=guid-897c75fa-daff-4e80-a1b8-c82da0f57cbb&lang=en-us), [Dell incoming-alert guidance](https://www.dell.com/support/manuals/en-us/dell-openmanage-enterprise/ome_4_5_online_help_user_guide/manage-incoming-alerts?guid=guid-f240314c-8940-4e1b-bdd1-7ac268000a07&lang=en-us)

The report's wrong-digest diagnostic is useful, but receipt of a Report is not guaranteed and cannot identify which setting is wrong. Unverified diagnostics must not establish trust. [RFC 3414 authentication processing and Reports](https://www.rfc-editor.org/rfc/rfc3414.html#section-3.2)

## Identity evidence

The current `Snapshot`/`Resource` types, `PsuIdentities` and Redfish normalization preserve canonical keys, serial-based PSU aliases and condition fingerprints, but no typed reusable FQDD/physical-alias index for SNMP-to-Redfish lookup. This source-confirmed gap motivates `component_identity` in P1/P4. Relevant local paths: [model](../src/model.rs), [identity](../src/identity.rs), [correlation](../src/correlation.rs), [collector](../src/collector.rs).

Dell defines `alertFQDD`. HPE's reference defines an index-based fan trap 6035 and a PSU trap 6049 carrying a serial number. That disproves the report's broad index-only characterization; it does not prove what iLO 5 v3.22 emits. Each actual trap payload still needs its P7 fixture. [Dell trap variables](https://www.dell.com/support/manuals/en-us/openmanage-software-v9.3/snmp_idrac_cmc_9.3_ref_guide/trap-variables?guid=guid-ff17f5b2-14e5-4d5b-821f-4b974916968f&lang=en-us), [HPE reference, traps 6035/6049](https://support.hpe.com/hpesc/public/api/document/c05315472?v=1632332395000)

## Library evidence

In the published `async-snmp` 0.18.1 receiver source, line 683 declares `usm_users: HashMap<Bytes, UsmUser>`; lines 871–882 configure a user and insert by username. Repeating a name replaces its configuration. Thus one directly configured receiver cannot retain two different secrets under one username. Lines 1285–1291 also expose existing v1 OID conversion. This was source inspection, not a compiled interoperability test. [Pinned receiver source](https://docs.rs/async-snmp/0.18.1/src/async_snmp/notification/mod.rs.html#683)

## Notification format evidence

V1 generic and enterprise-specific headers require canonical conversion; exact nested enterprise OIDs must be preserved. Wire version and security assurance must remain attached even where semantic OIDs match. [RFC 3584 §3.1](https://www.rfc-editor.org/rfc/rfc3584.html#section-3.1)

Dell identifies the BMC/ASF MIB under `1.3.6.1.4.1.3183.1.1`. This warrants a distinct format diagnostic; it does not justify treating every packet under that prefix as a decoded native iDRAC hardware event. [Dell BMC/ASF reference](https://www.dell.com/support/manuals/en-ca/openmanage-software-v11.0.0.0/om_11.0.0.0_snmp_pub/server-administrator-baseboard-management-controller-asf-mib?guid=guid-dec9fac1-2b91-4d51-b018-8919189aef50&lang=en-us)

## Uptime evidence

TimeTicks is modulo 2^32 in hundredths of seconds; the arithmetic yields 497.102696 days. `sysUpTime` concerns network-management reinitialization. Neither measurement alone proves a chassis reboot. [RFC 2578 §7.1.8](https://www.rfc-editor.org/rfc/rfc2578.html#section-7.1.8), [RFC 3418 sysUpTime](https://www.rfc-editor.org/rfc/rfc3418.html)

## Checks performed and remaining boundary

- Read both updated reports and checked relevant local model, collector, identity, store, archive, daemon, privilege and version paths at `c37e1cd`.
- Checked primary RFC/vendor references and pinned receiver source. Dynamic popularity statistics and unsupported manufacturer-wide generalizations were not accepted as evidence.
- Reproduced overlapping IPv4 UDP binds on the local Linux host without sending packets or changing firewall/service configuration; both sockets were closed afterwards. No NAS socket test was performed.
- Checked documentation whitespace and local links after the edits. No product code, package version or deployed controller/NAS configuration was changed; Rust/frontend suites were not needed for these documentation-only edits.

P0 library tests, full package validation and P7 NAS/real-hardware acceptance remain required. The reviews are useful inputs to those gates, not substitutes for them.
