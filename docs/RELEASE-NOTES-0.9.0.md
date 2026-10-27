# 0.9.0-0065 — Hardware-log query corrections

Unsigned DSM 7 x86_64 package with explicit SNMP polling and optional traps
alongside Redfish. See [SNMP setup and limitations](SNMP.md),
[Compatibility](HARDWARE-COMPATIBILITY.md) and [Validation](VALIDATION.md).

## Build 0065

- Disabling Redfish hardware-log reading immediately retires its stored query
  warnings and pending automatic notifications, including old states at startup
  and restore. Hardware/SNMP faults, acknowledgements and history are preserved.
- Keep independent connection/coverage failures visible; configuration changes
  do not create measured recoveries. Fresh applicable queries can replace stale
  chronological-selection diagnostics after switching to All available.
- Show log-reading controls only for a Redfish primary, including Redfish with
  optional SNMP traps. Preserve saved preferences across protocol changes and
  prevent unfinished hidden log counts from blocking SNMP device saves.
- Regression coverage includes the actual collector against synthetic HTTP 501
  and unsupported-selection responses. Installation and both reported fixes are
  user-confirmed on the NAS (27 October 2026); see the
  [implementation and validation record](LOG-QUERY-WARNINGS-FOLLOWUP.md).

## Build 0064

- Align the event-retention note with the panel title and action buttons.
- Add space between saved-sender verification and the polling-interval field.
- Consolidate SNMP setup/profile/security/diagnostic guidance; replace temporary
  phase/review/result reports with maintained documentation and descriptive
  reference-tool names. Validate local links/anchors in source and the SPK.
- Restore the regular polling cadence in the receiver load fixture after its
  deliberately day-long clock-compatibility case; keep the automatic-poll load
  assertion intact. Runtime application behavior is unchanged.
- Record duplicate handling as user-accepted, completing the reported core SNMP
  workflow. UPS profiles remain explicitly untested on real hardware.

No primary-protocol selector, alarm, polling or cryptographic behavior changes
in this build. Local UI checks do not claim a new native DSM visual acceptance.

## SNMP features and corrections

- One selected Redfish or SNMP primary. Explicit v1/v2c compatibility or v3
  authPriv, SHA-1/SHA-256 and AES-128; no automatic security downgrade.
- Generic availability, Network Generic interface discovery, Dell iDRAC,
  HPE iLO, Synology DSM and APC/Eaton/RFC 1628 UPS polling profiles. Missing or
  partial evidence stays explicit; profile OK covers only its assessed scope.
- Independently configured traps with exact source IPs, separate credentials,
  reviewed v3 sender engine and optional context filters. Empty trap context
  fields impose no additional filter; sender authentication remains required.
- Default local UDP 1162, configurable port/address. Standard UDP 162 uses the
  bundled [administrative capability helper](TRAP-PRIVILEGED-PORTS.md), never a
  root service or automatic installer privilege request. Reapply after binary
  replacement if needed. Bind permission failures show an amber setup warning.
- Prominent missing-v3-identity guidance, saved-target identity review, detailed
  rejection counters, separate binding/verification/freshness diagnostics and
  bounded normalized receipts without packet/credential logging.
- Verified uniquely mapped v3 faults can immediately raise provisional alarms.
  Sequence barriers stop old in-flight OK from clearing newer evidence. Fresh
  covering primary reads own recovery; unknown input retains faults.
- Repeated fault plus confirming poll shares the incident/notification. New
  faults after recovery remain new incidents. Similar native logs and traps
  are not merged without positive unique occurrence proof.
- Explicit default-off clock compatibility handles the reported iDRAC backwards
  trap boots as authenticated polling hints only. Live reception/timestamp is
  prominent, with unconfirmed freshness; no normal receipt or direct alarm is
  produced by such a hint. Strict replay state remains unchanged.
- HPE explicit empty-population handling, persistent removal history,
  firmware-aware fan units and power/storage context. Empty storage cannot
  assert health. Existing `hpe_ilo5` saved profiles remain valid.
- Synology partition/power/fan/disk/RAID polling; no DSM trap support. Network
  profiles arm previously active links and expose safe two-sample rates without
  invented thresholds. UPS states and measurements retain MIB-specific units.
- German/English editing, independent secret actions, event-only default-off
  notification filter and source/verification/provisional provenance in history,
  CSV and optional template fields. Existing delivery filters remain intact.

## Events counter (0063)

The sidebar now counts all retained events instead of the grouped latest-100
list. The header distinguishes displayed messages, stored events and the
latest-100 selection. This is stored history, not an unread counter. Retention,
full-history CSV, alarms and notifications keep their existing semantics.

## Accepted scope

User confirmations cover Synology DSM, HPE iLO, Generic/Network operation,
Dell v3 traps/direct alarms/configured notifications, reception after package
and DSM restart, wrong credentials/unknown sender/changed-ID configuration
checks, fault → recovery, acknowledgement and duplicate handling. Upgrade
**0.8.0-0043 → 0.9.0-0062** and app backup/restore are confirmed.

**APC, Eaton and RFC 1628 profiles ship untested on real UPS hardware**, by
explicit agreement because suitable hardware is unavailable. Local synthetic/
reference results do not claim device/card/firmware interoperability. Confirmed
results do not certify all firmware/security or physical-fault combinations.

## Upgrade and restore

Retain an encrypted app backup and its password before upgrading. Schema-1
migration to schema 2 is transactional and preserves Redfish state/settings/
acknowledgements. Private synced database/key pre-migration copies are retained
for recovery/diagnosis. Post-install explicitly initializes state; readiness
allows 120 seconds with bounded startup contention instead of the former
five-second startup failure.

Current logical archive format is **7**, with supported older-format conversion.
Restore re-encrypts credentials under the destination key, pauses devices/traps/
listener/channels, invalidates stale work and cancels old pending deliveries.
Local authoritative engine files and live clocks are not replayed. An old app
cannot open the new schema or read the new archive. DSM Package Center downgrade
to 0.8.0 is outside the supported path; no manual downgrade procedure is offered.
See [Backup and restore](BACKUP-RESTORE.md).

## Limits and remaining work

No Inform ACKs, BMC/ASF PET decoding, proxy context-engine routing, SNMP SET,
power control, arbitrary MIB imports, simultaneous dual primaries or trap-only
healthy-state assessment. HPE index-only traps lack a general Redfish crosswalk.
Reference load/corpus checks do not certify complete UDP DoS resistance or NAS
capacity. Full native DSM Application Privileges/viewer menu integration remains
separate. The log-query-warning and Redfish-only log-controls corrections are
implemented and user-confirmed in 0065; see the
[validation record](LOG-QUERY-WARNINGS-FOLLOWUP.md).

Build tools retain static executable/protocol/lifecycle/version/source-identity
checks and dependency licenses. Local validation does not claim a hosted CI run
or publication; review checked assets and audit secrets before commit/push.
