# Deferred fix: warnings after disabling hardware-log reading

Status: **analysed and recorded; not implemented** (27 October 2026).
Dependency: implement **after the SNMP merge**, as requested by the user.
This record does not authorize changes to the current runtime or package build.

## Report and scope

The user reports that disabling hardware-log reading leaves these warnings in
the current/retained alarm list:

- `/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/FaultList/Entries`: HTTP 501.
- `/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries`:
  `Chronologische Hardwarelog-Auswahl vom Controller nicht unterstützt`.

The screenshot shows both as `Gespeicherter Fehler · aktuell nicht bewertbar`,
last observed on 27 October 2026 at 18:09:13. These are failures to query logs,
not evidence of a current hardware fault or the contents of hardware logs.
The controller's reason for HTTP 501 has not been established by a live probe.

## Source analysis

- `Collector::walk` in `src/collector.rs` skips log resources when
  `HardwareLogRead::Disabled` is selected. It does not emit replacement OK
  observations for the skipped resources.
- `Collector::poll_with_deadline` converts capability failures into Warning
  observations with keys `coverage:<resource URI>`. Chronological selection
  failures use `log_selection_unsupported`.
- The device-save path in `src/store.rs` detects a changed log policy but only
  resets `logs_initialized`. It does not retire the corresponding coverage
  alarm states or reconcile their pending notifications and snapshot entries.
- `alarm::reduce` only applies observations present in the new snapshot;
  `store::apply_observation` deliberately preserves faults on Unknown. Missing
  observations therefore leave their previous `alarm_state` rows intact.
- `Store::dashboard` returns non-OK stored alarm states and treats a missing
  current observation as Unknown. `alarmConfirmation` in `web/src/health.js`
  renders exactly the retained/unassessable message seen in the screenshot.
- `web/src/AlarmRow.vue`, `web/src/alarm-actions.js` and the backend hardware-key
  restriction in `src/acknowledgement.rs` exclude `coverage:` alarms from manual
  acknowledgement/reset. The normal reset action cannot resolve this case.

The preservation rule is appropriate for genuine hardware faults during lost
visibility. The missing piece is a separate lifecycle for query diagnostics
whose source has been intentionally disabled.

Evidence: current source review and the user's screenshot. No controller/NAS
reproduction or runtime test was performed for this analysis. Existing policy
checks in `tools/integration_test.py` verify that disabled mode skips log
requests, but do not check disabling after a persisted log-query warning.

## Planned correction

Reconcile log-query diagnostics when saving the disabled policy, without
waiting for a successful poll. Retire only coverage alarms belonging to log
resources of that device, using exact resource keys and the collector's log
resource classification rather than labels or a broad alarm deletion.

Reconcile the saved snapshot/capabilities, alarm-control state and pending
automatic SMTP/DSM desktop deliveries consistently. A previously stored
collector summary must not remain faulty solely because of the retired log
diagnostics; unrelated collection failures must remain visible. Do not claim a
measured hardware recovery or synthesize a hardware-recovery notification for
a configuration change. Preserve event history and imported hardware logs
under their existing retention rules, plus all real hardware/SNMP incidents
and their acknowledgement state.

Cover already-disabled devices carrying stale diagnostics after upgrade or
restore, and reactivation of log reading. Revision checks must prevent an
in-flight poll from recreating retired diagnostics. Check the related
Latest-N to All transition separately: obsolete selection diagnostics should
be reconciled against a fresh applicable query, not treated as hardware faults.

## Acceptance criteria for the later implementation

1. Persist both reported warnings, then disable reading: the log-query alarms
   disappear without a successful poll, including while the target is offline.
2. The result survives restart and covers an already-disabled device upgraded
   or restored with stale log-query diagnostics.
3. Pending automatic deliveries for retired diagnostics are cancelled; no false
   hardware-recovery event/notification is created. History remains available.
4. Independent hardware faults, acknowledgements, other query failures and SNMP
   trap/poll incidents remain unchanged. The overall assessment reflects the
   remaining applicable observations, including genuine Unknown states.
5. An old in-flight poll cannot recreate the retired alarms. Re-enabling reading
   allows fresh applicable failures to create warnings again, retaining the
   existing baseline/deduplication rules for imported logs.
6. Add focused store/API and frontend regression coverage, extend the collector
   integration scenario, then verify the reported transition on the NAS.

## Additional deferred UI fix: show log reading only for Redfish

Status: **source-reviewed and recorded; not implemented** (27 October 2026).
The user requested checking whether hiding this option for SNMP makes sense.
Recommendation: **yes, for the currently implemented collectors**. Implement
after the SNMP merge alongside the deferred log-query warning fix.

Evidence from the current code:

- `collect_with_runtime` in `src/collector.rs` selects exactly one primary
  collector. The Redfish collector receives `Device.hardware_log`; the SNMP
  `Poller::poll` receives SNMP `PollConfig`, credentials, revision and epoch,
  without the hardware-log policy.
- `src/snmp/profiles.rs` builds snapshots from `Snapshot::default()` and the
  current SNMP profile/poll paths do not populate `snapshot.logs`. They query
  hardware/system/network/UPS state, including applicable current alarm tables,
  rather than importing Redfish-style historical hardware logs.
- SNMP trap reception and cross-source event correlation are separate paths.
  References to `hardware_log` in SNMP correlation code do not implement log
  collection or make this reading option control traps.
- `web/src/DeviceEditor.vue` currently renders the reading mode, Latest-N count
  and retention/chronological-selection explanation unconditionally.
- `deviceForm`/`deviceInput` in `web/src/snmp.js` preserve and submit the policy
  for either primary protocol. `Device::validate` checks Latest-N limits for
  both protocols. Existing `web/tests/snmp.test.mjs` explicitly checks policy
  preservation alongside SNMP configuration; this is a compatibility detail,
  not evidence that SNMP uses the setting.

Planned behavior and acceptance:

1. Render the complete log-reading block (mode, count and explanation) only
   when `form.primary_protocol === 'redfish'`, including when changing the
   protocol within an open editor. Labels could clarify the Redfish scope.
2. Keep it visible for Redfish-primary devices with optional SNMP trap reception
   or an SNMP sender-verification target. Visibility must not depend on whether
   any SNMP configuration exists.
3. Keep SNMP trap controls, application-event history and global retention
   controls independent and operational for SNMP devices.
4. Preserve valid stored Redfish log preferences and same-dialog preferences
   when switching protocols; hiding the controls must not silently delete logs,
   change retention, disable traps or require a schema migration.
5. Check browser validation, `deviceInput` and backend validation together:
   hidden/unfinished Latest-N inputs must not block saving/testing an SNMP
   device. A later return to Redfish must again validate its active log settings.
6. Cover SNMP-only, Redfish-only, Redfish plus traps, edit/reopen and both protocol
   switches with focused frontend/form regression checks. No current runtime
   behavior or tests were changed for this source analysis.
