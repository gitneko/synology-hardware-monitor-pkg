# Log-query warnings and Redfish-only log settings

Status: **implemented, locally validated and user-confirmed on the NAS**
(27 October 2026, **0.9.0-0065**). The user confirms installation and both
reported fixes: query warnings disappear when log reading is disabled, and
log controls appear only for Redfish, including Redfish with optional SNMP traps.

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

## Source analysis before the fix

The following describes the original failure path.

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

Initial evidence was source review and the user's screenshot. The new
regressions now exercise the original failure with synthetic local data; no
controller/NAS reproduction is claimed.

## Implemented correction

`src/log_query.rs` retires exact log-coverage keys, using the collector's shared
log-resource classification. Device save reconciles them in the same transaction
as the configuration update, without waiting for a new poll. Startup and both
archive restore paths also reconcile already-disabled Redfish devices.

The saved capabilities/observations, corresponding alarm-control rows and pending
automatic SMTP/DSM desktop jobs are reconciled. A collector summary caused only
by the removed log failures is retired; independent coverage failures and a
later Critical connection failure remain visible. Completed deliveries, manual
mail replay, event contents, imported logs, hardware/SNMP incidents and their
acknowledgement state are preserved. Configuration changes do not create recovery
events or claim a new measurement. Cancellation explanations are bilingual.

Existing revision/epoch checks reject an old in-flight poll after device save or
restore. Re-enabling reading accepts fresh query failures and retains the normal
log baseline/deduplication rules. Changing Latest-N to All waits for a fresh
applicable query: old query-parameter variants are retired only when that same
resource succeeds with no contradictory failure in the current snapshot.

## Acceptance criteria

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

## Additional UI fix: show log reading only for Redfish

Status: **implemented, locally validated and user-confirmed on the NAS**
(27 October 2026, **0.9.0-0065**).
The current SNMP collector does not use the Redfish log-reading policy.

Source analysis before the UI fix:

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
- `web/src/DeviceEditor.vue` previously rendered the reading mode, Latest-N count
  and retention/chronological-selection explanation unconditionally.
- `deviceForm`/`deviceInput` in `web/src/snmp.js` preserve and submit the policy
  for either primary protocol. `Device::validate` checks Latest-N limits for
  both protocols. Existing `web/tests/snmp.test.mjs` explicitly checks policy
  preservation alongside SNMP configuration; this is a compatibility detail,
  not evidence that SNMP uses the setting.

Implemented behavior and acceptance:

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
   switches with focused frontend/form regression checks.

## Local validation and NAS confirmation

Eight new backend/API regression tests cover retirement, queue cancellation,
completed delivery, acknowledgement/history preservation, exact resource/device
scope, overall assessment, offline failure preservation, stale polls,
reactivation, startup, both restore paths and successful query replacement.
Frontend regressions cover Redfish/SNMP with and without traps, preserved log
preferences, hidden unfinished counts and cancellation explanations.

The extended `tools/integration_test.py` runs the actual CLI collector against a
local TLS Redfish server. It creates unsupported chronological selection and HTTP
501 failures, disables collection without polling, checks alarm/history/hardware
preservation, verifies no further log requests and checks Latest-N to All after
fresh success. The full Rust/frontend tests, frontend build, formatting, clippy
and maintained-documentation link checks pass: 254 Rust tests and 78 frontend
tests succeed. The existing multi-GiB archive acceptance test remains explicitly
ignored; the ignored protected-daemon fixture runs through its parent test.

The user confirmed NAS installation and testing of both reported fixes in
0.9.0-0065 on 27 October 2026. This closes the reported warning-removal and
Redfish-only control workflows. It does not independently confirm every
startup/restore, queue-cancellation or controller/firmware variant; those paths
retain their local regression evidence unless separately reported.
