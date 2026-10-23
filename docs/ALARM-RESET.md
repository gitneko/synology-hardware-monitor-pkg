# Resetting a stored alarm

Build 0.8.0-0037 adds **Reset stored alarm ...** to independent hardware incidents in **Current & retained state alarms**. It is available to DSM administrators for both open and acknowledged incidents. Derived summaries are handled through their concrete causes; query/coverage alarms and hardware-log records are outside this operation.

Choose the incident, select **Reset stored alarm ...**, review the dialog and press **Reset alarm now**. Cancelling the dialog does not change anything. The action is bound to the selected device revision and incident token; background refreshes cannot silently retarget it. A changed, ended or replaced incident requires a fresh selection.

## What changes

- Only that resource's stored alarm state, its acknowledgement and its current trap-derived evidence are removed. Historical trap receipts remain; an old provisional trap cannot recreate the incident merely because a later poll is unknown.
- Current measurements, applicability reasons, device settings and monitoring remain unchanged. An absent PSU stays **Not present**, without inventing an OK reading.
- Existing event rows, timestamps, messages, SMTP recipient acceptance records and hardware logs are retained. The operator, resource and time are recorded in the audit log as an alarm reset.
- Pending automatic email/DSM desktop jobs for the resource, including proven canonical aliases, are cancelled transactionally. Their delivery reason identifies the reset. Already accepted messages cannot be recalled; an in-flight submission may finish before the reset obtains the shared submission gate.
- Explicitly requested manual replays of historical events remain independent and are not cancelled by resetting a hardware incident.

A new successful poll that still reports Warning or Critical creates a new unacknowledged incident with a fresh token and normal notification processing. Missing/Unknown/Absent measurements do not recreate the reset incident. Reset is an operator decision, not a recovery event and not an automatic rule for deleting old faults.

Other alarms remain active. A genuinely faulty summary is not cleared together with its cause; dangling grouping labels are removed from the current display and the next poll can announce the still-faulty summary independently. Separate unknown measurements or incomplete coverage can still make a device not fully assessable after the last stored warning is reset.

## Security and verification

The operation uses the existing native DSM administrator, HTTPS/origin, DSM-token and package-CSRF checks, plus explicit confirmation, device revision and incident token validation. It shares the email/desktop submission gate and uses a single immediate database transaction.

Tests cover retained absent alarms, unchanged history/measurements, independent incidents, restart, current and acknowledged faults returning at the next poll, stale/replayed requests, invalid scopes, derived summaries, canonical aliases, partial SMTP acceptance, independent manual replay, summary fallback and authenticated API/CGI forwarding. Frontend tests cover request shape, explicit confirmation, administrator/derived visibility and localized cancellation reasons.

No production alarm is reset simply by installing the update. Native NAS installation and acceptance of this build remain pending.
