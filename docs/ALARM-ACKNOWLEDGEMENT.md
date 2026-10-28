# Acknowledging known hardware faults

Administrators can acknowledge current or retained hardware-state alarms. Open **Current & retained state alarms**, choose **Acknowledge …**, and enter a reason. The record applies to all users and suppresses automatic email, DSM desktop and webhook notifications for that incident. Acknowledged component and explained summary states appear blue; raw hardware health remains visible.

Acknowledgement has no expiry while the same fault persists and survives daemon restarts, monitoring pauses and package upgrades. It is an operator decision inside Hardware Monitor; it does not change the controller, its logs or the server display's Ignore setting.

## Lifecycle

- Confirmed OK closes the acknowledgement. The recovery stays in local history without additional email or desktop delivery. A later fault is a new unacknowledged incident.
- Worsening severity revokes acknowledgement and announces the fault again. A reduction from Critical to Warning keeps acknowledgement; a subsequent increase requires another acknowledgement.
- A new identifiable condition, worsening condition or change between two previously usable UUIDs/serials revokes acknowledgement. Build 0029 learns first available identity/condition details as a baseline; it does not interpret newly available data after power-on as a replacement or new fault. Missing/placeholder identities and missing condition details preserve the last usable fault baseline while the fault persists. Conditions are compared by message identifier, origin and severity. Human-readable text, timestamps, ordering and fluctuating message arguments do not define a new cause. Controllers without distinguishable conditions cannot support reliable detection of a new cause at unchanged severity.
- Unknown or missing readings never establish recovery. Retained acknowledged faults remain acknowledged; data freshness and independent query problems retain their significance.
- **Remove acknowledgement …** makes the fault actionable again. Fresh confirmed faults are announced once immediately. Old/unavailable data waits for a new valid poll, even when periodic reminders are disabled. Cancelled historical jobs are not replayed.

An administrator can acknowledge an independent summary alarm whose cause cannot be resolved further. A summary with known explanatory component faults must be acknowledged through those causes. Acknowledging a summary never acknowledges its descendants. If a lower-severity child fault appears later, the summary shows that open severity while preserving the acknowledgement of its own known fault. Its acknowledgement can still be removed independently.

## Summary and overall states

The backend evaluates acknowledgements separately from reported health and notification grouping. It follows explicit resource relationships and checks all known faulty descendants, including retained faults and lower-severity faults. An explained summary is acknowledged only when all relevant faults are acknowledged. Independent/unexplained conditions, missing origin evidence and cycles prevent automatic acknowledgement.

For example, an acknowledged Critical fan plus an open Warning drive produces an operative Warning system state, while preserving the raw Critical hardware summary and displaying the acknowledged fan. An independent unexplained Critical summary remains Critical. Stale devices remain Unknown, and incomplete assessment is not hidden by the blue status.

This is an assessment of known reported faults, not proof of complete physical causality. A hidden second cause that the BMC never reports individually cannot be reconstructed from an unchanged rollup. Hardware replacement cannot always be detected if the controller exposes no stable identity change.

## Delivery and history

Pending automatic email, desktop and webhook jobs for acknowledged components and fully acknowledged explained summaries are cancelled in the same database transaction as the operator action. SMTP recipients already accepted remain recorded. An in-flight submission may finish before the operation completes; once it succeeds, no new matching automatic submission starts. Already submitted email, DSM desktop or webhook notifications cannot be recalled. Local alarms and state events remain available; delivery reasons explain acknowledgement suppression separately from grouped summaries and event filters.

New manufacturer hardware-log entries are independent and continue to follow the configured filters. Query, TLS, authentication and coverage alarms cannot be acknowledged through this feature. Hardware-log records currently have no reliable component association, so their text is not used to guess whether they describe an acknowledged incident.

## Persistence, security and restore

Only DSM administrators can change acknowledgement, using the existing HTTPS/origin/session/CSRF checks. Viewers can inspect the status and reason. A version token binds every action to the selected alarm; changing or ending an incident invalidates stale actions. Opening the dialog captures that version so a background refresh cannot silently change its target. Operator actions and automatic invalidations appear in the audit log.

Acknowledgement records are keyed by device and canonical resource. Proven resource aliases can carry state forward; an already independent unacknowledged peer is not silently acknowledged. Retargeting or deleting a device removes its active records. Clearing event history preserves them.

Acknowledgement metadata was added in logical app backup format 3 and remains included in the current format 8. Earlier formats are migrated; see [Backup and restore](BACKUP-RESTORE.md). Restore preserves imported reasons/attribution for review, resets acknowledgement and version tokens, pauses monitoring/delivery and cancels historical jobs. Administrators must deliberately acknowledge imported faults again. The local SQLite/master-key upgrade backup preserves active acknowledgements as ordinary database state.

## Verification boundary

Automated local tests cover automatic email/desktop queues and webhook lifecycle cancellation, restart, recovery/reappearance, worsening, retained Unknown readings, mixed severities, independent summaries, condition/identity changes, version conflicts, reason bounds, permissions, aliases, retarget/delete, event clearing, archive migration/review/rollback and UI rendering. Local fake delivery acknowledgements prove queue decisions, not actual email receipt or DSM display. Acceptance on a NAS with a real faulty fan-sensor input remains required.

## Upgrade from build 0028

Build 0028 could revoke an acknowledgement of a retained fault made while the server was off when the first powered-on poll supplied identity or condition details. The audit reason was `Fehlermerkmale geändert`. Build 0029 corrects this comparison and preserves the acknowledgement across that transition. Acknowledgements already revoked by 0028 must be set again deliberately; the fix does not reconstruct and activate past suppression decisions from audit text.

## Resetting an incident

Build 0037 additionally supports removing an individual stored incident without deleting its event history. Unlike acknowledgement, reset removes the incident from the current alarm list and permits a still-reported fault to create a new incident on the next poll. See [Reset stored alarm](ALARM-RESET.md).
