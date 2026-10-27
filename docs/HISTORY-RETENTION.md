# History retention and cleanup

Starting with build **0.8.0-0042**, administrators configure two independent policies on the **Backup** page under **Retention & cleanup**:

| Setting | Default | Meaning |
|---|---|---|
| Event history retention | 90 days | Remove recorded application events older than the cutoff, including their terminal delivery history. |
| Hardware log retention | 90 days | Remove imported controller log entries older than the cutoff, independently of the number requested from the controller. |

Each accepts whole days from 0 to 36,500. **0 means unlimited** for that policy. Existing installations receive these defaults on upgrade. Settings are included in encrypted app backups. Saving a policy does not immediately delete data. Shortening a period makes more records eligible at the next cleanup; increasing it cannot recover deleted application events. Controller log entries may be read again if the controller still has them. Widening the hardware-log window establishes a new baseline so these historical entries do not generate new alerts.

The first automatic cleanup is scheduled 24 hours after installation or upgrade to this build, giving administrators time to back up the existing history and review the new rules. After each successful automatic run it is scheduled again in 24 hours. The deadline persists across service restarts; a restore also starts a fresh 24-hour review window. The service checks due work every minute. This does not require DSM Task Scheduler or an external cron job. It runs even if every device is paused or hardware-log reading is disabled. Only one backup, inspection, restore or cleanup worker runs at a time; a busy automatic run is retried after a minute.

For immediate cleanup, save the rules, choose **Check cleanup**, review the event/hardware-log counts, then choose **Clean up now** and confirm. The preview is valid for 15 minutes and only for its saved policy revision. Counts can change as polling and deliveries continue. Progress and cancellation are available. Cleanup commits small batches: cancellation stops further work but does not undo records already removed. A policy change interrupts a running cleanup before its next batch. Administrative policy changes and cleanup outcomes are recorded in the audit log.

## Which time is used?

Event age uses the app's UTC creation time. Hardware-log age uses the controller's `Created` value, parsed as an RFC 3339 timestamp, including its time-zone offset. The age is measured against the current NAS time; there is no midnight/calendar-day rounding. Missing or invalid dates and timestamps in the future are preserved. The preview reports logs without a reliable past timestamp separately. Check controller and NAS clocks if unexpected logs remain.

The retention rule also filters newly received hardware logs before storing them or generating events. Therefore a five-year-old log will not be imported again at the next poll after cleanup. In All available mode, a log with no reliable timestamp remains eligible for import and is protected from time-based deletion. Newest N cannot place undated entries chronologically and reports them as an incomplete selection. Old log details are also removed from retained device snapshots; current observations and alarm states are preserved.

## Reading logs versus retaining them

[Device settings](DEVICE-MANAGEMENT.md#hardware-log-reading) control whether to read hardware logs and how many to request: disabled, all available, or newest N. This is independent of retention:

- A limit of 100 does not trim the database to 100 records. Newer records accumulate over successive polls until their retention age expires.
- Disabling reading stops future collection, while existing entries remain subject to the global hardware-log retention period. Stored warnings about querying those disabled log resources are retired immediately, along with their pending automatic notifications; this does not remove hardware faults, event history or imported logs.
- Reading all available logs does not override the retention cutoff.

Hardware logs are separate from application events generated from them. Deleting an old hardware-log row does not independently delete its application event; the event policy decides that event's lifetime.

## Preserved state and storage

Time-based cleanup preserves current hardware alarm states, acknowledgements and pending automatic email/desktop or queued manual email submissions. Old events with pending work remain until delivery is terminal or cancelled. This differs from explicitly clearing the event log, which cancels pending event deliveries.

The **audit log keeps the newest 10,000 entries**, irrespective of either age setting; the interface shows the most recent 50. The 10,000-entry cap is fixed, rather than a third age setting.

SQLite reuses freed pages. Deletion usually reduces future growth and backup content without immediately shrinking `monitor.db` on disk. Cleanup does not run a blocking `VACUUM`. Sufficient free disk space is still required for SQLite transactions, snapshots and restore staging. Use a complete backup if deleted history must remain available elsewhere.

## Event count and display window

Starting with build 0.9.0-0063, the Events navigation counter is the total number
of retained event records. It is not an unread counter. The dashboard still
loads only the latest 100 event records; grouping and filters determine how
many messages are displayed from that window. The header labels these values
separately. Retention cleanup and clearing the history decrease the stored
total, while CSV export continues to include the full matching retained history.

## SNMP diagnostic bounds

Event-only `snmp_trap` history also has a fixed seven-day/10,000-row bound;
normalized trap receipts have their own seven-day/10,000-row cap. General event
retention can expire eligible events earlier, but `0` does not disable these
SNMP-specific limits. Pending delivery/replay protection still applies. Mapped
state-alarm events use normal event retention; pruning never clears retained
hardware faults. See [SNMP diagnostic event retention](SNMP.md#diagnostic-event-retention).
