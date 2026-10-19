# Notification channels and event selection

Hardware Monitor supports its own SMTP email client and independent native DSM desktop notifications. Both channels require global enablement, matching event filters and the per-device **Enable notifications for this device** option. Monitoring must also be enabled on the device. Events remain visible locally when delivery is disabled or filtered.

The shared filters cover critical events, warnings, query warnings/failures, recoveries, reminders and new hardware-log entries. Hardware alarm reminders and hardware logs additionally need their severity selected. Recovery selection is independent of the severity switch. Reminder intervals are configured per device and must be at least five minutes.

## Delivery behavior

Each channel has a durable queue. SMTP has separate recipient progress and stable message IDs for retries. Bounded retries distinguish transient failures from permanent rejections. Failure of the desktop command does not prevent the SMTP worker from processing its queue, although the bounded sequential worker can introduce a short delay.

Saving channel/filter settings cancels pending jobs for both channels; saving SMTP settings cancels pending email jobs. Pausing, disabling notifications, deleting or retargeting a device cancels affected pending jobs. Already submitted messages cannot be recalled. Enabling delivery never replays all historical events.

The event table distinguishes locally stored, filtered, grouped, queued, cancelled, failed and submitted states. SMTP acceptance is not inbox delivery. A native command's zero exit status is not proof of a displayed notification. Historical events are not necessarily current hardware faults; use the current/retained alarm panel for state.

## Languages and timestamps

Save the desktop language independently of the email language. Interface language does not silently change background settings. Existing templates remain unchanged; explicit default-template replacement is available. UI dates use the selected interface locale and browser time zone. Email/CSV local timestamps use the configured IANA zone and date format, including daylight saving time. `{{time}}`/`{{time_local}}` are local; `{{time_utc}}` is UTC; `{{timezone}}` names the configured zone.

The user confirms a Gmail test email, automatic reminder email, desktop test and a critical desktop reminder with resolved details/error level on DSM 7. The initially missing reminder email was caused by the device delivery option being disabled, not by a failed queue. English paths introduced in build 0017 remain to be accepted. See [SMTP](SMTP.md), [Desktop notifications](DESKTOP-NOTIFICATIONS.md) and [Alarm grouping](ALARM-GROUPING.md).

Build 0025 adds **Query warnings** as an independent selection for both email and DSM desktop. It covers the event log's monitoring category: collector failures and incomplete coverage, including warning and critical query results. Enabling it does not require the hardware Warning/Critical switches; disabling it suppresses query alarms, repeats and recoveries. Query repeats additionally require Reminders and query recoveries require Recoveries. Vendor hardware-log entries retain their own category and filters. Local event history is unaffected.

Existing settings without an explicit query choice retain their precise severity-based behavior on upgrade. The new checkbox initially reflects whether either severity was selected. Saving the form makes the visible query choice explicit and applies the independent behavior. Reading the form does not rewrite settings, and enabling it does not replay old events. Device and channel enablement still apply.

Build 0028 adds [operator acknowledgement](ALARM-ACKNOWLEDGEMENT.md). Acknowledging a hardware fault suppresses both channels and cancels its pending submissions, including explained acknowledged summaries. Recovery for that acknowledged incident remains local. Hardware logs and query problems are independent. Already submitted messages cannot be recalled; partial SMTP recipient progress remains visible.
