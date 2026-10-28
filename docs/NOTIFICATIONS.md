# Notification channels and event selection

Hardware Monitor supports SMTP email, independent native DSM desktop notifications and [outgoing HTTP/HTTPS webhooks](WEBHOOKS.md). All automatic channels require monitoring and **Enable notifications for this device** on the device. Events remain visible locally when delivery is disabled or filtered.

SMTP and DSM desktop have separate global enablement and share an event selection. Every webhook destination has its own enabled state, event selection, optional device selection and language; SMTP/desktop filters do not restrict webhook delivery. An empty webhook device selection permits all devices whose monitoring and notifications are enabled.

## Event selection

Selections cover critical events, warnings, query warnings/failures, recoveries, reminders, new hardware-log entries and a default-off **Verified SNMP trap events without component mapping** choice. The latter permits only verified known event-only faults and still requires the matching severity; tests, unknown OIDs, unverified input and recovery hints do not automatically notify. Mapped traps use the regular hardware alarm filters and canonical transition pipeline. Settings/archives without this choice default it to off.

Hardware alarm reminders and hardware logs additionally need their severity selected. Hardware recovery selection is independent of the severity switch. Reminder intervals are configured per device and must be at least five minutes.

**Query warnings** covers collector failures and incomplete coverage, including warning and critical query results. Enabling it does not require the hardware Warning/Critical switches; disabling it suppresses query alarms, repeats and recoveries. Query repeats additionally require Reminders and query recoveries require Recoveries. Vendor hardware-log entries retain their own category and filters. Existing settings without an explicit query choice retain their precise severity-based behavior on upgrade; saving the selection makes the visible query choice explicit.

## Delivery behavior

Each channel has a durable queue. SMTP has separate recipient progress and stable message IDs for retries. Bounded retries distinguish transient failures from permanent rejections. Failure of the desktop command does not prevent the SMTP worker from processing its queue, although the bounded sequential worker can introduce a short delay. Webhook workers run independently and track acceptance, retry, cancellation and terminal failure per destination.

Saving SMTP/desktop channel or shared filter settings cancels pending jobs for those two channels; saving SMTP settings cancels pending email jobs. Saving or deleting a webhook destination cancels that destination's pending jobs. SMTP/desktop settings do not cancel webhook work. Pausing, disabling device notifications, deleting or retargeting a device cancels its affected pending deliveries. Already submitted messages cannot be recalled. Enabling delivery never replays all historical events.

[Operator acknowledgement](ALARM-ACKNOWLEDGEMENT.md) suppresses automatic notifications for the acknowledged hardware incident and explained acknowledged summaries, and cancels their pending work across all three transports. Recovery for that acknowledged incident remains local. Hardware logs and query problems are independent. Partial SMTP recipient progress remains visible.

These rules apply to automatic notifications. Separately confirmed [manual email replay](MAIL-REPLAY.md) is independent of device/filter/acknowledgement gates, has its own durable job and history, and sends to one selected saved recipient. It creates no desktop or webhook notification. SMTP changes, event-log clearing and archive restore also invalidate or cancel relevant manual work.

## Event history

The event table distinguishes locally stored, filtered, grouped, queued, cancelled, failed and submitted states. Channel and webhook-destination entries are separated by a middle dot. Each active webhook records “excluded by device selection” or “excluded by event filters” when applicable, including when every destination excludes delivery. Device selection takes precedence when both exclude it. These reasons are fixed at event time, consume no pending queue capacity and survive later settings changes. Disabled webhook destinations are omitted; older history is not backfilled.

When the device notification switch is off, the event log says **Notifications disabled for this device**, since the restriction covers all automatic channels. Already accepted deliveries remain visible. SMTP or HTTP acceptance is not proof that a recipient read a message. A native command's zero exit status is not proof of a displayed notification. Historical events are not necessarily current hardware faults; use the current/retained alarm panel for state.

## Languages and timestamps

Email, desktop and each webhook destination have independent saved message languages. Interface language does not silently change background settings. Existing templates remain unchanged; explicit default-template replacement is available. UI dates use the selected interface locale and browser time zone.

Email/CSV local timestamps use the configured IANA zone and date format, including daylight saving time. SMTP `{{time}}`/`{{time_local}}` are local; `{{time_utc}}` is UTC and `{{timezone}}` names the configured zone. Webhooks instead use Unix seconds in `{{created}}` and UTC ISO format in `{{time}}`. Webhook preview and manual tests use the destination language; generated text is localized while real device names, vendor text, custom literals and machine-readable values are preserved.

The user has confirmed Gmail test/reminder email, desktop test/critical reminder with resolved details/error level on DSM 7, and functional testing of the outgoing webhook implementation. The reported coverage and additional deployment checks are recorded in [Validation](VALIDATION.md) and [NAS acceptance](NAS-ACCEPTANCE.md). See also [SMTP](SMTP.md), [Desktop notifications](DESKTOP-NOTIFICATIONS.md) and [Alarm grouping](ALARM-GROUPING.md).
