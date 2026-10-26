# Resend a recorded event by email

Use **Events → Resend email …** to test an alarm server's text processing with a recorded event, without reproducing the hardware fault. DSM administrator access is required. The action is also available for recovered, acknowledged, filtered and local-only events, including retained events for a removed device.

1. Save the desired SMTP settings and template under Notifications first.
2. Select one of the saved recipient addresses. The first saved address is initially selected; the action never sends to the entire list.
3. Create a delivery preview. It renders the original event data with the currently saved email template, language and time formatting. Unsaved editor changes are not used.
4. Review the subject, body and recipient, then choose **Send once to selected recipient**.
5. Review **Manual submission history** in the same dialog. It records the operator, recipient, queue time, SMTP acceptance time, attempts and fixed error category separately from the original event's delivery status. The dialog refreshes this history while open; the audit log also records intentional submissions and their outcomes.

The preview is valid for ten minutes. Changing SMTP settings invalidates previews and cancels pending manual submissions, so a displayed preview cannot silently be sent through changed settings. The confirmed content is frozen; inserted text is never evaluated again as a template. To intentionally send another copy, create a new preview. Reconfirming the same preview, including after a lost response or restart, refers to the same durable job.

Manual submission does not change alarm state, acknowledgement, event ID, event time, event type or original delivery progress. It creates no new hardware event and sends no DSM desktop notification. Automatic channel enablement, device notification options, event filters, summary grouping and acknowledgement suppression do not block an explicitly requested manual email. The configured SMTP credentials and TLS validation still apply.

No `TEST` marker or other replay label is added to the subject or body. Every intentional new job receives a new email Message-ID; bounded technical retries of that job keep its Message-ID and previewed content. An alarm server deduplicating by original event ID or event time may ignore a replay. A mode that fabricates a new event is not implemented.

SMTP acceptance does not establish delivery or parsing in the alarm server. As with ordinary SMTP, a connection loss after acceptance can leave an ambiguous result; stable Message-IDs assist deduplication but do not guarantee exactly-once delivery. Permanent rejections stop retries; transient errors use the existing bounded backoff (at most eight attempts).

The dialog shows the latest 50 manual submissions for its event. Clearing the event log removes associated manual history and pending jobs together with the original events; the audit log remains. Manual history was added in encrypted archive format 4 and is included in current format 6; restore cancels pending jobs and discards drafts rather than resuming them. Saving automatic notification filters or acknowledging a hardware fault does not cancel separately requested manual jobs.

The UI groups some equivalent raw event representations. The replay dialog displays the exact original event ID used for the email; it does not send every grouped representation.
