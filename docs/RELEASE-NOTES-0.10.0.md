# 0.10.0 — Outgoing webhooks

Hardware Monitor adds independently configurable outgoing HTTP and HTTPS notifications alongside SMTP email and DSM desktop notifications. Administrators can configure up to 16 destinations with their own device/event selection, language, authentication, headers and optional HTTPS CA bundle. New or re-enabled destinations send future events only.

## Message formats and configuration

Destinations support generic event JSON, custom JSON, text, URL-encoded forms and multipart text fields. Repeated form field names are preserved. Templates use validated event placeholders; JSON preserves the types of complete-value placeholders and escapes embedded text. Preview renders redacted sample data without sending, while the test action sends a real sample in the destination's selected language.

Discord and Slack support editable message text. Discord additionally supports rich embeds, an optional sender name and avatar URL. Modern Slack incoming webhooks use the app's configured identity. Local image uploads and file attachments are outside this release.

Full destination URLs and marked secret headers/form values are encrypted and omitted from ordinary dashboard responses. Administrators can explicitly show and hide a saved URL to verify it. HTTP and HTTPS are supported; HTTPS validates certificates and hostnames. Private/local network destinations require an explicit per-target option. Requests validate resolved addresses, do not follow redirects and do not use environment proxies.

## Delivery and event history

Persistent per-destination queues run independently from SMTP and DSM desktop delivery. Bounded retries, HTTP rate-limit delays, stable delivery IDs and per-device/resource ordering support temporary failures without blocking other destinations. Alarm acknowledgement, reset and device/query lifecycle changes cancel affected pending jobs. A successful response records recipient acceptance; it does not establish that a person read the message.

The event log separates channel and destination statuses with a middle dot. Each active webhook records acceptance, retries, cancellation, failure or its selection exclusion. “Excluded by device selection” and “excluded by event filters” remain visible even when all destinations exclude delivery. Exclusion reasons are fixed at event time and survive later configuration changes; they create no sendable work. Existing historical events are not backfilled. The device notification switch is described as applying to all automatic notification channels.

## Backup compatibility

Logical archive format 8 includes webhook configuration, encrypted secrets and delivery history. Supported formats 1–7 remain readable. Restore re-encrypts secrets, advances destination revisions, pauses delivery and cancels imported pending work. Explicit reactivation sends future events only. Older application versions cannot read format 8; DSM package downgrade is not a supported migration path.

## Validation

The user confirmed functional testing of the outgoing webhook implementation. Automated source, UI, local HTTP/HTTPS, archive and package checks are recorded in [Validation](VALIDATION.md#outgoing-webhooks-0100); the report's coverage and further deployment evidence are distinguished in [NAS acceptance](NAS-ACCEPTANCE.md). Configuration, limits and lifecycle rules are documented in [Outgoing webhooks](WEBHOOKS.md).
