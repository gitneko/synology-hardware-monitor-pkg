# Outgoing webhooks

Administrators configure up to 16 independent destinations under **Notifications → Outgoing webhooks**. Each destination has a name, enabled state, language, device filter and event selection. Saving a destination never sends existing history. The device must also have monitoring and notifications enabled. SMTP/DSM desktop event filters do not restrict webhook selection.

## Destination and authentication

Both HTTP and HTTPS are supported, including paths and query parameters. URL credentials and fragments are rejected. The complete URL is stored encrypted and is omitted from normal dashboard responses; the editor initially displays only its origin. Administrators can explicitly choose **Show URL** to retrieve and verify a saved address; this separate operation requires the current revision and CSRF token. **Hide URL** masks the field again. Opening another editor resets visibility. Leave its input empty to retain the saved address.

HTTPS verifies certificates and hostnames. A custom CA bundle may be configured. There is no insecure-certificate mode or automatic downgrade to HTTP. HTTP sends message contents and authentication without transport encryption.

Authentication options are none, Bearer token and Basic Auth. Additional literal HTTP headers support custom authentication. Secret headers and secret form values are encrypted with the existing AES-GCM vault, bound to the destination ID, and blanked in API/dashboard views. Leave a secret input empty to preserve the same saved field (stable field ID and unchanged name). After changing URL, authentication mode or Basic username, re-enter the destination's secrets. Switching authentication off removes its credential. Secret fields contain literal values, not templates.

Request framing headers, Host, proxy headers and the delivery-ID header cannot be overridden. A custom Authorization header is supported when built-in authentication is None; otherwise the chosen authentication supplies it. Cookies are sent only when explicitly configured as a header; DSM/browser cookies are never forwarded. Content-Type is configured through the body format; text and JSON allow an optional custom media type. Multipart controls its own boundary. Only POST is supported.

Private/loopback destinations require the destination's explicit **Allow private and local network addresses** option. Link-local, known metadata, unspecified, multicast and reserved destinations remain blocked. Each send resolves the hostname, validates every returned address, and pins those addresses for the connection; DNS resolution and transport share an overall deadline. Environment proxies and redirects are disabled.

## Formats

| Format | Body |
|---|---|
| Generic event JSON | Versioned structured event; no custom template required |
| Custom text | UTF-8 text template; defaults to `text/plain; charset=utf-8` |
| Custom JSON | A valid JSON document whose string values can contain placeholders |
| URL-encoded form | Ordered name/value list; repeated names are retained and values are encoded once |
| Multipart form | Ordered text fields, repeated names and optional field Content-Type; boundary generated automatically |
| Discord | Editable text template, optional rich embeds, disabled mentions and bounded text; `wait=true` requests confirmation |
| Slack | Editable text template in a plain-text block, with disabled link/media previews |

Multipart currently supports text fields, including structured text such as JSON in a part. Binary/file attachments, scripts, arbitrary HTTP methods and HMAC signing are outside this version.

**Preview** validates configuration and renders sample data without sending a request. Secret fields are redacted. **Send test message** makes a real request using sample data, even if the destination is disabled. Preview and test sample data use the destination language, independently of the interface language. English samples use “Sample server: Fan failed”; German samples use “Beispielserver: Lüfter ausgefallen”. Machine-readable keys and enum values stay stable. Real device names, vendor log text and literal custom-template text are preserved. Manual tests are limited to one per administrator per 30 seconds. They do not create hardware alarms or automatic queue entries.

## Template contract

Placeholders use double braces, for example `{{device}}` and `{{message}}`. Replacement is one pass; braces in an event message are never executed as another template. Unknown, malformed and incomplete placeholders are rejected. JSON keys are static.

| Placeholder | Value |
|---|---|
| `schema_version` | Integer, currently 1 |
| `event_id` | Local persisted event number |
| `delivery_id` | Stable random ID per event/destination delivery |
| `device_id`, `device` | Device ID and event-time device name |
| `resource` | Canonical component/resource key |
| `kind`, `health` | Machine-readable event kind and severity |
| `message` | Human-readable message in the destination's saved language |
| `created`, `time` | Unix seconds and UTC ISO timestamp |
| `source`, `verified`, `provisional` | Recorded provenance; absent source/verification is JSON null |

In JSON, a string consisting entirely of a placeholder takes the source value's JSON type. For example:

```json
{
  "id": "{{event_id}}",
  "verified": "{{verified}}",
  "description": "{{device}}: {{message}}"
}
```

The first value becomes an integer, the second boolean or null, and the third a string. Quotes, line breaks and Unicode in event messages are escaped by the JSON serializer. Form values are templated before URL or multipart encoding. Bodies are limited to 64 KiB, forms to 64 fields and additional headers to 32 entries.

## Discord and Slack customization

Both chat formats have an editable text template using the same event placeholders. The default is `[{{health}}] {{message}}`. **Use default text** restores it. Custom Discord text is shortened to 2,000 UTF-16 units and Slack text to 3,000, without splitting Unicode characters. Slack uses plain text; Discord keeps mentions disabled.

Discord additionally accepts an optional JSON array of up to ten rich embeds. **Insert example embed** provides a starting point:

```json
[
  {
    "title": "{{device}}",
    "description": "{{message}}",
    "color": 15548997,
    "fields": [{"name": "Severity", "value": "{{health}}", "inline": true}],
    "timestamp": "{{time}}"
  }
]
```

Embeds support title, description, URL, color, timestamp, author, footer, image, thumbnail and fields. Typed JSON placeholders work here too. Image/icon URLs must use HTTP/HTTPS; local file attachments are not supported. A message can contain text plus embeds, or only embeds when the text template is empty. Preview shows the complete generated JSON.

Validation checks supported fields, JSON types, URLs/timestamps, up to 25 fields per embed, individual text limits and a combined 6,000-character embed limit. Invalid expanded embeds fail before submission; long embed fields are not silently rewritten. Limits follow the [Discord embed reference](https://docs.discord.com/developers/resources/message#embed-object); Slack plain-text limits follow its [text object reference](https://docs.slack.dev/reference/block-kit/composition-objects/text-object/). A local preview/test cannot establish delivery to a real channel.

## Sender name and avatar

Discord destinations can optionally override the message sender name (`username`) and avatar image URL (`avatar_url`). These are literal values, separate from Basic Auth username and from an embed's optional author. Empty values preserve the existing Discord webhook defaults. The app limits sender names to 80 UTF-16 units and avatar URLs to 2,048 bytes; avatar URLs must use HTTP/HTTPS, have a hostname and contain no URL credentials. Discord must be able to reach the image; Hardware Monitor does not download or host it.

The [Discord Execute Webhook endpoint](https://docs.discord.com/developers/resources/webhook#execute-webhook) accepts an avatar URL per message. Uploading image data is supported separately by [Modify Webhook](https://docs.discord.com/developers/resources/webhook#modify-webhook) (including its token variant), which changes the saved/default webhook avatar. This implementation does not modify the Discord profile; upload a default avatar in Discord's webhook settings instead.

Modern [Slack incoming webhooks](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) cannot override sender name or icon per message. Configure the app identity under **Basic Information → Display Information** in Slack. The separate [apps.icon.set API](https://docs.slack.dev/reference/methods/apps.icon.set) supports an image file or public URL with an app-configuration token. That app-management API is not part of notification delivery. Legacy Slack custom integrations offered username/icon overrides; the Slack format targets modern app-based webhooks and sends no unsupported identity overrides.

## Delivery and lifecycle

A separate SQLite job is created per selected event/destination in the same transaction as the event. Jobs have unique event/destination pairs, destination revisions, stable delivery IDs, retry state and per-destination history. Up to four workers run independently from SMTP and DSM desktop delivery. Each destination has at most one active request and at least one second between starts. Ordering is preserved per destination/device/canonical resource; another cause or destination can continue while a failed cause awaits retry.

Requests have a five-second connect timeout, ten-second HTTP timeout and fifteen-second overall deadline including DNS. Responses are limited to 64 KiB and their bodies are not logged. A successful HTTP response means **accepted by recipient**, not read by a person. Use the test action to verify the intended destination and its service-specific configuration.

Network failures, timeouts, HTTP 408 and 5xx retry with exponential backoff (30 seconds up to one hour) and jitter. HTTP 429 respects Retry-After (seconds or HTTP date); Discord's numeric retry_after is also considered. Other non-2xx responses, including redirects, are terminal. Delivery attempts are limited to eight; pending jobs expire after 24 hours. At most 10,000 jobs remain pending; further deliveries are recorded as terminal queue-full failures, without blocking event collection.

A timeout or restart can occur after a recipient processed a request. Retries therefore may duplicate messages. Own receivers can deduplicate using the stable `X-Hardware-Monitor-Delivery` header or generic JSON `delivery_id`. Exactly-once delivery is not claimed.

Alarm acknowledgement, reset, device disable/retarget/delete, query retirement, event grouping and duplicate-occurrence suppression cancel pending webhook jobs using the existing alarm lifecycle. Raw health remains unchanged. A request already in flight cannot be recalled. Saving/deleting one destination cancels its pending work without affecting other destinations. Saving SMTP or DSM desktop filters does not cancel webhooks.

Event history and its CSV export include per-target acceptance, cancellation, retry, terminal failure and HTTP status. Delivery entries in the event log are separated by a middle dot. For each active destination, the event-time device and event selections determine whether delivery is queued or excluded:

- A device outside the destination's device selection is recorded as “excluded by device selection”.
- A matching device whose event is not selected is recorded as “excluded by event filters”.
- These exclusions remain visible even when every destination excludes delivery. Device selection takes precedence when both selections exclude it.

Exclusions are inactive history records: they consume no pending queue capacity and do not replace the destination list's last automatic delivery status. They retain their original reason across configuration changes, restarts and backups. Disabled destinations are omitted. Events recorded before webhook selection history was available are not backfilled. Disabling notifications for a device is described as “Notifications disabled for this device”, since the option applies to all automatic channels.

Pending jobs pin their events against automatic retention; clearing the history explicitly removes those jobs. Endpoint configuration, encrypted secrets and delivery history participate in logical and streaming backups. Logical format 8 includes the two webhook tables; formats 1–7 remain readable through their existing readers. Restore re-encrypts credentials, advances endpoint revisions, disables destinations and cancels imported pending work. Explicit reactivation sends future events only.

## Validation

Local tests cover templates/encodings, secret redaction and identity binding, independent selection, retries/leases/order, acknowledgement/reset/delete and encrypted backup conversion/rekeying. `tools/webhook_integration_test.py` exercises real local HTTP/HTTPS requests from the development daemon, a synthetic Redfish fault, CA/hostname validation, authentication, repeated fields, 429 retries with stable IDs, terminal 401 responses, redirect refusal and independent workers. It also verifies localized samples, Discord/Slack payloads, and visible device/event-selection exclusions with no requests to excluded targets.

The user confirmed functional testing of the outgoing webhook implementation. The report does not enumerate individual destinations, service accounts, NAS versions or failure scenarios. Local transport fixtures and that confirmation remain separate evidence; see [Validation](VALIDATION.md#outgoing-webhooks-0100) and [NAS acceptance](NAS-ACCEPTANCE.md).
