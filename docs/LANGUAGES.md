# German and English

Build 0017 adds **Automatic / Deutsch / English** to the interface. The choice is stored only in the current browser. It is available before sign-in and does not grant access to device data. Automatic first checks a supported DSM language cookie, then the same-origin DSM parent document; otherwise it uses the browser language. Unsupported/missing languages fall back to English. Explicit choices take precedence. Automatic recognition on the target DSM remains part of acceptance; undocumented DSM JavaScript globals are not required.

The interface translates navigation, forms, confirmations, statuses, delivery descriptions and error messages. Dates use `de-CH` or `en-GB` presentation and the browser's local time zone. Mail and CSV local timestamps separately use the configured IANA time zone/date format; UTC columns/tokens remain available.

## Background channels

Set **Desktop notification language** under Notifications and **Email message language** in SMTP settings. These preferences are saved in SQLite and included in app backups. Each [webhook destination](WEBHOOKS.md) also has its own message language. These settings are independent of whoever currently has the interface open. Existing saved settings default to German on upgrade. New SMTP/desktop configurations can use the interface language. A new webhook destination starts in German; choose its message language explicitly.

SMTP placeholder values such as health/type and generated new-event messages follow the saved email language. Existing subject/body templates remain user data and are never silently overwritten. **Use default template** explicitly replaces the subject/body in the editor using the selected email language; save only after reviewing it. Date format and time zone remain separately configurable.

Native desktop notifications use fixed English/German package-language sections and three separate values for device, message and event ID. The saved desktop language selects the keys, even if the recipient's DSM language differs. Manual desktop tests use the current interface language. The helper's supported severity options and all existing recipient/permission/rate restrictions remain enforced. Native rendering of the new forced-language keys is still a NAS acceptance item.

Webhook preview and test samples follow the destination language, independently of the interface. Automatic messages localize generated event text while preserving device names, vendor text and literal custom templates. Generic JSON keys and enum values remain stable. Webhook `{{created}}` is Unix seconds and `{{time}}` is UTC ISO format; SMTP local time settings do not change them.

## Events and vendor text

New events contain structured message context alongside the original stored text. UI/CSV and background delivery can render the app-generated message in the selected language without rewriting history. Old events without context stay in their original language. Vendor component names, device names and hardware log messages are not machine translated. App-generated overall-health/power-state suffixes are translated; an unavailable component's retained-fault wording remains explicit.

`X-HardwareMonitor-Language: de|en` is a presentation hint for API clients, not an identity or authorization claim. The CGI defaults to German when the header is absent for compatibility with older clients. Authentication and write protection are unchanged. English README/documentation are the maintained source documentation.
