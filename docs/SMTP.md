# SMTP delivery and templates

The app uses an integrated Rust/lettre SMTP client. It does not run a mail server, depend on DSM's email credentials or require an internal DSM mail API. The earlier search did not establish a supported general DSM email-submission API for this package. On the test NAS, `/bin/ssmtp` existed, but its conventional configuration file was empty; that did not demonstrate a usable inherited mail transport.

The current implementation supports explicitly selected plaintext (for example port 25), required STARTTLS (usually 587) and implicit TLS (usually 465). SMTP authentication is optional. TLS modes verify certificates and server names and never downgrade automatically. A private CA can be added. Plaintext can expose both messages and optional SMTP credentials; it must be deliberately selected. The package uses rustls/ring and does not need an OpenSSL runtime.

Credentials are encrypted with the local vault. Changing server, port, security mode or username requires a newly supplied password when authentication is used. Saved templates and recipients are administrator settings. Up to 20 addresses are supported; messages are individually addressed and tracked. The sender and recipients are validated to prevent header injection.

## Templates and language

Placeholders: `{{device}}`, `{{health}}`, `{{kind}}`, `{{message}}`, `{{time}}`, `{{time_local}}`, `{{time_utc}}`, `{{timezone}}`, `{{event_id}}`, `{{resource}}`. Rendering is a single pass; inserted values are not evaluated as templates. Custom subject/body text remains unchanged when selecting a language. Use **Use default template** explicitly if replacement is wanted.

The saved email language controls generated new-event messages and translated health/type values. Old free-text events and vendor logs retain their original content. Local time uses an IANA time zone and validated strftime format. The default format for an unsaved English setup is ISO with UTC offset; upgrading does not rewrite a saved format. UI interface language and mail time zone are separate preferences.

Preview and test email use current editor values. The test sends only to the first recipient, is rate-limited to one per 60 seconds and does not require automatic delivery to be enabled. Automatic delivery additionally needs the channel, event filters and device notification option. Saving cancels pending old email jobs and does not replay history.

Each recipient has a durable message ID/status. Transient errors receive bounded retries; permanent rejections stop automatic retries. An externally accepted message cannot be recalled, and SMTP acceptance is not proof of inbox delivery. The user confirms Gmail test and automatic reminder delivery. Plaintext was locally tested. OAuth, HTML templates and arbitrary attachments are not implemented.

Reference: [lettre 0.11.23](https://docs.rs/lettre/0.11.23/lettre/). See [Notifications](NOTIFICATIONS.md) and [Validation](VALIDATION.md).

## Manual event replay

Administrators can select **Events → Resend email …** to preview and send one recorded event to one saved recipient using the current saved template. This explicit action works independently of automatic delivery filters and preserves the original alarm/event state and delivery history. No TEST marker is inserted. Each intentional job has a new Message-ID; its technical retries keep that ID and frozen content. See [Manual email replay](MAIL-REPLAY.md) for duplicate handling, history and cancellation rules.

The template editor lists the additional `{{source}}`, `{{verified}}` and `{{provisional}}` placeholders in the template editor. They use structured trap/poll event provenance. Saving or switching interface language does not rewrite an existing custom template. Trap provenance also appears in history and CSV; event-only trap delivery has its own default-off filter under Channels & events.
