# Streaming archive format (build 0042)

This documents the binary `HWMON-STREAM-1` envelope for future compatible readers. User instructions and resource requirements are in [Backup and restore](BACKUP-RESTORE.md). Existing Base64/JSON envelopes remain a separate legacy reader.

## Binary envelope

All numeric framing fields use big-endian encoding.

| Field | Size |
|---|---|
| ASCII `HWMON-STREAM-1` followed by LF | 15 bytes |
| Random salt | 16 bytes |
| Random base nonce | 12 bytes |
| Repeated frames: plaintext length, ciphertext, GCM tag | 4 bytes, length bytes, 16 bytes |

The key is PBKDF2-HMAC-SHA256(password UTF-8, salt, 600,000 iterations), producing 32 bytes. Frame sequence numbers start at zero and increase without wrapping. For sequence `s`, the 12-byte AES-256-GCM nonce is the base nonce with its last eight bytes XORed with the big-endian 64-bit encoding of `s`.

AAD is the concatenation of the complete 43-byte envelope header, the 8-byte frame sequence number and the 4-byte plaintext length. A data frame carries 1–65,536 bytes of the gzip-compressed logical stream. The writer emits an empty authenticated frame after all data. This final frame uses the next sequence number and must be followed by physical EOF. Readers authenticate each frame before releasing its plaintext, reject lengths above 65,536, and become permanently unusable after a read/authentication error. Nonce/sequence reuse and wraparound are forbidden.

The mandatory final frame detects truncation even at an otherwise valid gzip/record boundary. Sequence authentication detects insertion, duplication and reordering. The total archive has no configured size cap; the frame size is independent of total history size.

## Logical stream and activation

A single gzip member contains UTF-8 newline-delimited JSON records:

1. `header` with `metadata` (`format`, `version`, `created`). Logical format is **7**, combining retention and SNMP tables; format 6 streams remain readable with default SNMP settings.
2. For every compiled table in `archive::table_specs()`, a `table` record with `name`, followed by zero or more `row` records with `cells` in that table's compiled column order.
3. `end` with the exact total row count. No trailing logical records or compressed bytes are permitted.

Cells use the existing tagged representation: `Null`, `Integer`, `Text` or Base64 `Blob`. No SQL, table/column names or filesystem paths from the file are executed or trusted. Each JSON record is limited to 16 MiB plus its LF. Layout, column count, integer bounds and foreign keys are checked while staging. Device/SMTP/purpose-separated SNMP credentials are re-encrypted with the destination vault before entering the staging database.

The entire stream, including gzip termination, row count, final authenticated frame and physical EOF, must pass before a staged import is confirmable. Final application-record validation and replacement occur in one live SQLite transaction with cancellation and an audit-revision guard. The previous database survives failure; a completed commit is success. Restore resets operational revisions and the daily-cleanup review deadline, pauses devices/channels, and cancels imported pending deliveries.
