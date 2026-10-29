# Hardware Monitor 0.10.1

Package build: **0.10.1-0074**.

## Repeated Redfish log notifications

Redfish logs are deduplicated per device using the source timestamp and complete original message, before the existing 1000-character display/storage limit, formatting or translation. Equivalent RFC3339 offsets and fractional-second representations identify the same instant. Entry IDs, resource addresses, log-service addresses and vendor-specific fields do not affect this key. Two records with identical text and source time are intentionally treated as one occurrence. A different time or original text remains a new occurrence, including differences after the first 1000 characters.

Entries without a valid source timestamp retain the previous resource/ID-based fallback. Receipt time is never substituted. This change applies to Redfish logs; SNMP trap and polling identity rules are unchanged.

## Upgrade and restore

Startup and legacy-backup restore migrate the retained Redfish log cache transactionally, without changing historical events or their delivery records. Known entries remain known; a new occurrence in the first post-upgrade poll is still eligible for notification. Migration uses bounded batches and a backed-up completion marker.

Older collectors retained only the first 1000 characters of a message. Such an ambiguous legacy prefix is adopted once by the first matching complete message at the same source time. Subsequent different complete texts remain distinct. Redundant position-based cache records collapse during migration; recorded application history is preserved.

## Validation

Regression coverage includes HPE-style entry renumbering, Dell-shaped old/new Redfish log paths, equivalent UTC offsets, fractional precision, full original text, intentionally identical records, distinct devices, 100 repeated reads, process/store restart, email/desktop/webhook job counts, email completion, restore rollback, legacy duplicate-cache migration, truncated legacy text and the existing end-to-end HTTPS Redfish integration.

## Local network validation

Build 0073 recorded a synthetic SNMPv3 SHA-256 polling timeout, reproduced with the unchanged 0.10.0-0072 product. Investigation found a local network-environment problem: ordinary UDP loopback datagrams of 1500 bytes and larger were not delivered in the default WSL network, while smaller datagrams worked. This also affected the independent Net-SNMP client and large generated trap packets.

In a fresh isolated network namespace with only loopback enabled, the same datagrams up to 16 KiB arrived, and the original polling and trap-generator cases passed. Build 0074 runs the unchanged reference tests in that isolated local network. No SNMP product code, fixture view, security policy, timeout, retry or health-assessment rule changed. Host network/firewall settings were not changed.

Automated local tests establish application behavior. Real NAS and controller acceptance remains to be checked with the delivered unsigned development SPK.
