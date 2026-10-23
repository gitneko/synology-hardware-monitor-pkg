# 0.9.0-0056 — SNMP development package

This unsigned DSM 7 x86_64 development package adds explicit SNMPv1/v2c/v3 polling
and optional trap reception alongside the existing Redfish primary collector.
Local source, protocol and package validation is recorded in
[SNMP P6 results](SNMP-P6-RESULTS.md). Build 0.9.0-0051 installation and the DSM polling profile were confirmed by the user on 21 October 2026; the remaining NAS/controller acceptance matrix stays open in P7;
prior Redfish hardware results do not establish SNMP support on those firmwares.

## Build 0056: HPE iLO population and firmware-aware polling

The displayed profile is now **HPE iLO**; existing `hpe_ilo5` configurations
remain valid. Explicitly empty PSU/fan slots and proven empty DIMM slots are
neutral, not unknown required hardware. Previously populated slots report a
subsequent explicit removal using persisted snapshot history; missing/ambiguous
presence cannot confirm recovery. Reported and retained component faults remain
visible. New DIMM detail is optional on agents that do not implement its table.

Fan speed uses percent on positively identified iLO 5 >=3.06 / iLO 6 >=1.61;
older/unknown firmware never interprets the speed-level enumeration as percent.
The separate current-RPM field remains supported on older agents. Host power
state and unavailable storage have explicit UI context. Powered-off or empty
CPQIDA tables do not prove healthy or inapplicable storage. No power actions,
expected-population configuration or new trap mappings are added.

See the [HPE profile guide and evidence boundary](SNMP-HPE.md). Local replay of
sanitized supplied iLO 6 values is distinct from installation/live acceptance.

## Build 0055: direct legacy upgrade and startup

Corrects the locally reproduced five-second daemon-start timeout during a direct
schema-1 upgrade. Package `postinst` now explicitly initializes/migrates private
state before DSM starts the service, including during repair. The daemon allows
up to 120 seconds to reach readiness, waits for a connectable API socket and
publishes its PID after listener/shutdown initialization. Database initialization
allows 30 seconds for transient SQLite contention, then restores the existing
five-second runtime busy timeout. Stopped/unknown service status uses DSM's
specified exit codes 3/4.

The durable pre-migration database/key backup is published only after both files
are complete and synced; failed temporary backups are not advertised as usable
rollback copies. Initialization diagnostics go to private `service.log`.
Configuration, credentials, retained alarms, acknowledgements and delivery
settings are preserved. No reset or earlier SNMP development installation is
required. A new actual-product upgrade/repair regression runs in native CI and
against the static package executable.

[Reported NAS observations and local evidence](VALIDATION.md#build-0055-direct-upgrade-startup-correction-23-october-2026)
distinguish the confirmed DS220+ timeout symptom from the controlled local
reproduction. Installation/upgrade of 0055 on those NASes remains to be confirmed.

## Build 0054: APC, Eaton and standard UPS polling

Adds explicit `apc_ups` (PowerNet), `eaton_ups` (xUPS) and `ups_generic`
(RFC 1628 UPS-MIB) polling profiles. Battery/output state, reported alarm
conditions and optional diagnostics feed the existing retained-alarm and
acknowledgement pipeline. Available charge, runtime, temperature and electrical
measurements use their MIB-specific types/units; RFC/Eaton phase measurements
are discovered automatically. Empty alarm tables require a completed walk and
matching typed counts before/after reading. Unknown or partial evidence cannot
fabricate recovery. No UPS power controls, test initiation, invented measurement
alarm thresholds or new vendor trap-to-component mappings are added.

See [scope and validation](SNMP-UPS-RESULTS.md) and
[numeric source provenance](SNMP-UPS-SOURCES.json). Real UPS/card/firmware and
native DSM acceptance remain open.

## Build 0053: network detail layout

Align assessment and link-monitoring notes with the detail headings. Show general
components/readings before discovered network interfaces. Additional interface
measurements expand below their interface across the full table width, with short
metric labels and a responsive grid instead of a narrow, independently scrolling
list. Link, speed, traffic and health remain aligned at the top of the main row.
No polling, assessment or alarm behavior changes.

Validation: 58 frontend tests and the production UI build passed. A local browser
preview with 50 synthetic interfaces checked heading/note alignment, section
order, expanded measurements and mouse/keyboard toggling at desktop and narrow
viewport sizes. Native DSM visual acceptance remains pending.

## Build 0052: generic availability and network discovery

The generic profile now assesses SNMP availability/system identity. Unsupported
optional ENTITY inventory and sensors no longer block this scoped status.
Informational readings stay neutral; real failures and retained faults still
count. System metadata and separate SNMP/host uptimes are displayed.

The new `network_generic` profile discovers IF-MIB interfaces and optional ifX/
EtherLike extensions. Only previously active links raise subsequent down alarms;
the baseline survives process restart. Traffic/error/discard rates and optional
duplex data are displayed. Unknown/missing/reset input cannot fabricate recovery
or traffic spikes. See [scope, limits and validation](SNMP-GENERIC-NETWORK-RESULTS.md).

This is an independently implemented bounded subset inspired by Zabbix's generic
SNMP template contracts, not a Zabbix template import. No ICMP probe, CPU/RAM/disk
threshold monitoring, arbitrary MIB import or network-device discovery is added.

## Build 0051: Synology DSM

Adds the explicitly selected `synology_dsm` polling profile: system partition,
power, system/CPU fan status, system/disk temperatures, disk deployment and
optional DSM 7.1+ disk health, plus RAID status. No invented temperature
thresholds or vendor trap definitions. Routine RAID maintenance stays visible
as unknown assessment without generating a hardware fault solely for maintenance.
DSM does not support SNMP traps according to the official guide.

See [DSM profile validation and limits](SNMP-SYNOLOGY-RESULTS.md). Build 0050
remains the historical P6 baseline; 0051 retains application version 0.9.0.

## Changes

- Choose Redfish or SNMP as the primary polling protocol. SNMP uses bounded numeric
  generic/Dell iDRAC/HPE iLO 5/Synology DSM profiles, explicit v1/v2c community or v3 authPriv,
  SHA-1/SHA-256 and AES-128. Missing/partial/unsupported coverage stays visible.
  No automatic security downgrade or simultaneous second primary collector.
- Configure trap reception independently, with separate credentials, exact source
  IP allowlists, reviewed v3 engine/context identities and a supervised local UDP
  listener. The default port is **1162**, configurable **1024–65535**. Polling port
  **161** and standard trap port **162** are distinct; existing DSM SNMP service
  can retain its own port. Enabling reception remains an administrator action.
- Verified v3 faults with unique current inventory proof join the shared alarm,
  acknowledgement and notification pipeline immediately as provisional evidence.
  Sequence barriers prevent older polls from clearing newer trap evidence. Only
  fresh covering primary input confirms recovery; recovery traps alone do not.
- Unknown/unverified/unmapped input remains diagnostic/event-only evidence.
  Event-only fault notification has an explicit default-off filter. Existing
  delivery filters/templates remain intact; source/verification/provisional
  metadata is available in the UI, CSV and optional mail placeholders.
- German/English device and receiver configuration, explicit saved-target sender
  review, current binding/verification diagnostics, bounded receipts and separate
  poll/trap timestamps. A local bind or loopback receipt is not BMC acceptance.
- Static product reference tests are part of package generation and CI, including
  two 60-second load scenarios with primary polls/API and actual local SMTP.
  Version drift and dirty-source publication are rejected by the release tools.

## Upgrade and rollback

Back up the existing database and matching local master key **before upgrading**.
Opening the new app upgrades schema 1 to schema 2 transactionally and keeps a
private pre-migration backup. Existing Redfish devices/settings/acknowledgements
are preserved and the new receiver is disabled by default. Logical archives use
format 5; formats 1–4 remain readable. Imported devices, delivery and the listener
stay paused for review; runtime USM clocks are not replayed from logical archives.

Rollback requires stopping the service, restoring the matching pre-upgrade
SQLite/master-key backup and old SPK. An old executable must not open schema 2;
a format-5 app archive is not an old-version rollback image. Native upgrade,
restore and rollback still require P7 acceptance. See [Backup and restore](BACKUP-RESTORE.md).

## Limits and acceptance

No Inform acknowledgements, BMC/ASF PET decoding, proxy context-engine routing,
SNMP writes or arbitrary MIB import are added. Component proof/coverage limits in
[P4](SNMP-P4-RESULTS.md) continue to apply, including HPE index-only traps without
a proven Redfish crosswalk. Native log/trap records lacking a unique shared
occurrence identifier are not guessed to be duplicates. Security/load checks are
bounded local reference evidence, not complete UDP DoS resistance or maximum NAS
inventory sizing. Real model/firmware versions, custom-port reachability,
controller test traps and safe physical fault/recovery scenarios remain P7.
