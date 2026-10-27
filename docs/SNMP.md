# SNMP polling and traps

Hardware Monitor offers one selected primary collector per device: **Redfish
or SNMP**. Optional traps can accompany either primary. Polling, trap reception
and notifications have separate settings and credentials. The supported package
platform and the actual device evidence are listed in
[Hardware compatibility](HARDWARE-COMPATIBILITY.md); local reference tests are
listed in [Validation](VALIDATION.md). UPS profiles are included **untested on
real UPS hardware**.

## Polling setup

1. Enable the target's SNMP agent and permit read access to the selected MIB
   groups. No SNMP write, power control or controller reconfiguration is used.
2. Select **Primary polling protocol → SNMP**. Enter the agent host, remote UDP
   port (normally **161**) and an explicit hardware profile. A manufacturer name
   does not prove that its agent exposes the required MIB.
3. Prefer **SNMPv3 authPriv**, with matching username, SHA-1 or SHA-256 and
   **AES-128-CFB**. Dell's `SHA`/`AES` settings correspond to SHA-1/AES-128;
   select the same algorithms and both passphrases in the app. The Dell profile
   proposes SHA-1 for compatibility, while preserving saved/manual choices.
   MD5, DES, authNoPriv and AES-192/256 variants are unavailable.
4. Select v1 or v2c explicitly if needed. Community traffic is unencrypted and
   is not cryptographically authenticated. No automatic downgrade or protocol
   fallback occurs. Actual version/algorithm availability depends on firmware.
5. Use **Test connection**, review the assessed and unavailable groups, then save
   and enable monitoring. A successful identity read proves access, not full
   hardware coverage. Polling pauses start after completion; one device's polls
   never overlap. Request timeout/retry and whole-poll budgets remain bounded.

Polling and trap secrets are separately encrypted. **Keep**, **replace** and
**clear** have distinct meanings; credentials are never returned to the browser.
Changing the target/security/context scope requires explicit replacement or
clearing. Clear is available for disabled inputs. A polling context name is
optional; a configured polling context engine must match the authenticated
responder. Proxy context-engine routing is unsupported.

## Profile coverage

| Editor selection / saved identifier | MIB and assessment scope | Optional data and limitations |
|---|---|---|
| Generic · availability and system / `generic` | SNMPv2-MIB identity and uptime; an OK result means SNMP availability/system assessment | HOST-RESOURCES host uptime, ENTITY inventory and ENTITY-SENSOR readings; no full hardware-health or invented threshold claim |
| Network · generic / `network_generic` | Generic basis plus required IF-MIB interface discovery and previously active link monitoring | Optional ifXTable/EtherLike data; traffic/error/discard rates are informational; no CPU, RAM, filesystem or ICMP monitoring |
| Dell iDRAC / `dell_idrac` | iDRAC system ObjectStatus, PSU, fan, temperature, memory, controller and physical/virtual disk states | Typed measurements/FQDDs where provided; unsupported required groups remain visible; firmware and license coverage is not universal |
| HPE iLO / `hpe_ilo5` | CPQHLTH/CPQSM2/CPQIDA aggregates, PSU, fan, temperature, memory and available storage conditions | Population and fan-unit rules below; empty storage is unknown, not healthy; the saved identifier is retained for iLO 5/6 compatibility |
| Synology DSM / `synology_dsm` | Synology system partition, power/fans, disk deployment/health and RAID states | Optional newer health/overheat fields; not SMART/HA/expansion-chassis/utilization monitoring; no DSM trap mapping |
| UPS · Generic (RFC 1628) / `ups_generic` | UPS-MIB battery/output and active alarm evidence | Optional telemetry, self-test result and discovered phases; separate from the Generic availability profile |
| APC UPS / `apc_ups` | PowerNet UPS battery/output states | Optional replacement/diagnostic/state flags and telemetry; no PDU/outlet-control coverage |
| Eaton UPS / `eaton_ups` | xUPS output state and active alarm evidence | Optional battery/ABM/test states, telemetry and phases; no blanket legacy MGE or parallel-module coverage |

Required versus optional coverage appears in the device view. Successfully
unsupported optional groups do not block scoped assessment. A real timeout,
malformed response or exhausted budget still indicates incomplete input.
Missing, invalid or unknown values never confirm recovery of a retained fault.
MIBs are compiled numeric allowlists; runtime MIB upload/parsing is unavailable.

### Generic system and network

System description/name/contact/location and SNMP uptime are informational.
Host uptime, where exposed, is separate: restarting an agent is not proof of a
host reboot. Raw sensors without a hardware threshold state are informational;
explicitly nonoperational sensors can warn.

Network discovery finds interfaces on the configured target, not other devices.
A complete table reporting admin-up/oper-up arms a link. Subsequent down,
notPresent or lowerLayerDown while admin-up warns; fresh oper-up confirms
recovery. Initially disconnected and loopback interfaces stay neutral. An
admin-disabled, missing, dormant, testing or unknown port cannot clear a fault.
The armed baseline survives restart; configuration changes reset its context
without deleting retained incidents. Interface names, aliases and shared MACs
are not cross-protocol physical identity proof.

Half duplex on an active link warns; unknown duplex cannot clear it. Rates need
two matching valid samples, no agent reset or counter discontinuity, and a safe
elapsed interval (at most 900 seconds). v2c/v3 prefer Counter64; v1 uses Counter32
only where wrap ambiguity can be excluded. First samples, resets, unknown speed
or implausible deltas can omit a rate. There are no utilization/error thresholds,
port-selection rules or speed-regression alarms. Discovery is bounded to 128
current interfaces and 256 current/retained baseline entries plus shared poll
budgets; larger inventories are explicitly incomplete.

### HPE population, power and fan units

Explicitly empty PSU/fan bays and proven empty DIMM slots are neutral. A missing
OID alone is not proof of absence. Previously populated hardware later reported
removed produces an observation using persisted history. Unknown presence cannot
clear an earlier fault; explicit valid reinsertion can confirm recovery.

The optional modern DIMM table needs status notPresent, zero size and condition
other before a slot is considered empty; missing data alone is insufficient.
Its condition value 4 means degradedModuleIndexUnknown and warns. PSU Condition
and PSU Status use distinct enums: Status noError(1) is not Condition other(1).
Contradictory absent/fault states retain the fault. Population history is scoped
to the configuration revision and agent identity; edits establish a new baseline.
Explicit redundancy is configuration context, not a user-defined requirement.

Fan speed is percent only on positively identified iLO 5 firmware >=3.06 or
iLO 6 >=1.61. Older/unknown firmware does not interpret the speed-level enum as
percent; the separate current-RPM field remains supported. DIMM sizes use the
MIB's KiB units. Powered-off host status is context, not a reason to assume that
unavailable storage is healthy. Empty or unsupported CPQIDA storage stays
unassessable. HPE index-only traps cannot directly identify a Redfish component.

### Synology DSM

Enable the target's agent in DSM Control Panel. System-partition status is not
a complete NAS rollup. Disk allocation states 1–3 are neutral; deployment 4/5
is critical. Optional DSM 7.1+ physical health maps normal/warning/critical
separately; a present malformed value cannot fall back to healthy deployment.
RAID degraded 11 warns and crashed/read-only 12 is critical. Maintenance states
remain named unknown observations and cannot clear a prior failure. Missing
storage rows are not recovered disks. Use DSM Storage Manager for full coverage.
Typed temperatures are informational; no threshold is invented. The checked
Synology MIB guide excludes DSM SNMP traps; this profile is intended for polling.

### UPS states, measurements and alarms

**APC, Eaton and RFC 1628 profiles have local reference coverage only and are
released untested on real UPS/card/firmware combinations.**

Utility output is normal; battery operation and bypass warn. Explicit depleted,
faulted, disconnected or missing batteries, low battery, output loss and serious
faults are critical where reported. Replacement/aging warns. AVR boost/trim and
documented Eaton efficiency modes are normal. Unknown modes and control/test
operations in progress do not establish recovery.

Optional absent measurements/phases do not block assessment; missing required
states or failed walks do. Measurements retain MIB units: APC runtime is
TimeTicks converted to seconds, RFC runtime minutes and Eaton runtime seconds;
RFC current/voltage may use tenths while Eaton base units are whole units.
Signed charging current stays signed. Invalid readings and sentinels are hidden;
numeric values create no new alarm thresholds.

RFC/Eaton sparse alarm tables require a complete descriptor walk with matching
before/after Gauge32 counts, row counts and unique valid condition OIDs. Partial,
changing, duplicate or malformed input cannot prove an empty healthy set or
lower a retained critical state. Acknowledgement follows sorted condition OIDs
(APC: documented flag positions), not reusable row numbers. No UPS shutdown,
power switching, self-test initiation or vendor UPS trap component mapping is
implemented.

## Trap listener and controller destination

Enable **Receive SNMP traps** for the device and the global **SNMP trap
receiver**. Set exact source IP addresses, separate security/credentials and a
trap profile. Source lists accept individual IPv4/IPv6 addresses, not hostnames
or subnets. Ambiguous device matches are rejected; payload labels and v1 embedded
agent addresses cannot select the device.

The global listener defaults to **UDP 1162**, disabled. It accepts a configured
local port and explicit NAS IPv4/IPv6 addresses. Polling port 161 is a remote
agent destination; trap port 162/1162 is a local NAS destination. Configure the
same NAS address/port in the controller and permit that UDP traffic from the
specific controller IPs in DSM/network firewalls. Outgoing polls/replies also
need a working network path. The app does not change controller or firewall
settings. A controller's port setting may affect all its trap destinations;
check its firmware before changing it. A firmware unable to select a custom
port needs standard-port setup or a separately operated forwarder.

For standard port 162, follow [Privileged trap ports](TRAP-PRIVILEGED-PORTS.md).
The bundled root-run helper grants only the executable bind capability; service
and installation remain under the package identity. A replaced executable after
an update may require reapplying it. A denied bind shows an amber setup warning;
a port conflict has a separate error. Failed listener changes retain the prior
saved configuration and attempt to restore the prior sockets. Polling/UI continue
when reception cannot bind; saved and active bindings are shown separately.

### SNMPv3 sender enrollment

1. Save trap credentials and the responder host/port. A Redfish primary uses
   this SNMP target only for authenticated sender verification, without a second
   periodic hardware collector or polling-secret fallback.
2. Reopen the device and select **Check saved sender identity**. A fresh authPriv
   system read authenticates the target engine and clock. Discovery or an
   incoming signed trap alone grants no approval.
3. Review the target, engine ID and boots counter; explicitly choose **Use
   verified engine ID in draft**, re-enter the trap credentials and save. The
   action replaces the draft sender allowlist. A probe alone never saves trust.
4. Send a controller test trap and inspect live status and the accepted receipt.
   Missing approval is prominently reported when saving an enabled v3 input.

A changed engine ID requires new review even on the same IP. Same-engine
increasing boots/time renew the authenticated baseline. An enabled responder
must be reachable for initial verification/revalidation. Config changes and
restore invalidate obsolete queued packets, reviews and poll results.

Trap context filters are optional: an empty name allows all context names of
the verified sender; an empty context-engine list adds no context-engine filter.
An explicit name/list must match. These filters are separate from the approved
authoritative sender engine ID, which is always checked for v3.

### Controller clock compatibility

The reported iDRAC9 firmware 7.00.00.185 sent MEM7114 after restart with trap
boots 1/time 388 while its authenticated responder reported boots 113 (last
accepted trap boots 111). This is a backwards trap clock, not a normal increasing
reboot counter. Strict reception rejects it.

The default-off per-device option **Compatibility for differing boots counter or
engine time** permits an untimely trap only as a polling hint after successful
signature, decryption, source/approved engine/user, authPriv, PDU and context
checks. It requests the configured primary poll; alarms/notifications then come
from that fresh poll. It never lowers the strict replay baseline or creates a
regular receipt, history event, direct alarm or accepted-trap timestamp.

Live sender/device status shows the compatibility reception time and the separate
hint counter, labelled with unconfirmed freshness. These hints last only for the
service run; they are not persistent accepted receipts. Further hints can request
polling, coalesced with pending work and at least ten seconds between urgent
starts. Valid timely traps keep normal handling. This compromise provides an
accelerated state check without treating an old signed packet as a current fault.

## Alarms, duplicate handling and notifications

A verified v3 mapped fault can create a **provisional alarm immediately** when
it uniquely matches current inventory. A confirming primary poll does not send
a second automatic notification for that same transition. Only a later explicit
covering primary read confirms recovery. Traps do not replace the measurement
snapshot, refresh its timestamp or clear unrelated faults. An old in-flight poll
cannot clear a newer mapped trap fault. Acknowledgement retains hardware health
and the existing new/worsened-condition rules.

Dell mappings cover the explicit fan/temperature/PSU/memory/physical-disk OIDs
and FQDDs. HPE mappings cover explicit fan/PSU notifications; scoped SNMP indices
or proven serial/locator identity are required. Redfish crosswalks require actual
OEM identity evidence, never equal names or guessed indices. Unmapped, unknown,
test, recovery-hint and community input stays diagnostic/event-only. Informs
receive no acknowledgement; BMC/ASF PET is explicitly unsupported.

The semantic transport duplicate cache is bounded to 4096 entries/30 seconds;
message IDs and source ports do not define a new incident. Ongoing fault plus
confirmation does not repeat a state alarm; confirmed recovery followed by a new
fault creates a new incident. Configured periodic reminders remain intentional.
Similar hardware-log rows are suppressed across sources only with a proven
unique shared occurrence ID. Native Dell/HPE fields such as MessageId alone do
not establish that proof; both history records may remain.

Mapped alarms use normal hardware/recovery delivery filters. Verified fault
**events without a component mapping** use a separate default-off SNMP-trap event
filter. Unknown/unverified/test input is non-notifying information. Enable device
notifications, the desired email/desktop channel and matching filters. Source,
verification and provisional state appear in events/CSV and optional template
placeholders; no packets or passphrases are logged.

## Reception diagnostics and troubleshooting

Check live binding, per-sender verification, counters and bounded receipts under
**SNMP trap receiver**. Counters reset with the service. Regular receipts retain
normalized source/version/engine/OID/time/handling for seven days, at most 10,000
rows, without raw packets. Imported/old-revision/loopback evidence is marked and
is not proof of a current controller setup. Refresh reloads status and receipts.

| Observation | Next check |
|---|---|
| No incoming datagrams | Controller destination, UDP port, NAS interface and firewall; local bind alone proves no remote reachability |
| Unknown/ambiguous sender | Exact source IP and enabled per-device policies; do not widen trust based on payload text |
| Verification pending | Saved responder host/port, trap credentials and explicit approved sender engine |
| Authentication/decryption rejected | Matching user, both passphrases, SHA selection and AES-128; successful polling may use different credentials |
| Context rejected | Explicit name/engine filters; blank fields add no filter |
| Timeliness rejected after restart | Compare authenticated responder engine/boots with actual trap metadata; review clock compatibility only if necessary |
| Receipt accepted but no direct alarm | Version/verification, known OID, current unique inventory mapping and delivery selection; inspect confirming poll |
| Compatibility reception only | Expected polling-hint behavior; inspect the primary poll and its resulting alarm |
| Privileged bind denied / address in use | Capability setup for the former; another listener or unavailable address for the latter |

For protocol diagnosis, record sanitized source/destination/port, B/T metadata and
counter changes. Do not put raw packets, real credentials or private walks in the
repository. Numeric source provenance remains in `SNMP-SERVER-SOURCES.json`,
`SNMP-SYNOLOGY-SOURCES.json`, `SNMP-GENERIC-NETWORK-SOURCES.json` and
`SNMP-UPS-SOURCES.json`; licenses/patch provenance are described in
[Development](DEVELOPMENT.md#snmp-dependency-and-reference-tests).

### Diagnostic event retention

Event-only `snmp_trap` history has an additional fixed seven-day/10,000-row
bound, separate from normalized receipts and the general configurable event
retention. The general rule can remove eligible events sooner; selecting
unlimited general retention does not disable this SNMP-specific bound. Pending
automatic/manual delivery and active replay previews protect their events.
If all slots are protected, the receipt records `event_history_full` and primary
reconciliation still runs. Mapped state alarms and their retained faults are
not cleared by diagnostic-history pruning.
