# Generic availability and network SNMP profiles — 0.9.0-0052

Build 0052 changes the generic assessment contract and adds `network_generic`.
The application remains 0.9.0. The user's DSM/OPNsense observations exposed that
optional standard inventory/sensor groups permanently blocked useful generic
assessment. This is corrected with an explicit profile scope. DSM profile
acceptance on build 0051 remains a separate real-device record; the changed
Generic/Network profiles still require real-device acceptance.

## Reference comparison

The official Zabbix 7.4 [Generic by SNMP](https://github.com/zabbix/zabbix/blob/release/7.4/templates/net/generic_snmp_snmp/template_module_generic_snmp_snmp.yaml)
uses SNMPv2-MIB system information and HOST-RESOURCES-MIB host uptime, plus
availability/ICMP checks. Its MIB list does not imply CPU, memory or disk-health
monitoring. [Network Generic Device by SNMP](https://github.com/zabbix/zabbix/blob/release/7.4/templates/net/generic_snmp/template_net_generic_snmp.yaml)
adds interface discovery, traffic/error/discard counters and EtherLike duplex
information, with filters and trigger policies. It does not establish universal
vendor hardware health either. Download checksums and standards are recorded in
[the source record](SNMP-GENERIC-NETWORK-SOURCES.json).

This implementation uses the standardized numeric contracts and independently
written logic. No Zabbix template or implementation is imported, copied, shipped
or loaded at runtime. It is a bounded subset, not full Zabbix feature parity.

## Generic: availability and system

The `generic` profile reads sysObjectID, sysDescr, sysName and sysUpTime, plus
sysContact, sysLocation and optional `hrSystemUptime` (`1.3.6.1.2.1.25.1.1.0`).
System metadata is displayed; SNMP-subsystem and host uptimes are separate
informational readings. No host-reboot claim is inferred solely from SNMP uptime.

A fresh successful identity/uptime exchange creates the assessable observation
`snmp:availability`. The generic overall state can be **OK within this scope**.
The collector's own success row is still excluded from the component assessment;
it is not used as an implicit proof of hardware health.

ENTITY-MIB inventory and ENTITY-SENSOR-MIB are optional extensions. A successfully
completed walk with no supported rows records `optional: true, unsupported` and
does not block assessment. Real timeout, decoding, index, request/byte/item limit
or transport failures still count, including failures of optional walks.
Malformed or incomplete required input cannot become OK.

Generic raw sensor readings without a hardware threshold state are informational.
An explicitly nonoperational sensor still produces a warning. Informational or
missing readings cannot clear retained faults. Optionality does not suppress an
existing incident. The former unconditional generic unknown-coverage row is
removed; required/optional coverage is shown separately. The UI explicitly states
that this profile's OK is availability/system assessment, not a full hardware
health declaration. Existing Dell/HPE/DSM groups remain required; old serialized
capabilities default to required until a fresh poll applies the new policy.

## Network: interface discovery and transition assessment

`network_generic` includes the generic basis plus automatic discovery on the
configured target only. This discovers **interfaces**, not other IP devices.
No network scan, arbitrary OID walk, SET operation or automatic trap mapping is
added. Credentials, target/context restrictions and shared poll budgets remain.

| Numeric table entry | Selected fields |
| --- | --- |
| IF-MIB `1.3.6.1.2.1.2.2.1` | ifDescr, ifType, ifSpeed, ifPhysAddress, ifAdminStatus, ifOperStatus; inbound/outbound octets, errors and discards |
| Optional ifXTable `1.3.6.1.2.1.31.1.1.1` | ifName, ifAlias, ifHighSpeed, ifCounterDiscontinuityTime, ifHCInOctets and ifHCOutOctets |
| Optional EtherLike `1.3.6.1.2.1.10.7.2.1` | dot3StatsDuplexStatus (column 19) |

Rows are joined by complete positive interface index. Names, aliases, admin/oper
states, speed and counters are reread each poll. No permanent discovery cache
can hide a link transition. The required IF-MIB table must have usable rows;
missing optional ifX/EtherLike tables do not block the profile's status.

The user selected **only previously active ports alarm on subsequent link loss**:

- A port is armed only after a complete interface-table read reports admin-up
  and oper-up. Initially disconnected ports remain informational. Loopback
  interfaces (ifType 24) are not armed.
- An armed admin-up port reporting down/notPresent/lowerLayerDown raises warning.
  A fresh oper-up reading confirms recovery. Testing, unknown, dormant, missing
  or malformed states cannot fabricate a recovery.
- Admin-down is neutral for new alarms and does not clear a retained fault. A
  previously active port missing from discovery stays visible as unknown, with
  its baseline retained. Existing alarm retention/acknowledgement still applies.
- Arming and raw counter samples are saved transactionally with the snapshot,
  after revision/epoch checks. Repeated CLI invocations and daemon restarts do
  not forget an armed link. Config-revision changes establish a new baseline;
  retained incident rows are not erased by that reset.
- Logical keys include agent target/type/engine context and interface index,
  base-table description, type and available MAC context. Optional ifName/alias
  changes or absence do not change keys. Names, aliases and shared MACs are not
  cross-protocol physical identity proof. Renumbered/renamed/replaced interface
  contexts may leave an old retained incident requiring operator review.

On an active link, explicitly reported half duplex raises warning; full duplex
confirms that duplex condition. Unknown/absent duplex stays informational and
cannot clear an earlier duplex incident. Vendor-specific fan/PSU/RAID health is
outside this network profile's scope.

## Rates, bounds and exclusions

Counter64 octet values are preferred for v2c/v3. SNMPv1 never requests the two
Counter64 columns and uses Counter32 where safe. Rates require two current
matching samples, positive elapsed time no greater than 900 seconds, consistent
agent uptime/boots, matching width and unchanged reported counter-discontinuity
state. Decreasing counters are not interpreted as a known wrap. A Counter32
traffic sample is suppressed if speed/time permit an ambiguous complete wrap;
unknown speed and implausible rates also suppress it. Clock reversal, reset,
reboot or the first sample therefore cannot create a fake rate spike.

Traffic, error and discard rates are **informational** in this implementation.
No arbitrary high-utilization/error threshold is enabled. ICMP ping/loss/latency,
CPU/RAM/filesystem discovery, arbitrary regex filters, port-selection UI, speed
regression alarms and Zabbix's timed/hysteretic rate thresholds are not added.
These are explicit further features rather than hidden acceptance claims.

Discovery is bounded to 128 current interfaces and 256 current/retained baseline
entries, in addition to existing per-poll 4096 wire-varbind, request, byte and
60-second bounds. Larger inventories or exhausted budgets are surfaced as
incomplete; no successful maximum-size NAS/switch benchmark is claimed. v1 may
reach its request budget earlier. The UI groups discovered ports and additional
metrics instead of flattening every counter into the component overview.

## Verification and package

- 175 Rust unit tests plus 9 integration tests pass, including optional-capability
  defaults/failures, typed sparse rows, discovery limits, 64-bit preference,
  counter deltas, missing/disabled/partial/reboot transitions, durable baseline
  across Store reopen, retained fault and exactly one fresh-up recovery.
- 58 frontend tests pass, including generic optional coverage vs real failures,
  retained incidents, Network configuration round trip, safe port-name rendering,
  status/rate formatting, bilingual catalogs and profile guidance. 23 Python
  build/release/uninstall tests pass. Formatting and warnings-denied Clippy pass.
- Independent Net-SNMP integration exercises the actual native CLI with v1, v2c,
  v3 SHA-1/AES-128 and v3 SHA-256/AES-128. Generic basis assessment is OK with
  missing optional inventory/sensors. A synthetic sparse IF-MIB fixture verifies
  discovered ports, no initial-down alarm, arming on up, two-sample rates, durable
  down warning across new processes, admin/missing/partial preservation, one
  recovery, and neutral optional ifX/EtherLike absence. No real firewall/switch
  or notification recipient is contacted.
- The generic/network suite is required by the aggregate native/static SNMP
  wrapper and therefore the SPK build/CI path. Existing DSM, trap/enrollment,
  alarm/SMTP and Redfish/CGI/TLS functional suites remain build gates.
- Package **0.9.0-0052** is built with `--skip-load-tests` for initial delivery,
  recording that omission in the manifest. As requested previously, the two
  60-second load cases can be validated separately after delivery using the
  exact extracted executable. Package and supplement are distinct evidence.
- Source/package-text secret scans, exact-version dependency advisory checks,
  vendor provenance, static executable and assembled package inspection are
  recorded under ignored `.build/snmp-generic/`. No publication or real-device
  acceptance is implied.

Artifact: `dist/current/HardwareMonitor-0.9.0-0052-x86_64-dsm7-development.spk`.
The manifest retains the source/content identity, executable hash, suite results
and package checksum. Existing 0050/0051 artifacts and historical acceptance
records are retained. Real DSM/OPNsense/switch acceptance for these changed
profiles remains open.
