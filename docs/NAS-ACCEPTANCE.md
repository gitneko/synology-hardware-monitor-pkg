# NAS acceptance and additional validation

The package targets DSM 7.0+ x86_64 (`7.0-40761` minimum). User-reported host
results include RS2421RP+/v1000/DSM 7.4.1-90080; earlier DS220+/geminilake
observations are scoped in [Validation](VALIDATION.md). The user installs
packages manually. No agent-side NAS action is implied by local checks.

## Accepted workflows

[Current acceptance](VALIDATION.md#current-acceptance) is the authoritative
record for SNMP: reported profile operation, direct alarms/configured
notifications, negative identity/credential checks, recovery, acknowledgement,
duplicate handling, package/DSM restart, 0043 → 0062 upgrade and backup/restore
are confirmed. These must not remain generic outstanding items.

Prior-release confirmations also cover installation/menu/internal DSM window,
positive sign-in, device editing (address/password/certificate), R340 polling/
PSU critical status, Gmail test/reminders, DSM desktop test/reminders and older
archive restore. The [hardware matrix](HARDWARE-COMPATIBILITY.md) distinguishes
Redfish runs, supplied captures and later SNMP reports.

APC/Eaton/RFC 1628 profiles ship explicitly untested on real hardware. Their
future hardware checks do not block the agreed release. DSM package downgrade
is outside the supported path, separate from transactional failure recovery.

## Additional coverage, not a reopening of accepted checks

| Area | Useful remaining evidence |
|---|---|
| Current UI corrections | Native DSM display of total retained event count and the two 0064 spacing corrections; locally tested |
| Languages | Automatic detection, explicit English/German, errors, translated CSV/new events, channel-specific language and preserved custom/vendor text |
| Permissions | Denied/viewer users, session expiry, full DSM Application Privileges/menu integration and directory-service group resolution |
| Manual email replay | Preview/original ID/time, one requested recipient, separate history/Message-ID, unchanged alarm and original delivery; local SMTP/UI coverage exists |
| Hardware | Further model/firmware/security combinations, license-specific iLO access, two independent faults/partial recovery and unavailable-data retention |
| Large archives/retention | Native multi-GiB throughput/RAM/disk headroom, cancellation/session resumption, cleanup counts and preserved pending jobs; ordinary backup/restore is accepted |
| Operational endurance | Long outages, crash/disk-full behavior and NAS resource sizing; local boundary tests do not establish sustained production operation |
| Uninstall variants | Full older JSON versus newer Vue wizard/version matrix, retained-data reinstall and opt-in deletion on disposable state; the reported opt-in wizard flow is confirmed |

Only use an intended disposable dataset for destructive restore/uninstall tests,
with a downloaded backup when data must survive. No physical fault injection or
controller configuration changes are part of ordinary UI/reference validation.
Firmware-specific unsupported behavior should narrow the matrix, not be inferred
healthy. No live credentials/raw responses belong in repository fixtures.

For trap testing record the selected profile/security, real source/destination
and port, approved identity, normalized receipt or explicit compatibility hint,
primary poll and resulting incident/submission. A local bind, loopback receipt
or cryptographic signature alone proves no current hardware state. Do not
require another notification test for the already confirmed Dell workflow.
