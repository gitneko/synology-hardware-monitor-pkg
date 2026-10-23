# Device management

Administrators can add, edit, test, pause and remove devices in the DSM application. The user confirms creation/editing, including address, password and certificate changes, on the test NAS. Viewer access is read-only; full DSM Application Privileges/menu integration remains separate unfinished work.

Use the management controller's HTTPS origin, for example `https://bmc.example/`, without a Redfish path, credentials or query string. Enter a BMC account permitted to read the required hardware resources; effective privileges vary by firmware/resource. The app follows advertised resource links rather than assuming one fixed system ID. Pauses between polls are 30–86,400 seconds and start after completion; optional reminders must be at least five minutes apart.

In Standard mode, HTTPS certificate chains and hostnames are verified. Publicly trusted certificates or an imported private CA/server certificate are supported. Import PEM certificates only, never private keys. There is no production switch to disable TLS verification. Changing the endpoint or username requires a new password; otherwise a blank password preserves the saved secret. A CA change keeps hostname checks active.

**iDRAC7/8 and iLO compatibility** is a separate, explicitly selected per-device mode for controllers requiring an exact server certificate comparison. It uses bundled static OpenSSL, TLS 1.2 or newer and forward-secret AES-GCM suites including DHE-RSA. Import exactly one server PEM certificate from a trusted source and choose **Trust this exact server certificate**. The full certificate SHA-256 and validity dates are checked before any HTTP data or credentials are sent. This replaces CA/hostname checks only in this mode, allowing older self-signed Dell certificates marked CA:TRUE without SANs. There is no trust-on-first-use or automatic fallback. Certificate changes fail closed; reimport deliberately. Changing the endpoint requires reimporting the pin. Existing devices default to Standard, and switching modes never converts an existing CA import automatically. Pin settings survive encrypted backup/restore, which still pauses monitoring. No private keys are imported.

**Test connection** reads the service root and each advertised Systems, Chassis and Managers collection without saving the device. A public root alone no longer confirms device sign-in; if no collection links are advertised, the interface explicitly reports that data access is unconfirmed. An advertised collection must return successful JSON with a Members array; authorization, permission and transport failures fail the test. The whole probe is limited to 16 seconds. A successful probe does not prove complete storage/sensor coverage. Regular polling begins after saving an enabled device. **Enable notifications for this device** permits delivery only through globally enabled channels with matching event filters. Paused devices can retain old alarms, but their measurements are not current.

Build 0021 reuses one verified HTTP/1.1 TLS connection throughout an iDRAC7 probe or poll, avoiding repeated slow DHE handshakes. A closed idle connection permits one safe GET retry on a freshly verified connection. Certificate validity is checked before every request; every new stream must match the imported certificate before HTTP credentials are sent. Requests remain limited to 20 seconds and full polling to 90 seconds. Existing device settings and pins can be retained when updating from 0020.

Build 0022 reads hardware resources before hardware-log history. A later malformed response or reached scan limit no longer erases measurements already received. Partial scans are saved with explicit warnings, including the reason and resource path; the timestamp means **Last saved poll**, not complete coverage. Root-access, sign-in and certificate failures remain fatal and now give a classified path/reason in the active alarm. A successful three-collection probe still does not establish that every deeper endpoint is accessible or the complete scan fits its limits. Existing settings can be retained when upgrading from 0021.

Retargeting resets snapshot/old target state and cancels pending deliveries. Pausing, disabling notifications or removing a device also cancels affected pending jobs. Device deletion removes credentials and active device state while preserving event/audit history. Each administrative change is recorded in the audit log. Concurrent edits use revisions; obsolete poll results cannot overwrite a newer configuration or a completed restore.

The interface is available in German/English. Browser language choice is not an access-control setting. Credentials are encrypted locally and never returned to the browser. The service independently checks DSM session/groups, HTTPS, Origin, DSM token and package CSRF for changes. See [Languages](LANGUAGES.md), [Architecture](ARCHITECTURE.md) and [Notifications](NOTIFICATIONS.md).

Build 0023 uses an advertised temporary Redfish authentication session when available, so the password is not rechecked for every hardware resource. The session is logged out after the probe/poll; unsupported session creation retains Basic authentication. Hardware reads remain GET-only; POST/DELETE are limited to that authentication session. This follows [Dell session authentication](https://www.dell.com/support/manuals/en-ca/poweredge-t130/idrac8_redfishapiguide_2.70.70.70/redfish-authentication-and-authorization?guid=guid-d572792f-afd2-499a-bf12-38a6778b9bbc&lang=en-us).

The existing `idrac7` profile is now labelled **iDRAC7/8 compatibility** and allows a complete scan up to 300 seconds. Standard retains 90 seconds. The UI shows the budget and the pause after each completed scan. Devices never overlap their own polls. The compatibility profile's freshness threshold includes its full scan budget plus two configured pauses, avoiding stale classification during an expected longer scan. Existing settings, certificate pins and passwords are retained on upgrade. Critical hardware alarms remain separate from coverage warnings.

Build 0024 shows explicitly disabled functions, positively empty controllers and PowerControl measurements without health status as **Not applicable**, with a reason. These rows remain visible but do not make an otherwise healthy device **Not fully assessable**. Unexplained unknowns, unavailable inventories, actual faults and stored alarms continue to affect the overall state. Disabling a function does not confirm recovery from a previously reported fault. At least one assessable hardware state is required for an OK overall result.

Build 0034 uses explicit neutral labels: **Not present**, **Information**, **Controller without drives** and **Disabled**. On the tested iLO 5, this explains absent optional fan/temperature placeholders, an untyped PowerControl measurement and both advertised representations of each empty SATA controller. The SATA exception requires healthy, complete, SATA-only inventory evidence; missing Volumes alone is insufficient. Component names remain unchanged. These labels do not confirm recovery or remove retained alarms. Fresh polling is required after upgrading to populate the new applicability reasons.

Build 0027 accepts one optional trailing slash on both advertised Redfish session collections and returned session resources, as used by iLO 5. Requests keep the exact advertised/returned URL. Sessions must remain within the same origin and the collection used for login; nested, encoded, empty and malformed session IDs remain rejected. Pinned authentication writes use fresh verified TLS connections; POST requests are not automatically replayed after network failure. Hardware GETs retain connection reuse and the existing bounded safe retry.

The connection test now gives specific translated errors for invalid/unsupported responses, response-size limits and HTTP failures. The compatibility mode's UI name includes iLO; its stored `idrac7` value and existing device settings are unchanged. The tested iLO factory certificate lacks a complete issuer chain and an IP SAN, so Standard mode still correctly rejects it. To use the supplied factory certificate, explicitly choose the compatibility mode and import that exact certificate; alternatively configure a trusted certificate chain and matching DNS name for Standard mode.

## SNMP configuration on the development branch (P5)

Select **Primary polling protocol**: Redfish or SNMP. One primary collector owns regular hardware reads; trap reception is optional and separate. Existing Redfish devices retain their HTTPS/trust behavior. SNMP fields include agent host/UDP port (default 161), profile, request timeout/retry, explicit v1/v2c or v3 authPriv, SHA-1/SHA-256, AES-128 and optional v3 context. The generic profile assesses SNMP availability and system identity; select a suitable supported manufacturer or UPS profile for the corresponding hardware/operating-state coverage. A bounded probe shows version, security assurance, engine identity where authenticated, supported/missing data groups and elapsed time. Community access is explicitly not cryptographically verified. A digest failure or timeout does not identify one particular wrong setting; check both passphrases, SHA selection, version and network without automatic downgrade.

**Receive SNMP traps** has its own source IP allowlist, security, credentials, profile, context and approved engine IDs. Credentials are never returned: choose keep, replace or clear; clear is offered for disabled inputs. Changing a credential scope requires explicit replacement/clearing. Switching away from SNMP clears retired polling credentials. For a Redfish primary, the optional SNMP responder target serves only authenticated sender verification and uses trap credentials, with no second periodic SNMP collector or extra polling secret.

To enroll v3: save the trap credentials and responder target, reopen the device, select **Check saved sender identity**, review the observed target/engine/boots, then explicitly **Use verified engine ID in draft**. This replaces the previous sender-engine allowlist in the draft, requires re-entering trap credentials and takes effect only on Save. A probe alone grants no approval. Changing the draft invalidates its review result; stale revisions are rejected by the backend. Engine replacement requires a new review; normal boots increments/restarts renew the verification baseline through an authenticated query.

Under **SNMP trap receiver**, enable the global receiver and select a free UDP port (default 1162, configurable 1024–65535) and local IPv4/IPv6 addresses. Standard trap port 162 differs from polling port 161. Configure the matching destination on the controller and its permitted source IP on the device. Actual local binding, verification state, accepted receipt time and rejection counters have separate meanings. A successful local bind is not proof of controller reachability. Send a controller test trap and refresh bounded receipts; compare source, device/revision, version, verification, OID, engine and handling. Imported/old-revision and loopback receipts are explicitly distinguished from evidence for the current controller configuration.

The dashboard shows primary source, last saved poll, last accepted trap and coverage independently. Known trap faults remain visible when poll measurements are stale; only a fresh covering primary read confirms recovery. Event-only trap delivery is an explicit default-off notification filter. See [P5 implementation/verification](SNMP-P5-RESULTS.md); real DSM/controller acceptance remains P7.

## Synology DSM polling

Enable SNMP in the target NAS Control Panel, then choose **SNMP** as the primary
protocol and **Synology DSM** as the hardware profile. Enter the target address,
its configured agent port (normally UDP 161) and matching credentials. Use the
connection test before saving. v1/v2c compatibility and v3 authPriv with
SHA-1/SHA-256 and AES-128 use the existing explicit security selection; actual
algorithm availability depends on the target DSM version.

The profile reads system partition, power, fan, temperature, disk and RAID data.
A system-partition result is not a full hardware rollup. DSM has no SNMP trap
support according to Synology's guide; leave trap reception disabled for this
source. See [profile coverage and validation](SNMP-SYNOLOGY-RESULTS.md).

## Generic system and network SNMP profiles

**Generic · availability and system** assesses the current SNMP identity/uptime
exchange. Optional ENTITY inventory and sensors can extend the display, but
unsupported optional groups do not prevent OK within this profile's scope.
System details and separate service/host uptimes are available in the device
view. This scoped OK does not confirm full hardware health.

**Network · generic** adds automatic interface discovery on the configured
target, link state, speed, traffic/error/discard rates and optional duplex.
Only ports previously observed active raise subsequent link-loss alarms; the
baseline survives restart. Initially disconnected ports and loopback interfaces
are neutral. A disabled or disappeared port cannot clear an earlier fault.
Rates need two valid samples and may be omitted on reset or ambiguous v1 wraps.
See [profile contracts and limits](SNMP-GENERIC-NETWORK-RESULTS.md).


### UPS profiles (build 0054)

Choose **APC UPS**, **Eaton UPS** or **UPS · Generic (RFC 1628)** explicitly.
These are polling profiles: PowerNet, xUPS or UPS-MIB must be exposed by the
network management card and accessible to the configured account/community.
The generic UPS profile is separate from the existing generic availability
profile. A manufacturer name alone is not proof of supported MIB objects.

Battery power and bypass are operational warnings; low/depleted/faulted/missing
batteries and output loss are critical where explicitly reported. AVR boost/trim
are normal regulation. Unknown newer modes remain unknown. Optional measurements
and phase tables do not block assessment simply because they are absent.
Numeric readings do not create new alarm thresholds; UPS-reported alarms do.
An unconfirmed/partial empty alarm table cannot clear retained faults. Alarm
summaries use condition identities, so row renumbering keeps acknowledgement and
a newly reported cause requires review again.

No power switching, shutdown commands or self-tests are sent to the UPS. Existing
trap reception remains separate; this build adds no UPS component mappings for
traps. See [UPS scope, mappings and acceptance](SNMP-UPS-RESULTS.md).
