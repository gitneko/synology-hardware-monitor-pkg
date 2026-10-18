# Historical read-only Dell R340 records

These measurements are records from 17–18 October 2026, not a fresh scan or a promise that today's counts/status are identical. No new live hardware request was made for the English-language release.

## Initial evaluated run

The explicitly authorized target was a PowerEdge R340 with iDRAC9 Enterprise. Initial reported firmware was 7.00.00.183 and Redfish service version 1.17.0. A restricted account completed verified HTTPS GET discovery. The recorded static 0.1.1 run took 23.17 seconds, reached 117 resources and produced 68 observations (13 OK, 55 Unknown), seven physical-drive resources and four volume resources, three exposing RAID1. The server was off.

The run read 2,751 unique log entries (2,734 Lifecycle and 17 SEL). A repeated query preserved that count without replaying historical alarms. Delivery was disabled. Two early local events described a failed collector attempt and its recovery, not artificially induced hardware errors. Credentials, raw logs and private response data were excluded from public fixtures/packages.

The first live client failure involved embedded URI fragments such as `Thermal#/Temperatures/0`. Those refer to objects already present in JSON and are not separate HTTP targets. The client now avoids those GETs while normalizing embedded data. Expanded log members are also consumed without fetching every entry individually.

## Later fault and pagination records

The powered-on server reported Critical at system/chassis level. PS1 reported Critical/UnavailableOffline with 0 W, while PS2 was OK/Enabled. This exposed the now-fixed offline-fault precedence bug. Later, an off server could return null PSU health while retaining critical aggregate state; the app correctly preserved the earlier fault. No server action or physical fault was triggered by the agent.

One Lifecycle collection reported 2,851 entries: offered pages at skip=2700 and 2800 worked, but the subsequently offered skip=2850 page returned HTTP 500. A deliberately out-of-range skip=3000 also returned 500. This did not prove the earlier skip=2800 report was caused by too few entries.

The user separately authorized a direct-IP comparison without certificate verification for diagnosis. That exception stayed in private diagnostic code; the product retained mandatory TLS verification. Later, with changing counts around 2,909–2,917, valid final pages worked both directly and through the verified hostname. Queries beyond the reported end still returned HTTP 500/Base.1.12.GeneralError. The observations do not prove a hostname/proxy cause or one permanent last-page defect.

The app follows offered pagination, retains actual HTTP diagnostics, retries selected transient errors once and keeps incomplete log coverage visible. It does not hide arbitrary HTTP 500 responses as a successful log end.

## Scope of conclusions

Read access, discovery, persistence and selected health cases were demonstrated. Complete RAID/OEM health interpretation, all running-server sensor values and additional generations were not. Null values are not automatically healthy. The healthy vendor-OEM state of an object is not silently substituted for every missing standard field.

On the NAS, the user later confirmed the integrated UI, credentials/certificate editing, PS1 critical handling and notification workflows. Those supersede early notes that the UI could not add devices. See [Validation](VALIDATION.md), [Hardware compatibility](HARDWARE-COMPATIBILITY.md) and [NAS acceptance](NAS-ACCEPTANCE.md).
