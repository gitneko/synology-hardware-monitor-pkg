# Hardware and firmware compatibility

## Demonstrated versus intended support

The maintained package targets DSM 7 on x86_64 platforms.

| Target | Evidence |
|---|---|
| Dell PowerEdge R340 / iDRAC9 Enterprise | Read-only live discovery and user-confirmed polling/PSU fault and notification workflows; initial recorded firmware 7.00.00.183, Redfish 1.17.0 |
| Dell R420 / iDRAC7 2.63.60.62 | User confirms hardware readings on 0022, including critical Fan1B/redundancy reports; full scan hits the 90-second deadline. 0023 adds session authentication and a 300-second compatibility budget; full NAS acceptance pending |
| Dell iDRAC8 2.86.86.86 | Authorized 0024 collector test: 116 resources and 2939 log entries, complete coverage without query errors, 70.686 seconds; all four previously unknown observations explained as not applicable, frontend overall OK; NAS installation pending |
| Dell iDRAC7 and later generations | Intended scope; no claim that every model/firmware/resource has passed live acceptance |
| HPE ProLiant Gen10 / iLO 5 3.22 without Advanced | Intended acceptance target; API and selected OEM-link support exist, live coverage/licensing validation is pending |
| RS2421RP+ / v1000 / DSM 7.4.1-90080 | User-confirmed application deployment and prior-release workflows |

Build 0018 consolidates DSM 7 delivery into one `x86_64` SPK, covering the documented family containing v1000 and geminilake. Family-wide installer eligibility is not physical-model certification; see [Package architectures](PACKAGE-ARCHITECTURES.md).

The collector follows advertised Redfish resources, selected HPE SmartStorage links and embedded data. It records unavailable/forbidden/missing resources as coverage information; it does not assume all firmware exposes identical objects. HTTP 403 can indicate permissions or licensing and is not treated as proof of either cause alone. Hardware resources use GET only. POST/DELETE are confined to creating and logging out the collector's own temporary authentication session; power operations, firmware updates and storage configuration actions are not invoked.

## Vendor documentation and licensing boundary

Dell documents Redfish across iDRAC7/8 and states that Redfish is included across license levels, while individual operations still require authorization and some authentication integrations have separate license requirements. That supports targeting ordinary read-only accounts, not a blanket guarantee for every OEM resource. [Dell authentication/authorization guide](https://www.dell.com/support/manuals/en-us/idrac7-8-lifecycle-controller-v2.60.60.60/idrac_2.60.60.60_redfishapiguide/redfish-authentication-and-authorization?guid=guid-d572792f-afd2-499a-bf12-38a6778b9bbc&lang=en-us).

HPE documents the iLO RESTful API for iLO 5 and Gen10 storage interfaces. The application requests no Advanced-only control/console functionality and is intended to work without Advanced. Complete resource availability on iLO 5 3.22 without that license has not been demonstrated on target hardware; the documentation does not claim otherwise. [HPE API overview](https://developer.hpe.com/platform/ilo-restful-api/home/), [HPE storage model](https://developer.hpe.com/blog/storage-management-with-redfish/), [HPE iLO licensing information](https://www.hpe.com/us/en/collaterals/collateral.c04154343.html).

Vendor documentation was rechecked on 18 October 2026. It establishes interface availability, not complete application interoperability. No broad claim of universal RAID, OEM sensor or threshold-schema coverage is made. Standard health fields and selected embedded sensor/threshold forms are supported; additional schemas require fixtures and tests. SNMP fallback/traps are not implemented yet.
