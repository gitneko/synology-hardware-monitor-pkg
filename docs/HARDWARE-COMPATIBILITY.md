# Hardware and firmware compatibility

## Supported platform and tested systems

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). Its functions have been tested with iDRAC7, iDRAC8, iDRAC9 and iLO 5 on the systems listed here and in the [README](../README.md).

| Tested system | Evidence |
|---|---|
| Dell PowerEdge R340 / iDRAC9 7.00.00.185 | Read-only live discovery and user-confirmed polling/PSU fault and notification workflows |
| Dell PowerEdge R420 / iDRAC7 2.63.60.62 | Testing confirmed by the user on 19 October 2026; hardware readings and Fan1B/redundancy alarms observed. Earlier polling deadline issues are documented in the historical validation records |
| Dell PowerEdge R330 / iDRAC8 2.86.86.86 | Testing confirmed by the user on 19 October 2026. Authorized 0024 collector test: 116 resources and 2939 log entries, complete coverage without query errors, 70.686 seconds; all four previously unknown observations explained as not applicable, frontend overall OK |
| HPE ProLiant DL160 Gen10 / iLO 5 v3.22 | Authorized read-only account: session login, three protected collections, server details and complete build-0027 collector runs verified with exact certificate pinning; license entitlements were not checked |
| RS2421RP+ / v1000 / DSM 7.4.1-90080 | User-confirmed application deployment and prior-release workflows |

The listed Dell systems and HPE DL160 Gen10 have been tested. This evidence applies to the recorded model/firmware combinations; other models, firmware versions and resources require their own validation.

Build 0018 consolidates DSM 7 delivery into one `x86_64` SPK, covering the documented family containing v1000 and geminilake. Family-wide installer eligibility is not physical-model certification; see [Package architectures](PACKAGE-ARCHITECTURES.md).

The collector follows advertised Redfish resources, selected HPE SmartStorage links and embedded data. It records unavailable/forbidden/missing resources as coverage information; it does not assume all firmware exposes identical objects. HTTP 403 can indicate permissions or licensing and is not treated as proof of either cause alone. Hardware resources use GET only. POST/DELETE are confined to creating and logging out the collector's own temporary authentication session; power operations, firmware updates and storage configuration actions are not invoked.

## Vendor documentation and licensing boundary

Dell documents Redfish across iDRAC7/8 and states that Redfish is included across license levels, while individual operations still require authorization and some authentication integrations have separate license requirements. That supports targeting ordinary read-only accounts, not a blanket guarantee for every OEM resource. [Dell authentication/authorization guide](https://www.dell.com/support/manuals/en-us/idrac7-8-lifecycle-controller-v2.60.60.60/idrac_2.60.60.60_redfishapiguide/redfish-authentication-and-authorization?guid=guid-d572792f-afd2-499a-bf12-38a6778b9bbc&lang=en-us).

HPE documents the iLO RESTful API for iLO 5 and Gen10 storage interfaces. The application requests no Advanced-only control/console functionality. Read-only collection has been demonstrated on the DL160 Gen10 with iLO 5 v3.22. The test did not inspect license entitlements or certify complete coverage without Advanced. [HPE API overview](https://developer.hpe.com/platform/ilo-restful-api/home/), [HPE storage model](https://developer.hpe.com/blog/storage-management-with-redfish/), [HPE iLO licensing information](https://www.hpe.com/us/en/collaterals/collateral.c04154343.html).

Vendor documentation was rechecked on 18 October 2026. It establishes interface availability, not complete application interoperability. No broad claim of universal RAID, OEM sensor or threshold-schema coverage is made. Standard health fields and selected embedded sensor/threshold forms are supported; additional schemas require fixtures and tests. SNMP fallback/traps are not implemented yet.
