# NAS acceptance checklist and confirmed results

The package supports Synology DSM 7.0 and later on x86_64 NAS platforms (minimum DSM build: `7.0-40761`). NAS acceptance records below use RS2421RP+ / v1000 / DSM 7.4.1-90080 and DS220+ / geminilake / 7.4.1-90080. The user installs packages manually. No agent-side NAS login, package installation or hardware configuration change is implied by local checks.

## Confirmed by the user

Installation/service/menu, internal DSM window, positive DSM sign-in after session/cache fixes, device creation/editing including certificate/address/password, R340 polling, PS1 critical handling, Gmail test and automatic reminder delivery, native desktop test/critical reminder with resolved details and error severity. App backup/restore from build 0016 was also tested successfully. The user confirms successful installation of the grouped DSM 7 x86_64 build 0018.

The user confirms that the functions have been tested with Dell PowerEdge R420/iDRAC7, Dell PowerEdge R330/iDRAC8, Dell PowerEdge R340/iDRAC9 and HPE ProLiant DL160 Gen10/iLO 5 v3.22, as listed in the [README](../README.md). The R330 also passed a complete authorized live collector run and overall health calculation; complete read-only iLO 5 collection is recorded for build 0027. See [Hardware compatibility](HARDWARE-COMPATIBILITY.md).

## Current acceptance (language changes from 0017; grouped package from 0018)

1. Grouped DSM 7 `x86_64` build 0018 installation on the RS2421RP+ is confirmed. Check start/normal polling after the upgrade. The Package Center title should be **Hardware Monitor**. Check that the UI build marker says `0.8.0-0018`.
2. Switch Automatic/Deutsch/English. Check navigation, device editor, validation/error text, event filters, audit labels, backup confirmation and date presentation. Verify Automatic against the actual DSM/browser language.
3. Save English independently for email and desktop. Preview the current template; existing custom text must remain unchanged. If wanted, explicitly use the English default template. The manual desktop test uses interface language and still targets only the signed-in user.
4. Export CSV in each interface language. Check translated headings/new generated events and unchanged older/manufacturer text. The export includes all retained matching rows, not only the 100 loaded in the UI.
5. Restore a previously saved build-0016 archive when replacement of the current dataset is intended. Review counts and confirmation. Check preserved credentials/history, paused devices/channels and the audit entry; deliberately review before re-enabling delivery.

The new native English keys and format migration remain locally tested, not yet NAS-confirmed. Grouped DSM 7 SPK installation is user-confirmed; normal operation still needs acceptance. No artificial hardware fault is required for these UI checks.

## Hardware checks still useful

Compare running/offline PSU, fan, temperature and storage/RAID readings with iDRAC. For an existing fault repaired in normal operation, verify a single component recovery and retained summaries as appropriate. Later test two independent physical faults and partial recovery, plus HPE iLO 5 without Advanced. Missing/null data must never silently become healthy. Network/TLS/authentication failures must remain monitoring failures rather than false hardware recoveries.

Earlier R340 GET records showed PS1 Critical/UnavailableOffline with 0 W and a healthy PS2; this established the reported fault, not whether the PSU, supply or cable was the physical cause. A transient Lifecycle-log page returned HTTP 500; later direct-IP and hostname comparisons showed changing collections and successful valid final pages. Those observations did not prove a hostname problem or one permanent pagination defect. See [Live records](LIVE-TEST-R340.md).

Check start/stop/restart/upgrade, logout/session expiry, denied users and viewer roles before wider deployment. Full DSM ACL enforcement, directory services, storage-full behavior and long-running resource use remain open. See [Roadmap](ROADMAP.md).
