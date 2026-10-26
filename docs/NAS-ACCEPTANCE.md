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

## Build 0034 iLO applicability (pending NAS acceptance)

1. Upgrade to build 0034, reopen Hardware Monitor and wait for a completed fresh iLO poll.
2. If the reported configuration is unchanged, verify **Not present** for Fan 1-4 and the 19 absent temperature sensors, **Information** for PowerControl consumption, and **Controller without drives** for the four SATA representations. Vendor component names stay unchanged; controller representations are not merged by name.
3. Check that the failed physical drive and associated alarms still have their actual fault state. A retained fault on an absent component must not be cleared or unacknowledged merely because its reading is unavailable.
4. Compare unknown rows for active components and query failures separately; they must remain **Not fully assessable** when no positive exclusion evidence exists. No deliberate hardware fault is required for acceptance.

## Build 0033 manual email replay (pending NAS acceptance)

1. Upgrade to build 0033 and open Events as a DSM administrator. Select a recorded alarm, recovery or hardware log, including an acknowledged alarm. Viewers must not have the resend action.
2. Save the intended SMTP template, reopen the event's resend dialog and select exactly the alarm-server recipient. Verify the preview retains the original event ID/time and has no automatic TEST label.
3. Explicitly request one submission. Compare the received subject/body and parser behavior with the preview and inspect the separate manual history. Original delivery status, event count, raw alarm health and acknowledgement must remain unchanged.
4. If another copy is needed, create a new preview and submit it. Confirm a new Message-ID while the original event ID/time remain the same. The alarm server may still deduplicate using those original fields.
5. Compare SMTP failure/cancellation indicators and stored history after application restart. This build was checked against loopback SMTP and a synthetic browser fixture; no production alarm server was contacted during implementation.

## Build 0032 HPE SmartStorage (pending NAS acceptance)

1. Upgrade to build 0032 and wait for a fresh completed iLO poll. The authorized development collector verified the live hierarchy; installation on DSM has not yet been confirmed.
2. Compare the physical disk rows and locations with iLO. If the observed fault is unchanged, disk `1I:1:1` must be Critical and disk `1I:1:2` OK. The device must show Critical rather than only the parent Warning.
3. Inspect the failed drive's associated summaries: System, Chassis, SmartStorage, array controller and logical drive. Their raw reported Warning states remain inspectable, while notifications are grouped to the concrete drive fault. Existing event history remains intact.
4. Verify that unrelated hardware alarms still appear separately. No deliberate hardware failure is required. If an operator acknowledges an already verified fault, the resulting derived status must not conceal another newly observed disk or controller fault.

## Build 0031 optional uninstall cleanup (pending NAS acceptance)

Use a disposable test installation/dataset, with an encrypted app backup downloaded first if its contents need to be retained. No automated agent-side NAS uninstall is part of local validation.

1. Upgrade to build 0031. Verify that existing devices/settings/history and local upgrade backups survive the upgrade.
2. Open the uninstall wizard in German and English. Verify the checkbox is visible and unchecked, the scope is clear, and uninstall can continue while it remains unchecked. Cancel and reopen; it must start unchecked again.
3. Uninstall with the checkbox unchecked. Reinstall and confirm the same data and credentials are present.
4. Uninstall with the checkbox checked. Confirm the package configuration contents, including `private` and every `backup-*` directory, are gone. Downloaded backups/exports and neighboring packages must remain intact. Reinstall and confirm an empty configuration.
5. Verify both the older JSON wizard on DSM 7.0–7.2.1 and the Vue wizard on DSM 7.2.2 or later. Local simulated rendering does not establish either native wizard's behavior.

See [uninstall behavior and implementation](UNINSTALL.md).

## Build 0042: retention, device log selection and large archives

Use the new **Backup** page before manually cleaning important history. Existing installations receive 90-day event and hardware-log defaults, with a 24-hour review period before the first automatic cleanup. No NAS installation or production cleanup was performed by the agent.

1. Upgrade to 0042. Check both independent periods, set/save each, and verify that a service restart preserves the automatic deadline. `0` disables age deletion only for the corresponding history type. The audit view should explain its fixed 10,000-entry cap.
2. Create a complete encrypted backup of the existing large database before cleanup. Confirm progress, download through the native DSM window, private temporary-file cleanup and reasonable service/browser RAM use. Test cancelling an export and creating a fresh one.
3. Preview cleanup, check both counts and the preserved-undated count, then explicitly confirm **Clean up now**. Confirm progress/cancellation and the audited outcome. SQLite's physical database file need not shrink; reclaimed pages are reused. Pending deliveries and active/acknowledged hardware faults must remain.
4. In device settings test Disabled, All available and Newest N. Disabled must still collect hardware readings. Newest N requires chronological query support from that controller/firmware; unsupported queries must show incomplete coverage. Retention still applies to stored and newly fetched entries, even when N changes. Check that expired controller entries do not return after the next poll.
5. On a disposable installation/dataset, upload/check the large archive, confirm restore, and verify exact history counts plus device/SMTP credentials under the destination key. Devices/channels must remain paused and old pending jobs cancelled. Also inspect a backup from a prior build. Exercise wrong-password, damaged-file, interrupted-upload and cancel-before-commit paths; keep the live dataset unchanged on failure.
6. Refresh/reopen the page while a server job runs. Check session-bound resume/download, cancellation, one-hour expiry and explicit discarding of temporary backup jobs. Restart the service during a cancelled/incomplete job and confirm orphan files are removed.

The local checks could not exercise DSM's CGI/socket/native lifecycle in this environment because socket creation is denied. The ordinary CI pipeline retains these integration checks; run them in an unrestricted development runner and complete this NAS acceptance before treating the build as production-accepted.


## Build 0043: authenticated native backup download

1. Upgrade and reopen the versioned 0043 app. Upgrade restarts the service and invalidates temporary jobs, so create a new backup.
2. After completion, explicitly click **Download completed backup**. Verify that the browser saves `HardwareMonitor-backup.hmbackup` and that it can be inspected with the backup password. Test with DSM's CSRF protection enabled. A large file must still stream without loading the archive into JavaScript memory.
3. With an expired DSM session or an expired/discarded job, verify that the app reports an error before initiating a download. An HTML or JSON error must never be offered as a successful backup file. Confirm the metadata check is `HEAD` with an empty body and that its content length matches the subsequent file.
4. Repeat from the integrated DSM window and after revisiting a completed job. Cookie, administrator role and originating-session checks must still reject other users/sessions.
