# Native DSM desktop notifications

The user confirms the desktop test and a critical reminder on RS2421RP+ / DSM 7.4.1-90080, including a red error indication and resolved device/message text. This confirms the deployed native path; the new forced-language sections in build 0017 still need NAS acceptance.

The package invokes the fixed `/usr/syno/bin/synodsmnotify` executable directly, with no shell, fixed application class/keys and a verified saved DSM user as recipient. It does not accept an arbitrary user/group from the client. Manual tests target only the signed-in administrator, enforce existing HTTPS/origin/DSM-token/package-CSRF checks and wait at least 30 seconds between tests.

The NAS reports this usage syntax:

```text
synodsmnotify [-c className] [-t tag] [-e true/false] [-b true/false] [-p html/plain] [--fn fn] [-l info/warn/error] user/group title msg | [--watch ]...
```

Critical events map to `error`, warnings to `warn`, recoveries to `info`; reminders and hardware logs follow event severity. A bounded no-argument usage probe detects `-l` support once before the first invocation. Older helpers are called without the unsupported option; the manual result reports the applied info fallback. A failed submission is not retried immediately with different arguments.

Three positional values populate device, message and event ID. Arguments are separately passed, bounded, control-character sanitized and protected against option-like leading data. Plain-text mode is requested. The package keeps previous language keys intact so historical notifications without parameters are still readable.

In build 0017, `notification_details_en` and `notification_details_de` contain fixed-language keys in both package language directories. The saved desktop language selects the section; manual tests use the interface language. All legacy and current notification keys are preloaded. This avoids requiring a native language-option flag or changing the recipient's DSM language. The test reference is `Test-0017`.

The upstream [Synology command guide](https://help.synology.com/developer-guide/synology_package/show_massage.html) describes the class and package I18N key contract; [I18N](https://help.synology.com/developer-guide/integrate_dsm/i18n.html) and [preloadTexts](https://help.synology.com/developer-guide/integrate_dsm/config.html) describe resource loading. The additional positional argument mechanism was also source-confirmed in [DSM_Update](https://github.com/007revad/DSM_Update/blob/main/dsm_update.sh) and [DSM_Notify](https://github.com/007revad/DSM_Notify/blob/main/src/ui/texts/enu/strings), then confirmed by the user's actual notification display. Those projects are not installed, executed or dependencies of this app.
