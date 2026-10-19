# Uninstalling Hardware Monitor

Starting with build **0.8.0-0031**, Package Center's uninstall wizard offers **Delete all Hardware Monitor data and settings**. The checkbox is **off by default**. The wizard uses DSM's language, with German and English translations and English as the fallback.

- Leave it unchecked to retain the package's data for reinstallation.
- Select it to permanently remove devices, encrypted device/SMTP credentials, settings/templates, snapshots, events, alarm/acknowledgement and audit history, delivery state, service logs, the local encryption key, and all automatic local upgrade backups.

Cleanup removes the contents of the package's persistent `etc` directory, including hidden files and SQLite sidecars. It retains DSM's directory and symlink. Downloaded `.hmbackup` files, exported CSV files, external CA files and other packages' data are outside this cleanup. Deleting files does not promise forensic secure erasure or remove copies held by NAS snapshots or external backup systems.

With retained data, reinstalling the package reuses the previous settings and credentials. With deleted data, a new installation starts empty. An encrypted app backup downloaded beforehand can be restored through the app. Local upgrade backups are deleted together with the live data and cannot be used afterwards.

Install or upgrade to build 0031 or later **before uninstalling**: previously installed SPKs do not contain this wizard or cleanup hook. Updates never request data deletion and the cleanup hook explicitly ignores `UPGRADE`, even if a deletion selection is present. Missing, false or unrecognized selections retain data, including noninteractive uninstall requests without this choice.

## Implementation and verification

`tools/uninstall_wizard.py` generates `WIZARD_UIFILES/uninstall_uifile.sh`, `uninstall_uifile_enu.sh` and `uninstall_uifile_ger.sh` at SPK assembly time. The scripts read DSM's `productversion` from `/etc.defaults/VERSION`: before 7.2.2 they emit the native JSON multiselect form; from 7.2.2 they emit a Vue 2 JSONP component using DSM's existing runtime. No additional frontend dependencies or network requests are required. Both formats submit `wizard_delete_data`; the checkbox starts unchecked on every opening. Missing/invalid version metadata fails wizard generation rather than guessing a renderer.

`postuninst` clears data only for `SYNOPKG_PKG_STATUS=UNINSTALL`, `wizard_delete_data=true` and the expected package identity. It runs as the ordinary package user. The resolved configuration path must be a DSM volume's `@appconf/HardwareMonitor` or the older `/usr/syno/etc/packages/HardwareMonitor` location. It never follows nested symlinks while deleting contents, and reports cleanup errors with a nonzero exit code.

`tools/tests/test_uninstall.py` executes the hook against disposable DSM-like directories and exercises both wizard formats with simulated DSM globals. `tools/check_spk.py` repeats these tests against the actual hook and wizard scripts extracted from the SPK, in addition to checking script syntax and executable modes. This establishes local behavior; native Package Center rendering, environment propagation and removal timing still require NAS acceptance.

References: [Synology uninstall wizard](https://help.synology.com/developer-guide/synology_package/wizard/WIZARD_UIFILES_v2.html), [official Vue wizard example](https://github.com/SynologyOpenSource/ExamplePackages/tree/master/ExamplePackage/WIZARD_UIFILES), [script variables](https://help.synology.com/developer-guide/synology_package/script_env_var.html), [lifecycle order](https://help.synology.com/developer-guide/synology_package/scripts.html), [persistent directories](https://help.synology.com/developer-guide/integrate_dsm/fhs.html).
