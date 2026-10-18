# Device management

Administrators can add, edit, test, pause and remove devices in the DSM application. The user confirms creation/editing, including address, password and certificate changes, on the test NAS. Viewer access is read-only; full DSM Application Privileges/menu integration remains separate unfinished work.

Use the management controller's HTTPS origin, for example `https://bmc.example/`, without a Redfish path, credentials or query string. Enter a read-only BMC username/password. The app follows advertised resource links rather than assuming one fixed system ID. Polling intervals are 30–86,400 seconds; optional reminders must be at least five minutes apart.

HTTPS certificates and hostnames are always verified. Publicly trusted certificates or an imported private CA/server certificate are supported. Import PEM certificates only, never private keys. There is no production switch to disable TLS verification. Changing the endpoint or username requires a new password; otherwise a blank password preserves the saved secret. A CA change keeps hostname checks active.

**Test connection** checks HTTPS and Redfish authentication without saving the device. A successful probe does not prove complete storage/sensor coverage. Regular polling begins after saving an enabled device. **Enable notifications for this device** permits delivery only through globally enabled channels with matching event filters. Paused devices can retain old alarms, but their measurements are not current.

Retargeting resets snapshot/old target state and cancels pending deliveries. Pausing, disabling notifications or removing a device also cancels affected pending jobs. Device deletion removes credentials and active device state while preserving event/audit history. Each administrative change is recorded in the audit log. Concurrent edits use revisions; obsolete poll results cannot overwrite a newer configuration or a completed restore.

The interface is available in German/English. Browser language choice is not an access-control setting. Credentials are encrypted locally and never returned to the browser. The service independently checks DSM session/groups, HTTPS, Origin, DSM token and package CSRF for changes. See [Languages](LANGUAGES.md), [Architecture](ARCHITECTURE.md) and [Notifications](NOTIFICATIONS.md).
