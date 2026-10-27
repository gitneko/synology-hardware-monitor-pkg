# Administrative setup for privileged SNMP trap ports

The trap listener accepts UDP ports **1–65535**, including standard trap port
**162**. Port 0 is invalid; the default remains **1162**. The service continues
to run as the `HardwareMonitor` package user.

If binding a port below 1024 fails with `PermissionDenied`, the receiver editor
shows an administrative setup command. A port conflict or invalid local address
keeps its normal bind error; granting a capability cannot fix those errors.
Failed changes retain the previous saved receiver configuration and binding.
On startup, failed binds leave polling and the UI running and are retried.

## Enable

Connect to DSM over SSH with an administrative account and run:

```sh
sudo /var/packages/HardwareMonitor/target/scripts/setup-trap-port.sh enable
```

The script stops the package through DSM, makes only the service executable
root-owned and executable by the package group (`0750`), assigns exactly
`cap_net_bind_service=ep`, verifies the file capability and restarts the package
through DSM. It does not run the monitoring daemon as root, change the firewall,
change kernel port thresholds or grant capabilities to `ui/api.cgi`.
Both `setcap` and `getcap` must be installed. Missing tools, unexpected package
paths, symlinked executables and executables with multiple hard links are
rejected. A failure after stopping the service leaves it stopped and reports
the problem rather than claiming that setup succeeded.

Return to the receiver editor, reload the dashboard if necessary, save the
desired trap port again and check the **actual bound addresses**. Saving the
port before setup may have failed and retained the old configuration. A
successful package restart alone does not prove that trap reception is active.
Configure the controller with the same NAS address and port and send a test trap;
check receiver counters and accepted receipts. An active bind does not establish
network reachability or sender verification.

The capability permits binding privileged Internet ports generally; Linux does
not restrict `CAP_NET_BIND_SERVICE` to UDP/162. Application configuration chooses
the actual trap port. No automatic administrative command is run by the UI or
package installation/upgrade hooks.

## Check and remove

```sh
sudo /var/packages/HardwareMonitor/target/scripts/setup-trap-port.sh status
sudo /var/packages/HardwareMonitor/target/scripts/setup-trap-port.sh disable
```

`status` verifies the file capability without changing permissions or restarting.
It does not inspect the capabilities of an already-running process. `disable`
stops the package, removes file capabilities, restores package ownership and
mode `0755`, and restarts through DSM. If a privileged port is still configured,
trap reception may then fail while polling and the application remain available.

## Package updates

An update or repair may replace the service executable and remove its file
capability. If the permission warning reappears, run the same `enable` command
again. The script can be run repeatedly. It always operates on the current
installed executable; it does not install a boot task, persist a separate stale
binary or weaken DSM's package-installation checks.

Start/status/stop validate the running daemon using the held service lock,
PID file and kernel-provided Unix-socket peer PID/UID. This remains usable when
file capabilities restrict access to `/proc/PID/exe`, without making the daemon
dumpable or trusting an unverified PID file.

## Evidence and limits

On 23 October 2026, the separate UDP/162 package probe demonstrated
that a non-root DSM package process with exactly `CapEff=0x400` can bind
`0.0.0.0:162`; the identical executable without the capability failed with
`EACCES`. DSM rejected the unsigned probe that requested the capability through
`conf/privilege`, while the administrator-applied file capability worked.

The product keeps `conf/privilege` at `run-as: package` with no capability or
optional-resource request. Local tests cover port validation, error
classification, translated UI guidance, administrative script behavior using
command doubles, and daemon management of a protected non-dumpable subprocess.
The user subsequently confirmed that SNMP traps work in the deployed
application, including reception after package and DSM restart, and later the
0043 → 0062 upgrade; see [current acceptance](VALIDATION.md#current-acceptance).
These reports do not explicitly identify every listener port or helper execution
step. The successful capability probe and reported product reception therefore
remain separate evidence; no new native port/helper test is claimed here.

References: [Synology privilege config](https://help.synology.com/developer-guide/privilege/privilege_config.html),
[Synology signing/development-token restrictions](https://help.synology.com/developer-guide/getting_started/system_requirement.html),
[Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html),
[Unix socket peer credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
