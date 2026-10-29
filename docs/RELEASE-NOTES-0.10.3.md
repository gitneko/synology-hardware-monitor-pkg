# Hardware Monitor 0.10.3

Package build: **0.10.3-0077**.

## Repairs interrupted during large schema-1 upgrades

Service start now completes private-state initialization and migration in the controller before it starts the daemon readiness timer. The 120-second watchdog still bounds ordinary daemon/listener startup. It can no longer kill a progressing pre-migration backup simply because a large old database takes longer than two minutes. Startup still requires an authenticated local API listener before reporting success. Migration failures remain errors, and the existing atomic pre-migration database/key backup is retained.

Explicit native CLI commands now take precedence over an inherited `GATEWAY_INTERFACE` on the ordinary executable. A named `api.cgi` entrypoint always uses CGI, and environment-based CGI invocation without native arguments remains supported. Lifecycle shell hooks also unset the inherited gateway marker, including pre-upgrade calls to an older executable. This prevents an installation `initialize` call from returning an unrelated HTTP JSON response without initializing anything.

For an already stopped 0074 installation, initialization can also be completed once over SSH as the package user, outside its daemon readiness timer:

```sh
sudo -u HardwareMonitor /bin/sh -c 'unset GATEWAY_INTERFACE; exec /var/packages/HardwareMonitor/target/bin/hardware-monitor initialize'
```

Wait for `Private state initialized`, then retry repair in Package Center. The operation creates the protected database/key backup and performs normal migration; it does not bypass migration checks.

## Included fixes and validation

Includes [Redfish deduplication](RELEASE-NOTES-0.10.1.md) and the [background backup correction](RELEASE-NOTES-0.10.2.md). Tests cover inherited CGI variables on native initialize/version/status, genuine CGI entrypoints, failed initialization and repeated repair. Additional acceptance exercises use a large synthetic schema-1 database and initialization delayed beyond the former 120-second limit. Local tests do not establish final NAS acceptance.

## NAS feedback and source-only UI follow-up

The user confirmed that the reported update/repair works with 0.10.3-0077. This confirms that workflow on the reported NAS, not all controller or deployment combinations.

The subsequent source-only UI change adds space between notification/mail headings and their reload buttons, between the mail reload button and its explanation, and between retention/alarm action buttons. Action groups wrap with spacing on narrow layouts. No additional SPK was requested or built for this follow-up.
