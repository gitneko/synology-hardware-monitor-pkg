# DSM application privileges and the rejected resource probe

Reviewed on 18 October 2026. Application registration, Linux process permissions and resource-worker acceptance are three separate mechanisms.

The user confirmed probe stage 0001 installed and appeared in Application Privileges. The same probe with `sysnotify` and matching `app_privileges` mapping in stage 0002 was still rejected as an exclusive resource. Therefore, registering an application and mapping its category did not release that worker on this NAS. This is empirical evidence for the tested package/firmware, not a universal proof about every possible Synology release.

The suggestion that every app ID must start with `SYNO.SDS._ThirdParty.App.` was not established by the official examples: the resource guide uses a generic unique name, while the official Vue example uses a different class form. Additional prefix/metadata probes were created historically, but their existence is not a confirmed successful NAS result. Further name variations are not an active product plan.

The normal app uses an empty `conf/resource`, `run-as: package`, its own DSM desktop class and service-side verified groups. It does not elevate itself to root. The working desktop command is distinct from registering system events. Current email delivery is the app's own SMTP implementation.

## Work still required

The main app has not completed full native Application Privileges enforcement or viewer menu integration. `allUsers`, grant fields or a browser-reported permission are not substitutes for a trusted backend check. The current backend authorizes verified `administrators` and `hardware-monitor-viewers` groups; only administrators can mutate/export/restore. Directory-service group resolution remains unverified.

References: [sysnotify mapping](https://help.synology.com/developer-guide/resource_acquisition/sysnotify.html), [desktop config](https://help.synology.com/developer-guide/integrate_dsm/config.html), [process privilege config](https://help.synology.com/developer-guide/privilege/privilege_config.html), [official application example](https://github.com/SynologyOpenSource/ExamplePackages/blob/d2849c6fcf14ce72007d14e99a362c3d4f23be0a/ExamplePackage/ui/app.config), [SynoCommunity grant generation](https://github.com/SynoCommunity/spksrc/blob/f372bc0b1985ecb2cb923bf369a255749d58cc6e/mk/spksrc.service.mk#L452). External examples explain source behavior; they do not prove enforcement on the target NAS.
