# Grouping summary alarms without hiding independent faults

Redfish models relationships rather than one universal device tree. A ComputerSystem, chassis or subsystem can report an aggregate warning/critical state caused by one or several dependent components. Grouping uses explicit containment/dependency links, resource types, Health/HealthRollup and available Conditions/origin data. It never relies on similar names or URI depth alone.

On the read-only R340 test, ComputerSystem and chassis were critical and linked to power supplies through PoweredBy relationships. While the server was off, PS1 and the power subsystem could return null health. Their previously confirmed critical states were retained; unknown data did not clear them.

## Current policy

Known aggregate types are ComputerSystem, Chassis, PowerSubsystem, ThermalSubsystem, Power, Thermal and Storage. A component such as a drive, fan or power supply is not classified as an aggregate merely because its type name contains another word. Independent/unknown-origin Conditions, cycles and stronger unexplained summaries prevent unsafe grouping.

A faulty aggregate can be associated with multiple reachable faulty components of sufficient severity. The deepest appropriate components are preferred, while independent component faults remain separate. The local database retains all states/events; only redundant summary delivery jobs are cancelled. The UI exposes associated summaries in a collapsed list with their anchors and confirmation time.

The local two-cause test uses a failed PSU and drive. Both produce their own email/desktop jobs. PSU recovery does not recover the drive or suppress its later reminder. The final drive recovery does not create extra summary recoveries when the explicit conditions for grouping are satisfied. A still-faulty summary becomes separately announced if its formerly explanatory component recovers and no suitable anchor remains.

An unknown retained component can emit a carefully worded reminder only when a freshly faulty linked summary supports the ongoing fault and the reminder is due. The old component confirmation timestamp is preserved. This does not pretend that a new critical measurement was received.

## Limits

Relationships and severity do not prove physical causality. A second cause that the BMC never reports individually cannot reliably be inferred from an unchanged critical summary. Missing links, incomplete coverage or stronger/unexplained aggregate conditions retain a separate alarm. Real multi-fault testing and HPE iLO 5 acceptance are still pending.

Primary model references: [DMTF Redfish data model](https://redfish.dmtf.org/schemas/v1/DSP0268_2025.3.pdf) and [Resource schema](https://redfish.dmtf.org/schemas/v1/Resource.json). Existing sanitized fixture: `tests/fixtures/dell-r340-hierarchy.json`.
