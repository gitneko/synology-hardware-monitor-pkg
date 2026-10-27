# Isolated SNMP library reference harness

This development harness verifies the pinned patched library independently of
the product daemon/vault/database. It produces no SPK. All traffic is restricted
to numeric loopback addresses and synthetic credentials in private temporary
files/stdin. JSON/serde/Python copies are not a complete secret-erasure boundary.

Requirements: project Rust toolchain, Python 3.12+, `patch`, Net-SNMP `snmpd`,
`snmpget`, `snmptrap`, C build tools/Perl and `readelf`. For static checks install
the musl target and run `sh tools/bootstrap_musl.sh`. From the repository root:

```sh
python3 tools/snmp-reference/run.py --offline --musl
```

`--audit` queries OSV with public dependency names/versions. Preparation may
retrieve the pinned crate if its archive is missing; populate the cache before
an offline run. Runtime test secrets are temporary and never report contents.
The harness requires local socket permission, no privileged port or root daemon.

`prepare.py` reconstructs the archive and patch chain, checks production files
and omitted upstream examples/CI against `vendor/async-snmp-provenance.json`,
and retains licenses. `run.py` verifies dependency alignment with the product
manifest/root lock, formatting, Clippy, unit tests and 20 independent reference
cases on native and optional static binaries. Rust sources/manifest/licenses are
hashed to prevent stale reconstruction reuse. Reports/builds are ignored under
`.build/snmp-reference/`. No patch is applied during product installation/startup.

See [Development](../../docs/DEVELOPMENT.md#snmp-dependency-and-reference-tests),
[Architecture](../../docs/ARCHITECTURE.md#receiver-identity-and-alarm-ordering) and
[Validation](../../docs/VALIDATION.md#local-regression-coverage) for the API
boundary, budgets, patched-source policy and evidence limits. Original upstream
BER/USM/HMAC/AES/timeliness algorithms remain; polling hints never establish
freshness or alter the strict receiver clock.
