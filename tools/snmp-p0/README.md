# Isolated SNMP P0 spike

This development harness evaluates the transport/receiver decision for 0.9.0. It
does not add SNMP to Hardware Monitor, alter its database or produce an SPK. All
agent and receiver traffic is restricted to numeric loopback addresses. Use only
synthetic credentials: the JSON test configuration is not a production secret
container and serde/Python copies are not comprehensively zeroized.

Requirements: the project's Rust 1.98.1 toolchain, Python 3.12+, `patch`, Net-SNMP
`snmpd`, `snmpget`, `snmptrap`, and `readelf` for the static artifact check.
For musl, install the Rust `x86_64-unknown-linux-musl` target and run the existing
`sh tools/bootstrap_musl.sh` first. Native prerequisites for the product dependency
compatibility build include a C compiler, make and Perl (vendored OpenSSL).

From the repository root:

```sh
python3 tools/snmp-p0/run.py --musl --audit
```

After populating the dependency cache, add `--offline` to prohibit Cargo network
access. `--audit` separately queries OSV with public package names/versions;
`prepare.py` can download the published candidate if its local archive is missing.
There is no hardware access, controller reconfiguration, recipient delivery or
publication. Reference programs receive generated secrets through private
temporary configuration; the candidate receives them through stdin. Temporary
reference state is removed on exit. The harness needs permission to bind local
UDP sockets, but uses no privileged port or root daemon.

The runner checks formatting, Clippy and Rust tests, builds with the real product
as an optional dependency, then runs independent Net-SNMP cases against the native
binary and, with `--musl`, against the static generic x86-64 binary. Every product
runtime dependency has the same version as the current root lockfile; that root
lockfile and the product manifest are verified together. P2 now uses the same
vendored dependency, including the additional decoded-varbind budget hook.
Recheck this alignment after future product dependency updates.

Builds, reconstructed dependency source, sanitized JSON evidence and advisory
results are under ignored `.build/snmp-p0/`. The separate checked-in `Cargo.lock`
and checksummed archive plus explicit patch make the selected dependency
reproducible. P2's `prepare.py` additionally reconstructs the production source
with both patches and compares every file against the vendor provenance manifest.
`prepare.py` detects changes to reconstructed Rust sources,
manifest or license files and reconstructs the pinned tree before the next run.
No online patch is applied during product installation or service startup.

See the [P0 decision and evidence](../../docs/SNMP-P0-RESULTS.md) for the patch
contract, reference matrix and remaining production work. The patch changes API
access and bounded state configuration in two upstream files; BER, USM, HMAC,
AES and timeliness algorithms remain upstream implementations. The published
crate's MIT/Apache-2.0 license files remain in the reconstructed source.
