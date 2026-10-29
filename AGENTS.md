# Repository instructions for agents

## Keep Cargo lockfiles current

- Always keep every affected tracked `Cargo.lock` synchronized with its manifest
  and path dependencies. This applies to package version bumps as well as changes
  to dependencies, features, workspace membership, or dependency sources.
- The product uses `Cargo.lock`. The separate workspace in
  `tools/snmp-reference/Cargo.toml` uses `tools/snmp-reference/Cargo.lock` and
  depends on the product through the `product-compat` feature. A product version
  bump therefore requires refreshing both lockfiles, even when registry
  dependencies are unchanged.
- Use Cargo to refresh affected lockfiles, preserving existing dependency pins
  unless an upgrade is intended. Do not hand-edit generated lockfiles or remove
  `--locked` from CI/build scripts to work around a stale lockfile.
- Before handing off a Rust manifest or package-version change, validate both
  workspaces with locked dependency resolution:

  ```sh
  cargo metadata --locked --offline --format-version 1 > /dev/null
  cargo metadata --locked --offline --manifest-path tools/snmp-reference/Cargo.toml --features product-compat --format-version 1 > /dev/null
  ```

  If required dependencies are not cached, rerun without `--offline`, retaining
  `--locked`. Run the relevant checks in `docs/DEVELOPMENT.md`, including
  `python3 tools/snmp-reference/run.py --offline` for reference-harness changes.
- Review and include all affected lockfile diffs with the corresponding change.
  Shared registry package versions in the product and reference lockfiles must
  remain aligned; the reference runner enforces this.
- `vendor/async-snmp-0.18.1/Cargo.lock` belongs to the provenance-verified upstream
  snapshot. Change it only as part of an intentional vendor update using the
  documented provenance workflow.
