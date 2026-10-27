#!/usr/bin/env python3
"""Reproduce the isolated library checks; never builds or publishes an SPK."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tomllib

from prepare import verify_vendor, source_hash

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORK = ROOT / '.build/snmp-reference'
TARGET = 'x86_64-unknown-linux-musl'


def run(*args, env=None, capture=False):
    return subprocess.run(args, cwd=ROOT, env=env, check=True,
                          text=True, stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='Use cached Cargo dependencies only')
    parser.add_argument('--musl', action='store_true', help='Also build and reference-test the static binary')
    parser.add_argument('--audit', action='store_true', help='Query OSV for the locked dependency versions')
    parser.add_argument('--musl-prefix', type=Path, default=ROOT / '.build/musl')
    args = parser.parse_args()
    source = verify_vendor()
    product_lock = tomllib.loads((ROOT / 'Cargo.lock').read_text())['package']
    reference_lock = tomllib.loads((HERE / 'Cargo.lock').read_text())['package']
    product_versions = {(entry['name'], entry['version']) for entry in product_lock
                        if entry.get('source', '').startswith('registry+')}
    product_names = {name for name, _ in product_versions}
    if any((entry['name'], entry['version']) not in product_versions
           for entry in reference_lock
           if entry.get('source', '').startswith('registry+') and entry['name'] in product_names):
        raise RuntimeError('Reference/product dependency version mismatch; review lockfiles')
    env = dict(os.environ, CARGO_TARGET_DIR=str(WORK / 'target'))
    manifest = str(HERE / 'Cargo.toml')
    options = ['--locked', '--manifest-path', manifest, '--features', 'product-compat']
    if args.offline:
        options.append('--offline')
    run('cargo', 'fmt', '--manifest-path', manifest, '--check', env=env)
    run('cargo', 'clippy', *options, '--all-targets', '--', '-D', 'warnings', env=env)
    run('cargo', 'test', *options, env=env)
    run('cargo', 'build', *options, env=env)
    native = WORK / 'target/debug/hardware-monitor-snmp-reference'
    run('python3', str(HERE / 'integration.py'), str(native),
        '--report', str(WORK / 'reference-native.json'), env=env)
    evidence = {
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'rustc': run('rustc', '--version', capture=True).strip(),
        'net_snmp': run('snmpget', '--version', capture=True).strip(),
        'candidate': 'async-snmp 0.18.1 + routed receiver patch',
        'source_sha256': source_hash(source),
        'patch_sha256': sha256(HERE / 'patches/async-snmp-0.18.1-routed-receiver.patch'),
        'lock_sha256': sha256(HERE / 'Cargo.lock'),
        'product_compat': True,
        'native': json.loads((WORK / 'reference-native.json').read_text()),
    }
    if args.musl:
        compiler = args.musl_prefix.resolve() / 'bin/musl-gcc'
        if not compiler.is_file():
            parser.error('Run sh tools/bootstrap_musl.sh first or supply --musl-prefix')
        env.update(
            CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=str(compiler),
            CC_x86_64_unknown_linux_musl=str(compiler),
            CFLAGS_x86_64_unknown_linux_musl='-march=x86-64 -mtune=generic',
            RUSTFLAGS='-C target-cpu=x86-64 -C target-feature=+crt-static '
                      '-C relocation-model=static -C link-arg=-static -C link-arg=-no-pie',
        )
        run('cargo', 'build', *options, '--release', '--target', TARGET, env=env)
        binary = WORK / f'target/{TARGET}/release/hardware-monitor-snmp-reference'
        header = run('readelf', '-h', str(binary), capture=True)
        program = run('readelf', '-l', str(binary), capture=True)
        dynamic = run('readelf', '-d', str(binary), capture=True)
        if 'X86-64' not in header or 'INTERP' in program or '(NEEDED)' in dynamic:
            raise RuntimeError('static x86-64 artifact check failed')
        run('python3', str(HERE / 'integration.py'), str(binary),
            '--report', str(WORK / 'reference-musl.json'), env=env)
        evidence['musl'] = dict(
            sha256=sha256(binary), size_bytes=binary.stat().st_size,
            static=True, target=TARGET,
            reference=json.loads((WORK / 'reference-musl.json').read_text()),
        )
    if args.audit:
        run('python3', str(HERE / 'audit.py'), '--report', str(WORK / 'advisories.json'))
        evidence['audit'] = json.loads((WORK / 'advisories.json').read_text())
    (WORK / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print(f'Library reference checks passed; evidence: {WORK / "evidence.json"}')


if __name__ == '__main__':
    main()
