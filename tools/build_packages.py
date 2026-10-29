#!/usr/bin/env python3
"""Build and check the supported SPKs, then stage fixed-name release assets."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-unknown-linux-musl'
PROFILES = [('dsm7', 'x86_64')]


def version_metadata(root=ROOT):
    """Fail before building when executable, frontend or package identities drift."""
    version = tomllib.loads((root/'Cargo.toml').read_text())['package']['version']
    package = re.search(r'^version="([^"]+)"', (root/'packaging/INFO.dsm7').read_text(), re.M)[1]
    if not re.fullmatch(re.escape(version) + r'-[0-9]{4,}', package):
        raise ValueError('Product/package version mismatch')
    frontend = json.loads((root/'web/package.json').read_text())
    lock = json.loads((root/'web/package-lock.json').read_text())
    if [frontend['version'], lock['version'], lock['packages']['']['version']] != [version]*3:
        raise ValueError('Product/frontend lock version mismatch')
    locked = tomllib.loads((root/'Cargo.lock').read_text())
    if [p['version'] for p in locked['package'] if p['name'] == 'hardware-monitor'] != [version]:
        raise ValueError('Product/Cargo lock version mismatch')
    return package


def source_identity():
    """Identify dirty local builds without pretending HEAD describes their bytes."""
    try:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        result = None
    if result is None or result.returncode:
        return {'commit': None, 'source_dirty': None, 'source_sha256': None}
    commit = result.stdout.strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '-z'], cwd=ROOT))
    paths = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).split(b'\0')
    digest = hashlib.sha256()
    for name in sorted(set(paths)-{b''}):
        path = ROOT/os.fsdecode(name)
        digest.update(name+b'\0')
        if path.is_symlink():
            digest.update(b'link\0'+os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(b'file\0'+str(path.stat().st_mode & 0o777).encode()+b'\0')
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        else:
            digest.update(b'missing')
    return {'commit': commit, 'source_dirty': dirty, 'source_sha256': digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--musl-prefix', type=Path, default=ROOT/'.build/musl')
    parser.add_argument('--output', type=Path, default=ROOT/'dist/current')
    parser.add_argument('--skip-load-tests', action='store_true',
                        help='Skip only the two 60-second SNMP load cases; record this in the manifest')
    args = parser.parse_args()
    compiler = args.musl_prefix.resolve()/'bin/musl-gcc'
    copyright_file = args.musl_prefix.resolve()/'COPYRIGHT'
    if not compiler.is_file() or not copyright_file.is_file():
        parser.error('Run sh tools/bootstrap_musl.sh first (the prefix must include COPYRIGHT)')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    version = version_metadata()
    env = dict(os.environ)
    # Never use target-cpu=native: one executable must run on both Intel and AMD NASes.
    env.update(RUSTFLAGS='-C target-cpu=x86-64 -C target-feature=+crt-static -C relocation-model=static -C link-arg=-static -C link-arg=-no-pie',
               CC_x86_64_unknown_linux_musl=str(compiler),
               CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=str(compiler),
               CFLAGS_x86_64_unknown_linux_musl='-march=x86-64 -mtune=generic')
    env['SOURCE_DATE_EPOCH'] = env.get('SOURCE_DATE_EPOCH') or str(int(time.time()))
    assert int(env['SOURCE_DATE_EPOCH']) > 0
    source = source_identity()

    def run(*command):
        subprocess.run(command, cwd=ROOT, env=env, check=True)

    run('python3', 'tools/check_docs.py')
    run('cargo', 'fetch', '--locked')
    run('cargo', 'build', '--locked', '--release', '--target', TARGET)
    run('npm', 'ci', '--prefix', 'web', '--ignore-scripts')
    run('npm', 'run', 'build', '--prefix', 'web')
    run('python3', 'tools/license_notices.py', '--musl-copyright', str(copyright_file))
    target_dir = Path(env.get('CARGO_TARGET_DIR', ROOT/'target')).resolve()
    binary = target_dir/TARGET/'release/hardware-monitor'
    upgrade_reference = output/'upgrade-reference.json'
    run('python3', 'tools/upgrade_integration.py', str(binary), '--report', str(upgrade_reference))
    run('python3', 'tools/integration_test.py', str(binary))
    run('python3', 'tools/legacy_tls_integration_test.py', str(binary))
    run('python3', 'tools/smtp_integration_test.py', str(binary))
    reference = output/'snmp-reference.json'
    run('python3', 'tools/snmp_integration_test.py', str(binary), '--require-static',
        '--load-seconds', '0' if args.skip_load_tests else '60', '--report', str(reference))
    if source_identity() != source:
        raise ValueError('Sources changed during build; review generated notices/edits and rebuild')
    assets = output/'latest-assets'
    assets.mkdir(exist_ok=True)
    for profile, arch in PROFILES:
        run('python3', 'tools/build_spk.py', '--profile', profile, '--arch', arch,
            '--binary', str(binary), '--output', str(output))
        package = output/f'HardwareMonitor-{version}-{arch}-{profile}-development.spk'
        run('python3', 'tools/check_spk.py', str(package))
        shutil.copy2(package, assets/f'HardwareMonitor-{profile}-{arch}.spk')
    package_assets = {f'HardwareMonitor-{profile}-{arch}.spk' for profile, arch in PROFILES}
    expected = package_assets | {'build-manifest.json', 'SHA256SUMS'}
    # Refuse stale/foreign files rather than publishing unrelated contents.
    assert all(p.is_file() and p.name in expected for p in assets.iterdir()), 'Use a clean output directory'
    # The release contains one SPK; expose its compatibility hashes as strings.
    package_name, = package_assets
    data = (assets/package_name).read_bytes()
    checksums = {package_name: hashlib.sha256(data).hexdigest()}
    if source_identity() != source:
        raise ValueError('Sources changed during package inspection; rebuild')
    if env.get('GITHUB_SHA') and env['GITHUB_SHA'] != source['commit']:
        raise ValueError('CI/checkout commit mismatch')
    manifest = {'version': version, **source, 'release_epoch': int(env['SOURCE_DATE_EPOCH']),
                'status': 'unsigned development build; NAS acceptance required',
                'target': TARGET, 'cpu': 'x86-64 baseline (no native tuning)', 'musl': '1.2.5',
                'snmp': json.loads(reference.read_text()),
                'upgrade': json.loads(upgrade_reference.read_text()),
                'skipped_checks': ['60-second receiver and alarm load tests'] if args.skip_load_tests else [],
                'packages': checksums,
                'packages_md5': hashlib.md5(data, usedforsecurity=False).hexdigest(),
                'packages_sha1': hashlib.sha1(data, usedforsecurity=False).hexdigest(),
                'checks': ['static ELF', 'direct schema-1 upgrade/postinst/repair/DSM status', 'Redfish/TLS/CGI integration',
                    'pinned iDRAC7 TLS integration', 'SMTP/TLS/queue integration',
                    'actual static SNMP v1/v2c/v3 polling', 'actual static trap enrollment/reception',
                    'scoped generic availability and network interface discovery',
                    'RFC 1628, APC PowerNet and Eaton xUPS polling and alarm recovery',
                    'trap/poll alarm ordering and SMTP delivery',
                    'maintained documentation links and heading anchors',
                    'DSM 7 SPK, lifecycle and versioned SNMP UI assets']
                    + ([] if args.skip_load_tests else ['60-second receiver and alarm load tests'])}
    (assets/'build-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    sums = {**checksums, 'build-manifest.json': hashlib.sha256((assets/'build-manifest.json').read_bytes()).hexdigest()}
    (assets/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(sums.items())))
    print(f'Checked release assets: {assets}')


if __name__ == '__main__':
    main()
