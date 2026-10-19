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

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'x86_64-unknown-linux-musl'
PROFILES = [('dsm7', 'x86_64'), ('dsm6', 'geminilake')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--musl-prefix', type=Path, default=ROOT/'.build/musl')
    parser.add_argument('--output', type=Path, default=ROOT/'dist/current')
    args = parser.parse_args()
    compiler = args.musl_prefix.resolve()/'bin/musl-gcc'
    copyright_file = args.musl_prefix.resolve()/'COPYRIGHT'
    if not compiler.is_file() or not copyright_file.is_file():
        parser.error('Run sh tools/bootstrap_musl.sh first (the prefix must include COPYRIGHT)')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    # Never use target-cpu=native: one executable must run on both Intel and AMD NASes.
    env.update(RUSTFLAGS='-C target-cpu=x86-64 -C target-feature=+crt-static -C relocation-model=static -C link-arg=-static -C link-arg=-no-pie',
               CC_x86_64_unknown_linux_musl=str(compiler),
               CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=str(compiler),
               CFLAGS_x86_64_unknown_linux_musl='-march=x86-64 -mtune=generic')
    env['SOURCE_DATE_EPOCH'] = env.get('SOURCE_DATE_EPOCH') or str(int(time.time()))
    assert int(env['SOURCE_DATE_EPOCH']) > 0

    def run(*command):
        subprocess.run(command, cwd=ROOT, env=env, check=True)

    run('cargo', 'fetch', '--locked')
    run('cargo', 'build', '--locked', '--release', '--target', TARGET)
    run('npm', 'ci', '--prefix', 'web', '--ignore-scripts')
    run('npm', 'run', 'build', '--prefix', 'web')
    run('python3', 'tools/license_notices.py', '--musl-copyright', str(copyright_file))
    target_dir = Path(env.get('CARGO_TARGET_DIR', ROOT/'target')).resolve()
    binary = target_dir/TARGET/'release/hardware-monitor'
    run('python3', 'tools/integration_test.py', str(binary))
    run('python3', 'tools/legacy_tls_integration_test.py', str(binary))
    run('python3', 'tools/smtp_integration_test.py', str(binary))
    version = re.search(r'^version="([^"]+)"', (ROOT/'packaging/INFO.dsm7').read_text(), re.M)[1]
    assert f'version="{version}"' in (ROOT/'packaging/INFO.dsm6').read_text()
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
    checksums = {name: hashlib.sha256((assets/name).read_bytes()).hexdigest() for name in sorted(package_assets)}
    commit = env.get('GITHUB_SHA')
    if not commit:
        result = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
        commit = result.stdout.strip() if result.returncode == 0 else None
    manifest = {'version': version, 'commit': commit, 'release_epoch': int(env['SOURCE_DATE_EPOCH']),
                'status': 'unsigned development build; NAS acceptance required',
                'target': TARGET, 'cpu': 'x86-64 baseline (no native tuning)', 'musl': '1.2.5',
                'packages': checksums, 'checks': ['static ELF', 'Redfish/TLS/CGI integration',
                    'pinned iDRAC7 TLS integration', 'SMTP/TLS/queue integration', 'both SPK profiles, lifecycle and UI assets']}
    (assets/'build-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    sums = {**checksums, 'build-manifest.json': hashlib.sha256((assets/'build-manifest.json').read_bytes()).hexdigest()}
    (assets/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(sums.items())))
    print(f'Checked release assets: {assets}')


if __name__ == '__main__':
    main()
