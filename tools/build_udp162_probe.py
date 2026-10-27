#!/usr/bin/env python3
"""Build an isolated static DSM 7 UDP/162 capability experiment."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'HardwareMonitorUdp162Probe'
VERSION = '1.0.0-0001'
PRIVILEGE = {
    'defaults': {'run-as': 'package'},
    'tool': [{'relpath': 'bin/udp162-cap', 'user': 'package', 'group': 'package',
              'permission': '0700', 'capabilities': 'cap_net_bind_service'}],
}


def pack(archive, directory, epoch):
    for path in sorted(directory.rglob('*')):
        info = archive.gettarinfo(str(path), arcname=str(path.relative_to(directory)))
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.mtime = epoch
        if path.is_file():
            with path.open('rb') as stream:
                archive.addfile(info, stream)
        else:
            archive.addfile(info)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--arch', choices=['v1000', 'x86_64', 'geminilake'], default='v1000')
    parser.add_argument('--without-capability', action='store_true',
                        help='Build control 0002 with only run-as: package')
    args = parser.parse_args()
    version = '1.0.0-0002' if args.without_capability else VERSION
    privilege = {'defaults': {'run-as': 'package'}} if args.without_capability else PRIVILEGE
    args.output.mkdir(parents=True, exist_ok=True)
    output = args.output / f'{PACKAGE}-{version}-{args.arch}-dsm7.spk'
    if output.exists():
        raise SystemExit(f'Refusing to overwrite {output}')
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', str(int(time.time()))))
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        payload, outer = temp / 'payload', temp / 'outer'
        (payload / 'bin').mkdir(parents=True)
        (outer / 'conf').mkdir(parents=True)
        binary = payload / 'bin/udp162-cap'
        subprocess.run(['rustc', '--edition=2021', '--target=x86_64-unknown-linux-musl',
                        '-C', 'opt-level=s', '-C', 'strip=symbols',
                        str(ROOT / 'tools/udp162-probe/main.rs'), '-o', str(binary)], check=True)
        header = subprocess.check_output(['readelf', '-h', str(binary)], text=True)
        segments = subprocess.check_output(['readelf', '-l', str(binary)], text=True)
        dynamic = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
        assert 'Advanced Micro Devices X86-64' in header
        assert 'INTERP' not in segments and '(NEEDED)' not in dynamic
        binary.chmod(0o700)
        shutil.copy2(binary, payload / 'bin/udp162-baseline')
        shutil.copy2(ROOT / 'docs/UDP162-PROBE.md', payload / 'README.md')
        (outer / 'INFO').write_text(f'''package="{PACKAGE}"
version="{version}"
displayname="Hardware Monitor UDP 162 Probe"
description="UDP/162 package-user diagnostic. Capability requested: {str(not args.without_capability).lower()}."
maintainer="Hardware Monitor contributors"
arch="{args.arch}"
os_min_ver="7.0-40761"
startable="yes"
thirdparty="yes"
''')
        (outer / 'conf/privilege').write_text(json.dumps(privilege, indent=2) + '\n')
        (outer / 'conf/resource').write_text('{}\n')
        scripts = outer / 'scripts'
        scripts.mkdir()
        shutil.copy2(ROOT / 'tools/udp162-probe/start-stop-status', scripts / 'start-stop-status')
        for name in ['preinst', 'postinst', 'preuninst', 'postuninst', 'preupgrade', 'postupgrade']:
            (scripts / name).write_text('#!/bin/sh\nexit 0\n')
        for script in scripts.iterdir():
            script.chmod(0o755)
            subprocess.run(['sh', '-n', str(script)], check=True)
        for name, source in [('PACKAGE_ICON.PNG', 'packaging/ui/images/icon_64.png'),
                             ('PACKAGE_ICON_256.PNG', 'packaging/ui/images/icon_256.png'),
                             ('LICENSE', 'LICENSE')]:
            shutil.copy2(ROOT / source, outer / name)
        with gzip.GzipFile(filename=str(outer / 'package.tgz'), mode='wb', mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode='w') as inner:
                pack(inner, payload, epoch)
        with tarfile.open(output, 'w') as archive:
            pack(archive, outer, epoch)
        with tarfile.open(output) as archive:
            assert json.load(archive.extractfile('conf/privilege')) == privilege
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile('package.tgz').read()), mode='r:gz') as inner:
                assert inner.extractfile('bin/udp162-cap').read() == inner.extractfile('bin/udp162-baseline').read()
                assert inner.getmember('bin/udp162-cap').mode == 0o700
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.spk.sha256').write_text(f'{digest}  {output.name}\n')
    print(f'{output}\nSHA256 {digest}\nPASS static binary, paired payload, privilege config, shell syntax; DSM acceptance pending.')


if __name__ == '__main__':
    main()
