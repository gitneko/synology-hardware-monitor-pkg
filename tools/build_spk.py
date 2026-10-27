#!/usr/bin/env python3
"""Assemble an experimental SPK. Refuses dynamically linked or wrong-CPU binaries."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import re
import json
import os
import time
import tomllib
from uninstall_wizard import write_wizards

ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser()
p.add_argument('--profile',choices=['dsm7'],default='dsm7')
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--arch',choices=['x86_64','geminilake','v1000'],default='x86_64')
p.add_argument('--ui-dist',type=Path,default=ROOT/'web/dist')
p.add_argument('--output',type=Path,default=ROOT/'dist')
a=p.parse_args()
info=re.sub(r'^arch="[^"]+"',f'arch="{a.arch}"',(ROOT/f'packaging/INFO.{a.profile}').read_text(),flags=re.M)
version=re.search(r'^version="([^"]+)"',info,re.M).group(1)
assert re.fullmatch(r'[0-9A-Za-z.-]+',version), 'Invalid version for versioned UI paths'
product_version=tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
assert version.split('-')[0]==product_version, 'Product/INFO version mismatch'
assert json.loads((a.ui_dist/'ui-build.json').read_text())['version']==version, 'Refusing stale UI build: rebuild Vue for this package version'
# Static-file validators must change when a release changes. Reproducible builds
# can supply the release's SOURCE_DATE_EPOCH; never reuse it across releases.
release_time=int(os.environ.get('SOURCE_DATE_EPOCH',str(int(time.time()))))
assert release_time>0, 'A positive release timestamp is required'
binary=a.binary.resolve()
header=subprocess.check_output(['readelf','-h',str(binary)],text=True)
segments=subprocess.check_output(['readelf','-l',str(binary)],text=True)
dynamic=subprocess.check_output(['readelf','-d',str(binary)],text=True)
assert 'Advanced Micro Devices X86-64' in header, 'Expected x86_64 binary for the selected Synology architecture'
assert 'INTERP' not in segments and '(NEEDED)' not in dynamic, 'Refusing host-linked binary: build static musl target first'
assert subprocess.run([str(binary),'dev','--help'],capture_output=True).returncode!=0, 'Refusing a binary with local development authentication'
assert subprocess.check_output([str(binary),'--version']).strip()==f'hardware-monitor {product_version}'.encode(), 'Refusing stale product binary'
assert (a.ui_dist/'index.html').is_file(), 'Build Vue UI first'
a.output.mkdir(parents=True,exist_ok=True)

def add_tree(tar,base):
    for path in sorted(base.rglob('*')):
        info=tar.gettarinfo(str(path),arcname=str(path.relative_to(base)))
        info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=release_time
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:tar.addfile(info,stream)
        else:tar.addfile(info)

with tempfile.TemporaryDirectory() as temp:
    temp=Path(temp);payload=temp/'payload';outer=temp/'outer';payload.mkdir();outer.mkdir()
    (payload/'bin').mkdir();shutil.copy2(binary,payload/'bin/hardware-monitor');(payload/'bin/hardware-monitor').chmod(0o755)
    (payload/'scripts').mkdir()
    shutil.copy2(ROOT/'packaging/helpers/setup-trap-port.sh',payload/'scripts/setup-trap-port.sh')
    (payload/'scripts/setup-trap-port.sh').chmod(0o755)
    shutil.copytree(ROOT/'packaging/ui',payload/'ui',dirs_exist_ok=True)
    shutil.copytree(a.ui_dist,payload/'ui',dirs_exist_ok=True)
    entry=f'index-{version}.html'
    shutil.copy2(payload/'ui/index.html',payload/'ui'/entry)
    entry_url=f'/webman/3rdparty/HardwareMonitor/{entry}'
    shutil.copytree(ROOT/'packaging/desktop/dsm7',payload/'ui',dirs_exist_ok=True)
    launcher=payload/'ui/HardwareMonitor.js'
    source=launcher.read_text()
    assert source.count('/webman/3rdparty/HardwareMonitor/index.html')==1
    launcher_name=f'HardwareMonitor-{version}.js'
    (payload/'ui'/launcher_name).write_text(source.replace('/webman/3rdparty/HardwareMonitor/index.html',entry_url))
    launcher.unlink()
    config=json.loads((payload/'ui/config').read_text())
    config[launcher_name]=config.pop('HardwareMonitor.js')
    (payload/'ui/config').write_text(json.dumps(config,ensure_ascii=False,indent=2)+'\n')
    # Regular entrypoint: avoids relying on CGI symlink handling; 0004 showed
    # this alone does not resolve DSM's HTML 403 response.
    shutil.copy2(binary,payload/'ui/api.cgi')
    (payload/'ui/api.cgi').chmod(0o755)
    # Ignored local archives are not maintained product documentation.
    shutil.copytree(ROOT/'docs',payload/'docs', ignore=shutil.ignore_patterns('history'))
    for filename in ['LICENSE','README.md','THIRD_PARTY_NOTICES.txt']:
        shutil.copy2(ROOT/filename,payload/filename)
    (outer/'INFO').write_text(info)
    (outer/'conf').mkdir();shutil.copy2(ROOT/'packaging/conf/privilege',outer/'conf/privilege')
    shutil.copy2(ROOT/f'packaging/conf/resource.{a.profile}',outer/'conf/resource')
    # No user/system units are shipped until the DSM third-party resource contract is confirmed.
    (outer/'scripts').mkdir()
    shutil.copy2(ROOT/f'packaging/scripts/start-stop-status.{a.profile}',outer/'scripts/start-stop-status')
    for name in ['postinst','preupgrade','postuninst']:
        shutil.copy2(ROOT/f'packaging/scripts/{name}',outer/'scripts'/name)
    for name in ['preinst','preuninst','postupgrade']:
        (outer/'scripts'/name).write_text('#!/bin/sh\nexit 0\n')
    for script in (outer/'scripts').iterdir():script.chmod(0o755)
    write_wizards(outer/'WIZARD_UIFILES')
    shutil.copy2(ROOT/'LICENSE',outer/'LICENSE')
    shutil.copy2(ROOT/'packaging/ui/images/icon_64.png',outer/'PACKAGE_ICON.PNG')
    shutil.copy2(ROOT/'packaging/ui/images/icon_256.png',outer/'PACKAGE_ICON_256.PNG')
    with (outer/'package.tgz').open('wb') as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as tar:add_tree(tar,payload)
    output=a.output/f'HardwareMonitor-{version}-{a.arch}-{a.profile}-development.spk'
    with tarfile.open(output,'w') as tar:add_tree(tar,outer)
    digest=hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix('.spk.sha256').write_text(f'{digest}  {output.name}\n')
    print(f'{output}\nSHA256 {digest}\nDevelopment artifact: new-build NAS acceptance pending; SMTP/desktop require explicit channel and device activation.')
