#!/usr/bin/env python3
"""Build paired DSM 7 application-privilege probes. No notification dispatch."""
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
PACKAGE = 'HardwareMonitorPrivilegeProbe'
APP_ID = 'org.hardwaremonitor.privilegeprobe.app'
CATEGORY = 'Hardware Monitor Privilege Probe'
PRIVILEGE = {'defaults': {'run-as': 'package'}}
APP = {'.url': {APP_ID: {
    'type': 'url', 'title': CATEGORY,
    'desc': 'Application privilege registration experiment; no monitoring data',
    'icon': 'images/icon_{0}.png',
    'url': f'/webman/3rdparty/{PACKAGE}/index.html',
    'allUsers': True,
    'grantPrivilege': 'all', 'advanceGrantPrivilege': True,
    'texts': 'texts'
}}}
RESOURCE = {'sysnotify': {
    'texts_dir': 'ui/texts',
    'app_privileges': [{'app_id': APP_ID, 'categories': [CATEGORY]}]
}}
LIFECYCLE = '''#!/bin/sh
set -eu
: "${SYNOPKG_PKGVAR:?DSM package var directory is required}"
case "$1" in
  start) umask 077; touch "$SYNOPKG_PKGVAR/privilege-probe-running" ;;
  stop) rm -f "$SYNOPKG_PKGVAR/privilege-probe-running" ;;
  status) test -f "$SYNOPKG_PKGVAR/privilege-probe-running" ;;
  *) exit 1 ;;
esac
'''
HTML = '''<!doctype html><html lang="de"><meta charset="utf-8">
<title>Hardware Monitor Privilege Probe</title>
<h1>Hardware Monitor Privilege Probe</h1>
<p>Statisches Registrierungstestpaket. Keine Hardwaredaten, keine Anmeldung,
keine Zugangsdaten und kein Benachrichtigungsversand.</p>
<p>Bitte den Eintrag in DSM unter Systemsteuerung → Anwendungsberechtigungen
prüfen. Diese öffentliche Testseite prüft selbst keine Zugriffsberechtigung.</p>
<p>Stufe 0001: nur Desktop-App. Stufe 0002: dieselbe App mit sysnotify-Zuordnung.
Die installierte Stufe steht im Paketzentrum.</p></html>
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pack(tar, base, epoch):
    for path in sorted(base.rglob('*')):
        info = tar.gettarinfo(str(path), arcname=str(path.relative_to(base)))
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.mtime = epoch
        if path.is_file():
            with path.open('rb') as stream:
                tar.addfile(info, stream)
        else:
            tar.addfile(info)


def build(output, epoch, legacy_prefix=False):
    app_id = f'SYNO.SDS._ThirdParty.App.{PACKAGE}' if legacy_prefix else APP_ID
    app = json.loads(json.dumps(APP))
    app['.url'][app_id] = app['.url'].pop(APP_ID)
    resource = json.loads(json.dumps(RESOURCE))
    resource['sysnotify']['app_privileges'][0]['app_id'] = app_id
    first_stage = 3 if legacy_prefix else 1
    records = {}
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        payload = temp / 'payload'
        (payload / 'ui').mkdir(parents=True)
        (payload / 'ui/config').write_text(json.dumps(app, indent=2) + '\n')
        (payload / 'ui/index.html').write_text(HTML.replace('0001', '0003').replace('0002', '0004') if legacy_prefix else HTML)
        shutil.copytree(ROOT / 'packaging/ui/images', payload / 'ui/images')
        for lang, title, message in [
            ('enu', 'Registration test (no automatic dispatch)', 'Registration test only.'),
            ('ger', 'Registrierungstest (kein automatischer Versand)', 'Nur Registrierungstest.')
        ]:
            folder = payload / 'ui/texts' / lang
            folder.mkdir(parents=True)
            (folder / 'mails').write_text(
                f'[HardwareMonitorPrivilegeProbeEvent]\nCategory: {CATEGORY}\n'
                f'Level: NOTIFICATION_WARN\nTitle: {title}\nDesktop: {message}\n'
                'Target: desktop,mail,mobile\n\nNo automatic notification is sent.\n')
        compressed = io.BytesIO()
        with gzip.GzipFile(fileobj=compressed, mode='wb', mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode='w') as inner:
                pack(inner, payload, epoch)
        payload_bytes = compressed.getvalue()
        for stage, resources in [(first_stage, {}), (first_stage + 1, resource)]:
            outer = temp / f'outer-{stage}'
            (outer / 'conf').mkdir(parents=True)
            version = f'1.0.0-{stage:04d}'
            (outer / 'INFO').write_text(f'''package="{PACKAGE}"
version="{version}"
displayname="Hardware Monitor Privilege Probe"
description="Stage {stage}: app privilege registration experiment. No notifications sent. No monitoring data."
maintainer="Hardware Monitor contributors"
arch="v1000"
os_min_ver="7.0-40761"
startable="yes"
thirdparty="yes"
dsmuidir="ui"
dsmappname="{app_id}"
''')
            (outer / 'conf/privilege').write_text(json.dumps(PRIVILEGE))
            (outer / 'conf/resource').write_text(json.dumps(resources))
            (outer / 'package.tgz').write_bytes(payload_bytes)
            scripts = outer / 'scripts'
            scripts.mkdir()
            (scripts / 'start-stop-status').write_text(LIFECYCLE)
            for name in ['preinst', 'postinst', 'preuninst', 'postuninst', 'preupgrade', 'postupgrade']:
                (scripts / name).write_text('#!/bin/sh\nexit 0\n')
            for script in scripts.iterdir():
                script.chmod(0o755)
                subprocess.run(['sh', '-n', str(script)], check=True)
            env = {**os.environ, 'SYNOPKG_PKGVAR': str(temp)}
            script = scripts / 'start-stop-status'
            assert subprocess.run(['sh', str(script), 'status'], env=env).returncode == 1
            for action in ['start', 'status', 'stop']:
                subprocess.run(['sh', str(script), action], env=env, check=True)
            assert subprocess.run(['sh', str(script), 'status'], env=env).returncode == 1
            for name, source in [('PACKAGE_ICON.PNG', 'packaging/ui/images/icon_64.png'),
                                 ('PACKAGE_ICON_256.PNG', 'packaging/ui/images/icon_256.png'),
                                 ('LICENSE', 'LICENSE')]:
                (outer / name).write_bytes((ROOT / source).read_bytes())
            path = output / f'{PACKAGE}-{version}-v1000-dsm7.spk'
            assert not path.exists(), f'Refusing to replace existing probe: {path}'
            with tarfile.open(path, 'w') as archive:
                pack(archive, outer, epoch)
            with tarfile.open(path) as archive:
                assert json.load(archive.extractfile('conf/resource')) == resources
                assert json.load(archive.extractfile('conf/privilege')) == PRIVILEGE
                assert archive.extractfile('package.tgz').read() == payload_bytes
                for item in archive.getmembers():
                    if item.name.startswith('scripts/') and item.isfile():
                        body = archive.extractfile(item).read()
                        assert b'synonotify' not in body and b'synodsmnotify' not in body
                with tarfile.open(fileobj=io.BytesIO(payload_bytes), mode='r:gz') as inner:
                    config = json.load(inner.extractfile('ui/config'))['.url']
                    assert set(config) == {app_id}
                    assert resources == {} or resources['sysnotify']['app_privileges'][0]['app_id'] in config
                    assert not any(n.startswith('bin/') or n.endswith(('.key', '.db', '.cgi', '.js')) for n in inner.getnames())
                    for lang in ['enu', 'ger']:
                        assert f'Category: {CATEGORY}\n'.encode() in inner.extractfile(f'ui/texts/{lang}/mails').read()
            checksum = digest(path)
            path.with_suffix('.spk.sha256').write_text(checksum + '  ' + path.name + '\n')
            records[path.name] = {'sha256': checksum, 'bytes': path.stat().st_size,
                                  'stage': stage, 'resources': resources}
            print(f'{path}\nSHA256 {checksum}')
    return {'date': '2026-10-18', 'app_id': app_id, 'category': CATEGORY,
            'legacy_prefix_experiment': legacy_prefix,
            'payload_sha256': hashlib.sha256(payload_bytes).hexdigest(),
            'same_payload_between_stages': True,
            'local_checks': 'passed; matched IDs/categories, identical payload, scripts syntax and marker lifecycle, no dispatch or sensitive data',
            'nas_registration_and_resource_acceptance': 'pending', 'packages': records}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    parser.add_argument('--legacy-prefix', action='store_true',
                        help='Build stages 0003/0004 using SYNO.SDS._ThirdParty.App prefix')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', str(int(time.time()))))
    assert epoch > 0
    manifest = build(args.output, epoch, args.legacy_prefix)
    name = 'privilege-probes-legacy-prefix-manifest.json' if args.legacy_prefix else 'privilege-probes-manifest.json'
    (args.output / name).write_text(json.dumps(manifest, indent=2) + '\n')
    print('PASS local checks. Both NAS stages remain untested. Main package unchanged.')
