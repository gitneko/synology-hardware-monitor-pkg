#!/usr/bin/env python3
"""Build an isolated DSM 7 sysnotify registration probe. Sends no notifications."""
import argparse,hashlib,io,json,os,subprocess,tarfile,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'dist');a=p.parse_args()
info='''package="HardwareMonitorNotifyProbe"
version="1.0.0-0001"
displayname="Hardware Monitor Notification Probe"
description="Isolated registration-only sysnotify test. No notifications are sent. Does not change HardwareMonitor."
maintainer="Hardware Monitor contributors"
arch="v1000"
os_min_ver="7.0-40761"
startable="yes"
thirdparty="yes"
'''
lifecycle='''#!/bin/sh
set -eu
: "${SYNOPKG_PKGVAR:?DSM package var directory is required}"
case "$1" in
  start) umask 077; touch "$SYNOPKG_PKGVAR/registration-probe-running" ;;
  stop) rm -f "$SYNOPKG_PKGVAR/registration-probe-running" ;;
  status) test -f "$SYNOPKG_PKGVAR/registration-probe-running" ;;
  *) exit 1 ;;
esac
'''
texts={
'enu':'''[HardwareMonitorRegistrationProbe]
Category: Hardware Monitor Registration Probe
Level: NOTIFICATION_WARN
Title: Registration probe (not sent automatically)
Desktop: Hardware Monitor notification registration probe.
Target: desktop,mail,mobile

This package registers one event for inspection. It never sends a notification automatically.
''',
'ger':'''[HardwareMonitorRegistrationProbe]
Category: Hardware Monitor Registration Probe
Level: NOTIFICATION_WARN
Title: Registrierungstest (kein automatischer Versand)
Desktop: Hardware Monitor Benachrichtigungs-Registrierungstest.
Target: desktop,mail,mobile

Dieses Paket registriert ein Ereignis zur Prüfung. Es versendet keine automatische Benachrichtigung.
'''}
with tempfile.TemporaryDirectory() as temporary:
 temp=Path(temporary);payload=temp/'payload';outer=temp/'outer';payload.mkdir();outer.mkdir()
 for lang,value in texts.items():
  target=payload/'ui/texts'/lang;target.mkdir(parents=True);(target/'mails').write_text(value)
 (payload/'README.txt').write_text('Registration only. No daemon, no devices, no credentials, no notification dispatch. See the supplied integration guide.\n')
 (outer/'INFO').write_text(info);(outer/'conf').mkdir();(outer/'conf/privilege').write_text(json.dumps({'defaults':{'run-as':'package'}}));(outer/'conf/resource').write_text(json.dumps({'sysnotify':{'texts_dir':'ui/texts'}}))
 (outer/'scripts').mkdir();(outer/'scripts/start-stop-status').write_text(lifecycle)
 for name in ['preinst','postinst','preuninst','postuninst','preupgrade','postupgrade']:(outer/'scripts'/name).write_text('#!/bin/sh\nexit 0\n')
 for script in (outer/'scripts').iterdir():
  script.chmod(0o755);subprocess.run(['sh','-n',str(script)],check=True)
 for name,source in [('PACKAGE_ICON.PNG','packaging/ui/images/icon_64.png'),('PACKAGE_ICON_256.PNG','packaging/ui/images/icon_256.png'),('LICENSE','LICENSE')]: (outer/name).write_bytes((ROOT/source).read_bytes())
 # Exercise only the probe's own local marker lifecycle, never DSM binaries.
 env={**os.environ,'SYNOPKG_PKGVAR':str(temp)};script=outer/'scripts/start-stop-status'
 assert subprocess.run(['sh',str(script),'status'],env=env).returncode==1
 for action in ['start','status','stop']:subprocess.run(['sh',str(script),action],env=env,check=True)
 assert subprocess.run(['sh',str(script),'status'],env=env).returncode==1
 epoch=int(time.time())
 def pack(tar,base):
  for path in sorted(base.rglob('*')):
   item=tar.gettarinfo(str(path),arcname=str(path.relative_to(base)));item.uid=item.gid=0;item.uname=item.gname='root';item.mtime=epoch
   if path.is_file():
    with path.open('rb') as f:tar.addfile(item,f)
   else:tar.addfile(item)
 with tarfile.open(outer/'package.tgz','w:gz') as t:pack(t,payload)
 a.output.mkdir(parents=True,exist_ok=True);output=a.output/'HardwareMonitorNotifyProbe-1.0.0-0001-v1000-dsm7.spk'
 with tarfile.open(output,'w') as t:pack(t,outer)
 with tarfile.open(output) as t:
  assert json.load(t.extractfile('conf/resource'))=={'sysnotify':{'texts_dir':'ui/texts'}}
  assert json.load(t.extractfile('conf/privilege'))=={'defaults':{'run-as':'package'}}
  assert b'synonotify' not in t.extractfile('scripts/start-stop-status').read()
  with tarfile.open(fileobj=io.BytesIO(t.extractfile('package.tgz').read()),mode='r:gz') as inner:
   assert not any(n.startswith('bin/') or n.endswith(('.key','.db')) for n in inner.getnames())
 digest=hashlib.sha256(output.read_bytes()).hexdigest();output.with_suffix('.spk.sha256').write_text(digest+'  '+output.name+'\n')
 print(f'{output}\nSHA256 {digest}\nPASS local probe structure/lifecycle. DSM resource acceptance and event visibility remain untested.')
