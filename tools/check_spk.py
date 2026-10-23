#!/usr/bin/env python3
"""Inspect the assembled SPK and execute its extracted binary on the development host."""
import argparse,hashlib,io,json,os,re,shlex,sqlite3,subprocess,tarfile,tempfile,urllib.parse
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('spk',type=Path);a=p.parse_args()
profile='dsm7'
assert '-dsm7-' in a.spk.name, 'Only DSM 7 packages are supported'
architecture=next((arch for arch in ['x86_64','v1000','geminilake'] if f'-{arch}-' in a.spk.name),None)
assert architecture, 'Expected an explicit supported architecture in the SPK filename'
with tarfile.open(a.spk) as outer:
    names=set(outer.getnames())
    assert {'INFO','conf/privilege','conf/resource','scripts/start-stop-status','package.tgz','LICENSE','PACKAGE_ICON.PNG'}<=names
    assert {'scripts/postuninst', 'WIZARD_UIFILES/uninstall_uifile.sh',
            'WIZARD_UIFILES/uninstall_uifile_enu.sh', 'WIZARD_UIFILES/uninstall_uifile_ger.sh'}<=names
    privilege=json.load(outer.extractfile('conf/privilege'))
    assert privilege=={'defaults':{'run-as':'package'}}
    resource=json.load(outer.extractfile('conf/resource'))
    # Regression guard for the actual DSM installation rejection: no optional workers/units.
    assert resource=={}, 'Unverified DSM resource requests must not be shipped'
    assert not any(n.startswith('conf/systemd') for n in names)
    lifecycle=outer.extractfile('scripts/start-stop-status').read()
    postinst=outer.extractfile('scripts/postinst').read()
    assert b'hardware-monitor initialize' in postinst and b'umask 077' in postinst
    assert b'service start' in lifecycle and b'--notify-dsm' not in lifecycle and b'synosystemctl' not in lifecycle
    import struct
    width,height=struct.unpack('>II',outer.extractfile('PACKAGE_ICON.PNG').read()[16:24])
    assert (width,height)==(64,64)
    info=outer.extractfile('INFO').read().decode(); full_version=re.search(r'^version="([^"]+)"',info,re.M).group(1);version=full_version.split('-')[0];assert f'arch="{architecture}"' in info;assert 'displayname="Hardware Monitor"' in info
    assert 'os_min_ver="7.0-40761"' in info, 'Expected DSM 7 minimum version'
    for member in outer.getmembers():
        if (member.name.startswith('scripts/') or member.name.startswith('WIZARD_UIFILES/')) and member.isfile():
            assert member.mode&0o111
            subprocess.run(['sh','-n'],input=outer.extractfile(member).read(),check=True)
    with tarfile.open(fileobj=io.BytesIO(outer.extractfile('package.tgz').read()),mode='r:gz') as payload:
        members={m.name:m for m in payload.getmembers()}
        assert members['ui/api.cgi'].isfile() and not members['ui/api.cgi'].issym(), 'CGI must be a regular executable inside ui'
        assert members['ui/api.cgi'].mode & 0o111
        assert payload.extractfile('ui/api.cgi').read()==payload.extractfile('bin/hardware-monitor').read()
        assert 'ui/index.html' in members and 'THIRD_PARTY_NOTICES.txt' in members
        config=json.load(payload.extractfile('ui/config'))
        class_name='SYNO.SDS.App.HardwareMonitor.Instance'
        launcher_name=f'HardwareMonitor-{full_version}.js'
        app=config[launcher_name][class_name]
        assert app['type']=='app' and app['appWindow']==class_name
        assert f'dsmappname="{class_name}"' in info
        launcher=payload.extractfile('ui/'+launcher_name).read().decode()
        assert 'window.open(' not in launcher and 'v-app-instance' in launcher and 'v-app-window' in launcher
        # Verify the actual launcher code with DSM globals stubbed. This does not
        # validate DSM's component implementation, only our own registration/render.
        program="""const vm=require('node:vm'),assert=require('node:assert/strict');
const source=JSON.parse(process.argv[1]);
const context={SYNO:{SDS:{App:{HardwareMonitor:{}}},namespace(){}},Vue:{extend:x=>x}};
vm.createContext(context);vm.runInContext(source,context);
const tree=context.SYNO.SDS.App.HardwareMonitor.Instance.render((name,options,children)=>({name,options,children}));
assert.equal(tree.name,'v-app-instance');
assert.equal(tree.options.props.className,'SYNO.SDS.App.HardwareMonitor.Instance');
assert.equal(tree.children[0].name,'v-app-window');
assert.equal(tree.children[0].children[0].name,'iframe');
process.stdout.write(tree.children[0].children[0].options.attrs.src);"""
        app_url=subprocess.check_output(['node','-e',program,json.dumps(launcher)],text=True)
        canonical='/webman/3rdparty/HardwareMonitor/'
        resolved=urllib.parse.urljoin('https://nas.example.invalid:5001/',app_url)
        assert urllib.parse.urlsplit(resolved).path.startswith(canonical), 'Desktop link misses the DSM /webman/ prefix'
        assert urllib.parse.urlsplit(urllib.parse.urljoin('https://nas.example.invalid:5001/webman/',app_url)).path==urllib.parse.urlsplit(resolved).path
        assert urllib.parse.urlsplit(resolved).path==canonical+f'index-{full_version}.html'
        assert json.load(payload.extractfile('ui/ui-build.json'))['version']==full_version
        entry='ui/'+urllib.parse.urlsplit(resolved).path.removeprefix(canonical)
        assert entry in members
        assert members[entry].mtime>0 and members['ui/index.html'].mtime>0
        assert payload.extractfile(entry).read()==payload.extractfile('ui/index.html').read()
        html=payload.extractfile(entry).read().decode()
        references=re.findall(r'(?:src|href)="([^"]+)"',html)+['./api.cgi']
        for reference in references:
            target=urllib.parse.urlsplit(urllib.parse.urljoin(resolved,reference))
            assert target.path.startswith(canonical), f'Asset/API escapes DSM app alias: {reference}'
            assert 'ui/'+target.path.removeprefix(canonical) in members, f'Asset/API missing in package: {reference}'

        # Regression: shipping a fresh package with stale Vue assets would retain
        # the observed token-less request. Inspect the bundled JavaScript itself.
        javascript=b'\n'.join(payload.extractfile(name).read() for name in members if name.startswith('ui/assets/') and name.endswith('.js'))
        assert b'synology_dsm' in javascript and b'Synology DSM' in javascript
        assert all(profile in javascript for profile in (b'ups_generic',b'apc_ups',b'eaton_ups'))
        assert b'network_generic' in javascript and b'snmp:interface:' in javascript
        assert b'/webman/login.cgi' in javascript and b'X-SYNO-TOKEN' in javascript
        assert full_version.encode() in javascript and b'Oberfl' in javascript
        assert b'POST' in javascript and b'csrf' in javascript and b'certificate_pem' in javascript, 'Device administration assets missing'

        assert b'mail_save' in javascript and b'mail_test' in javascript and b'mail_preview' in javascript, 'SMTP settings assets missing'
        assert all(action in javascript for action in [b'events_export',b'events_clear',b'backup_export',b'backup_inspect',b'backup_restore']), 'History/backup UI actions missing'
        assert b'WIEDERHERSTELLEN' in javascript and 'docs/BACKUP-RESTORE.md' in members
        assert app['texts']=='texts'
        assert app['preloadTexts']==[f'{section}:{key}_{part}' for section in ['notification','notification_details','notification_details_en','notification_details_de'] for key in ['test','critical','warning','recovery','repeat','hardware_log'] for part in ['title','body']]
        assert all(word in javascript for word in [b'notification_save',b'time_local',b'time_utc',b'date_format',b'desktop_enabled'])
        assert all(action in javascript for action in [b'snmp_receiver_save', b'snmp_trap_probe', b'snmp_receipts', b'snmp_secrets', b'snmp_trap']), 'SNMP administration/provenance UI missing'
        assert all(label in javascript for label in [b'SNMPv1', b'SNMPv2c', b'SNMPv3', b'1162', b'1024']), 'SNMP versions/receiver settings missing'
        assert 'docs/SNMP-IMPLEMENTATION-PLAN.md' in members
        for language in ['enu','ger']:
            text=payload.extractfile(f'ui/texts/{language}/mails').read().decode()
            strings=payload.extractfile(f'ui/texts/{language}/strings').read().decode()
            assert '[notification]' in strings and 'test_title=' in strings and 'test_body=' in strings
            for category in ['test','critical','warning','recovery','repeat','hardware_log']:
                body=next(line for line in strings.split('[notification_details]',1)[1].splitlines() if line.startswith(category+'_body='))
                assert all(token in body for token in ['{0}','{1}','{2}']), 'Desktop placeholders missing from packaged strings'
            assert all(f'[{key}]' in text for key in ['HardwareMonitorCritical','HardwareMonitorWarning','HardwareMonitorRecovered'])
        assert not any(n.startswith(('vendor/','tools/','node_modules/','.build/')) or n.endswith(('.db','.key','.sqlite','.pem','.hmbackup','.mib')) for n in members), 'Runtime state or reference tooling must not ship'
        with tempfile.TemporaryDirectory() as temp:
            temp=Path(temp);(temp/'bin').mkdir();(temp/'ui').mkdir()
            binary=temp/'bin/hardware-monitor';binary.write_bytes(payload.extractfile('bin/hardware-monitor').read());binary.chmod(0o755)
            assert 'INTERP' not in subprocess.check_output(['readelf','-l',str(binary)],text=True)
            assert '(NEEDED)' not in subprocess.check_output(['readelf','-d',str(binary)],text=True)
            assert subprocess.check_output([str(binary),'--version']).strip()==f'hardware-monitor {version}'.encode()
            assert subprocess.run([str(binary),'dev','--help'],capture_output=True).returncode!=0, 'Local development authentication must not be shipped in an SPK'
            fresh=temp/'fresh-state'
            prepare_invocation=' '.join(shlex.quote(str(v)) for v in [binary,'--state',fresh,'--socket',temp/'prepare.sock'])
            prepare=postinst.decode().replace('/var/packages/HardwareMonitor/target/bin/hardware-monitor',prepare_invocation).replace('/var/packages/HardwareMonitor/etc/private',shlex.quote(str(fresh)))
            subprocess.run(['sh','-c',prepare],check=True,capture_output=True)
            first_key=(fresh/'master.key').read_bytes()
            subprocess.run(['sh','-c',prepare],check=True,capture_output=True)
            assert (fresh/'master.key').read_bytes()==first_key
            assert (fresh/'service.log').stat().st_mode & 0o077 == 0
            dashboard=json.loads(subprocess.check_output([str(binary),'--state',str(fresh),'snapshot']))
            assert dashboard['version']==version and dashboard['devices']==[]
            with sqlite3.connect(fresh/'monitor.db') as database:
                settings=json.loads(database.execute('SELECT config FROM snmp_receiver_settings WHERE id=1').fetchone()[0])
                assert settings=={'enabled':False,'listen_port':1162,'listen_addresses':['0.0.0.0']}, 'New installation must not enable trap reception'
                assert database.execute('SELECT COUNT(*) FROM protocol_secrets').fetchone()[0]==0
            cgi=temp/'ui/api.cgi';cgi.write_bytes(payload.extractfile('ui/api.cgi').read());cgi.chmod(0o755)
            response=subprocess.check_output([str(cgi)],env={**os.environ,'REQUEST_METHOD':'GET','HTTP_COOKIE':''})
            assert b'Status: 403 Forbidden' in response
            denial=json.loads(response.split(b'\r\n\r\n',1)[1])
            assert denial['ok'] is False and 'data' not in denial
            # Probe runs without cookie/helper/socket. Diagnostics must never return
            # device or identity data and retain application-level denial in a 200 envelope.
            env={**os.environ,'REQUEST_METHOD':'GET','HTTP_COOKIE':''}
            probe=subprocess.check_output([str(cgi)],env={**env,'QUERY_STRING':'probe=1'})
            marker=json.loads(probe.split(b'\r\n\r\n',1)[1])
            assert b'Status: 200 OK' in probe and marker=={'ok':True,'code':'cgi_ready','source':'hardware-monitor','version':version}
            diagnostic=subprocess.check_output([str(cgi)],env={**env,'QUERY_STRING':'diagnose=1'})
            diagnosis=json.loads(diagnostic.split(b'\r\n\r\n',1)[1])
            assert b'Status: 200 OK' in diagnostic
            assert diagnosis=={'ok':False,'code':'cgi_cookie_missing_or_invalid','source':'hardware-monitor','version':version}

            post=subprocess.check_output([str(cgi)],env={**env,'REQUEST_METHOD':'POST','QUERY_STRING':''})
            denied_post=json.loads(post.split(b'\r\n\r\n',1)[1])
            assert b'Status: 200 OK' in post and denied_post['ok'] is False and 'data' not in denied_post

            # Exercise the shipped lifecycle against the shipped binary. Only absolute paths
            # are relocated into this disposable directory; no NAS or real equipment is used.
            runtime=temp/'runtime';runtime.mkdir()
            invocation=' '.join(shlex.quote(str(v)) for v in [binary,'--state',runtime/'private','--socket',runtime/'api.sock'])
            adapted=lifecycle.decode().replace('/var/packages/HardwareMonitor/target/bin/hardware-monitor',invocation)
            script=temp/'start-stop-status';script.write_text(adapted)
            try:
                subprocess.run(['sh',str(script),'start'],check=True,capture_output=True)
                subprocess.run(['sh',str(script),'status'],check=True,capture_output=True)
                subprocess.run(['sh',str(script),'start'],check=True,capture_output=True)
                assert subprocess.run(['sh',str(script),'invalid'],capture_output=True).returncode!=0
                subprocess.run(['sh',str(script),'stop'],check=True,capture_output=True)
                assert subprocess.run(['sh',str(script),'status'],capture_output=True).returncode==3
            finally:
                subprocess.run(['sh',str(script),'stop'],capture_output=True)
subprocess.run([os.sys.executable, '-m', 'unittest', 'discover', '-s', str(Path(__file__).parent/'tests'),
                '-p', 'test_uninstall.py', '-v'],
               env={**os.environ, 'HARDWARE_MONITOR_TEST_SPK': str(a.spk.resolve())}, check=True)
print(f'PASS {profile}: archive structure, privilege/profile separation, native lifecycle execution, syntax/modes, static executable, regular CGI entrypoint denial, DSM route/relative assets/API path, event templates and optional uninstall cleanup')
print('SHA256',hashlib.sha256(a.spk.read_bytes()).hexdigest())
