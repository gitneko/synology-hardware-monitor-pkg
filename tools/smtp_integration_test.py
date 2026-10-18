#!/usr/bin/env python3
"""SMTP/TLS and daemon queue tests on loopback only. All addresses are synthetic."""
import base64
import json
from pathlib import Path
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time

BINARY = Path(sys.argv[1]).resolve()
SECRET = 'synthetic-smtp-secret'


class Server(socketserver.ThreadingTCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        connection = self.request
        reader = None
        secure = server.mode == 'tls'
        try:
            if secure:
                connection = server.context.wrap_socket(connection, server_side=True)
            reader = connection.makefile('rb')
            connection.sendall(b'220 localhost synthetic SMTP\r\n')
            recipient = None
            while True:
                line = reader.readline(65536)
                if not line:
                    return
                command = line.decode(errors='replace').strip()
                verb = command.split(' ', 1)[0].upper()
                server.commands.append(verb)  # Never store authentication values.
                if verb == 'EHLO':
                    connection.sendall(b'250-localhost\r\n')
                    if not secure and server.mode not in ('no_starttls','plain'):
                        connection.sendall(b'250-STARTTLS\r\n')
                    connection.sendall(b'250 AUTH PLAIN\r\n')
                elif verb == 'STARTTLS':
                    connection.sendall(b'220 Ready for TLS\r\n')
                    reader.close()
                    connection = server.context.wrap_socket(connection, server_side=True)
                    reader = connection.makefile('rb')
                    secure = True
                elif verb == 'AUTH':
                    assert secure or server.mode == 'plain', 'Credentials attempted without explicitly selected plaintext mode'
                    token = command.split()[-1]
                    decoded = base64.b64decode(token)
                    expected = b'\0monitor\0' + SECRET.encode()
                    server.auth_ok = decoded == expected
                    connection.sendall(b'235 authenticated\r\n' if server.auth_ok and not server.reject_auth else b'535 rejected\r\n')
                elif verb == 'MAIL':
                    assert secure or server.mode == 'plain', 'Message attempted without explicitly selected plaintext mode'
                    connection.sendall(b'250 sender accepted\r\n')
                elif verb == 'RCPT':
                    recipient = command.split(':', 1)[1].strip().strip('<>')
                    connection.sendall(b'550 synthetic recipient rejected\r\n' if recipient.startswith('reject@') else b'250 recipient accepted\r\n')
                elif verb == 'DATA':
                    connection.sendall(b'354 data\r\n')
                    lines = []
                    while True:
                        line = reader.readline(65536)
                        if line in (b'.\r\n', b''):
                            break
                        # RFC 5321 transparency: remove the SMTP dot-stuffing.
                        lines.append(line[1:] if line.startswith(b'..') else line)
                    server.messages.append((recipient, b''.join(lines)))
                    connection.sendall(b'250 queued\r\n')
                elif verb == 'QUIT':
                    connection.sendall(b'221 bye\r\n')
                    return
                else:
                    connection.sendall(b'250 ok\r\n')
        except (ssl.SSLError, ConnectionError, OSError):
            pass  # Negative TLS checks intentionally close the connection.
        finally:
            if reader:
                reader.close()
            connection.close()


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    cert = root / 'cert.pem'
    key = root / 'key.pem'
    ca = root / 'ca.pem'
    ca_key = root / 'ca.key'
    def openssl(*args):
        subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl('req','-x509','-newkey','rsa:2048','-nodes','-keyout',ca_key,'-out',ca,'-days','1','-subj','/CN=Synthetic SMTP CA','-addext','basicConstraints=critical,CA:TRUE')
    openssl('req','-new','-newkey','rsa:2048','-nodes','-keyout',key,'-out',root/'server.csr','-subj','/CN=localhost')
    (root/'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
    openssl('x509','-req','-in',root/'server.csr','-CA',ca,'-CAkey',ca_key,'-CAcreateserial','-out',cert,'-days','1','-extfile',root/'extensions')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)

    def start(mode):
        server = Server(('::1', 0), Handler)
        server.context = context
        server.mode = mode
        server.commands = []
        server.messages = []
        server.auth_ok = False
        server.reject_auth = False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def settings(server, security='starttls'):
        return {'enabled': False, 'host': 'localhost', 'port': server.server_address[1], 'security': security,
                'username': 'monitor', 'from_address': 'monitor@example.invalid', 'from_name': 'Hardware Monitor',
                'recipients': ['receiver@example.invalid'], 'subject_template': '{{health}}: {{device}}',
                'body_template': '{{message}}\n{{time}}\n{{event_id}}', 'ca_pem': ca.read_text()}

    def test(config, success):
        config_file = root / 'smtp.json'
        config_file.write_text(json.dumps(config))
        state = root / 'test-state'
        result = subprocess.run([str(BINARY), '--state', str(state), 'mail-test', '--file', str(config_file)],
                                input=SECRET+'\n', text=True, capture_output=True, timeout=20)
        assert (result.returncode == 0) == success, result.stderr
        assert SECRET not in result.stdout + result.stderr
        return result

    server = start('starttls')
    try:
        cfg = settings(server)
        test(cfg, True)
        assert server.auth_ok and len(server.messages) == 1
        assert b'Message-ID: <hm-test-' in server.messages[0][1]
        assert b'Content-Type: text/plain' in server.messages[0][1]
        for overrides in [{'ca_pem': None}, {'host': '::1'}]:
            before = len(server.messages)
            test({**cfg, **overrides}, False)
            assert len(server.messages) == before
        server.reject_auth = True
        assert 'mail_rejected' in test(cfg, False).stderr
        server.reject_auth = False
        assert 'mail_rejected' in test({**cfg, 'recipients': ['reject@example.invalid']}, False).stderr
    finally:
        server.shutdown()
        server.server_close()
    server = start('no_starttls')
    try:
        test(settings(server), False)
        assert 'AUTH' not in server.commands and not server.messages
    finally:
        server.shutdown()
        server.server_close()
    server = start('plain')
    try:
        cfg = settings(server, 'plain'); cfg.update(username='', ca_pem=None)
        test(cfg, True)
        assert len(server.messages)==1 and 'STARTTLS' not in server.commands and 'AUTH' not in server.commands
        cfg['username']='monitor';test(cfg,True)
        assert server.auth_ok and len(server.messages)==2 and 'STARTTLS' not in server.commands
    finally:
        server.shutdown();server.server_close()
    server = start('tls')
    try:
        cfg = settings(server, 'tls')
        test(cfg, True)
        assert server.auth_ok and len(server.messages) == 1
        server.messages.clear()
        # Seed private synthetic queue state, then exercise the real daemon worker.
        state = root / 'queue-state'
        subprocess.run([str(BINARY), '--state', str(state), 'snapshot'], check=True, capture_output=True)
        cfg.update(enabled=True, username='', recipients=['receiver@example.invalid', 'reject@example.invalid'])
        assert not Path('/usr/syno/bin/synodsmnotify').exists(), 'Desktop-failure fixture must run off DSM'
        with sqlite3.connect(state / 'monitor.db') as db:
            db.execute('INSERT INTO notification_settings VALUES(1,?,1)',(json.dumps({'desktop_enabled':True,'desktop_recipient':'synthetic-test-user','selection':{'critical':True,'warning':True,'recovery':True,'repeat':True,'hardware_log':True}}),))
            db.execute('INSERT INTO mail_settings VALUES(1,?,?,1)', (json.dumps(cfg), b''))
            db.execute('INSERT INTO events(id,device,key,kind,health,message,created,device_name) VALUES(1,?,?,?,?,?,?,?)',
                       ('synthetic', 'PS1', 'alarm', '"critical"', 'Synthetic PS1 fault', int(time.time()), 'Synthetic server'))
            db.execute('INSERT INTO outbox(id,event_id,transport) VALUES(1,1,?)', ('smtp',))
            db.execute('INSERT INTO desktop_jobs(event_id,recipient,revision) VALUES(1,?,1)',('synthetic-test-user',))
            for recipient in cfg['recipients']:
                db.execute('INSERT INTO mail_recipient(outbox_id,recipient,message_id,revision) VALUES(1,?,?,1)',
                           (recipient, '<synthetic-'+recipient+'>'))
        daemon = subprocess.Popen([str(BINARY), '--state', str(state), '--socket', str(root / 'api.sock'), 'serve'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                with sqlite3.connect(state / 'monitor.db') as db:
                    outcomes = db.execute('SELECT recipient,delivered,permanent FROM mail_recipient ORDER BY recipient').fetchall()
                if len(outcomes) == 2 and outcomes[0][1] is not None and outcomes[1][2] == 1:
                    break
                time.sleep(.15)
            else:
                raise AssertionError('daemon did not record separate recipient outcomes')
            assert len(server.messages) == 1 and server.messages[0][0] == 'receiver@example.invalid'
            with sqlite3.connect(state / 'monitor.db') as db:
                desktop=db.execute('SELECT delivered,attempts,error FROM desktop_jobs WHERE event_id=1').fetchone()
            assert desktop[0] is None and desktop[1]>=1 and desktop[2]=='desktop_test_unavailable', desktop
        finally:
            daemon.terminate()
            stdout, stderr = daemon.communicate(timeout=5)
            assert SECRET.encode() not in stdout + stderr
        # Restart must not resubmit the accepted recipient or permanent rejection.
        before = len(server.messages)
        daemon = subprocess.Popen([str(BINARY), '--state', str(state), '--socket', str(root / 'api.sock'), 'serve'],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(2.5)
            assert len(server.messages) == before
        finally:
            daemon.terminate()
            daemon.communicate(timeout=5)
    finally:
        server.shutdown()
        server.server_close()
    # End-to-end correlation: real HTTPS discovery -> SQLite events/queues -> SMTP.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from email import policy as email_policy
    from email.parser import BytesParser
    fixture=json.loads((Path(__file__).resolve().parents[1]/'tests/fixtures/dell-r340-hierarchy.json').read_text())
    phase={'value':'on'}
    class RedfishHandler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.headers.get('Authorization')!='Basic '+base64.b64encode(b'monitor:'+SECRET.encode()).decode():
                self.send_error(401);return
            resources={item['uri']:json.loads(json.dumps(item['body'])) for item in fixture['resources']}
            resources.update({'/redfish/v1/':{'Systems':{'@odata.id':'/redfish/v1/Systems'},'Chassis':{'@odata.id':'/redfish/v1/Chassis'}},'/redfish/v1/Systems':{'Members':[{'@odata.id':'/redfish/v1/Systems/System.Embedded.1'}]},'/redfish/v1/Chassis':{'Members':[{'@odata.id':'/redfish/v1/Chassis/System.Embedded.1'}]}})
            value=resources.get(self.path)
            if value is None:self.send_error(404);return
            def adjust(body):
                if not isinstance(body,dict):return
                status=body.get('Status')
                if isinstance(status,dict):
                    if phase['value']=='recovered':status.update(Health='OK',State='Enabled');status.pop('HealthRollup',None)
                    elif phase['value']=='on':
                        status['State']='Enabled'
                        if 'Slot.2' in body.get('@odata.id','') or body.get('MemberId')=='1':status['Health']='OK'
                        else:status['Health']='Critical'
                for key in ['Members','PowerSupplies']:
                    if isinstance(body.get(key),list):
                        for child in body[key]:adjust(child)
            adjust(value)
            payload=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
    redfish=ThreadingHTTPServer(('127.0.0.1',0),RedfishHandler);redfish.socket=context.wrap_socket(redfish.socket,server_side=True)
    threading.Thread(target=redfish.serve_forever,daemon=True).start()
    mail_server=start('plain')
    state=root/'correlation-state';device_file=root/'device.json'
    device_file.write_text(json.dumps({'id':'synthetic-correlated','name':'Synthetic server','endpoint':f'https://localhost:{redfish.server_port}/','username':'monitor','interval_seconds':30,'repeat_seconds':300,'alerts_enabled':True,'enabled':True,'ca_file':str(ca)}))
    def cli(*args,password=None):
        result=subprocess.run([str(BINARY),'--state',str(state),*args],input=password,text=True,capture_output=True,timeout=20)
        assert result.returncode==0,result.stderr
        assert SECRET not in result.stdout+result.stderr
        return result
    def deliver(expected):
        daemon=subprocess.Popen([str(BINARY),'--state',str(state),'--socket',str(root/'correlation.sock'),'serve'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+12
            while time.monotonic()<deadline:
                with sqlite3.connect(state/'monitor.db') as db:pending=db.execute("SELECT COUNT(*) FROM mail_recipient p JOIN outbox o ON o.id=p.outbox_id WHERE p.delivered IS NULL AND o.cancelled=0").fetchone()[0]
                if pending==0:break
                time.sleep(.1)
            else:raise AssertionError('correlated SMTP job was not submitted')
            assert len(mail_server.messages)==expected,[(r,len(body)) for r,body in mail_server.messages]
        finally:
            daemon.terminate();stdout,stderr=daemon.communicate(timeout=5);assert SECRET.encode() not in stdout+stderr
        return BytesParser(policy=email_policy.default).parsebytes(mail_server.messages[-1][1]).get_content()
    try:
        cli('device-put','--file',str(device_file),password=SECRET+'\n')
        cfg=settings(mail_server,'plain');cfg.update(enabled=True,username='',ca_pem=None,body_template='{{message}}\n{{kind}}\n{{resource}}')
        with sqlite3.connect(state/'monitor.db') as db:db.execute('INSERT INTO mail_settings VALUES(1,?,?,1)',(json.dumps(cfg),b''))
        cli('poll-once');body=deliver(1);assert 'PSU.Slot.1' in body and 'Alarm' in body,body
        phase['value']='off'
        with sqlite3.connect(state/'monitor.db') as db:db.execute('UPDATE alarm_state SET emitted=?',(int(time.time())-301,))
        cli('poll-once');body=deliver(2);assert 'aktuell nicht bewertbar' in body and 'Wiederholung' in body,body
        phase['value']='recovered';cli('poll-once');body=deliver(3);assert 'Entwarnung' in body and 'PSU.Slot.1' in body,body
    finally:
        redfish.shutdown();redfish.server_close();mail_server.shutdown();mail_server.server_close()
print('PASS: verified explicitly selected plaintext with/without auth, STARTTLS/implicit TLS, authentication, CA/hostname rejection, no downgrade, fixed errors, real daemon independent desktop failure/SMTP recipient progress and restart without resubmission; one SMTP message each for discovered component alarm/offline reminder/recovery; loopback only')
