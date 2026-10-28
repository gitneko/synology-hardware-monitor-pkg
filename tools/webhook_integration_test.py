#!/usr/bin/env python3
"""Exercise outgoing webhooks against isolated HTTP/HTTPS recipients and a synthetic BMC."""
import base64
from email.parser import BytesParser
from email.policy import default
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT/'target/debug/hardware-monitor'


def main():
    records = []
    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            resources = {
                '/redfish/v1/': {'Systems': {'@odata.id': '/redfish/v1/Systems'}},
                '/redfish/v1/Systems': {'Members': [{'@odata.id': '/redfish/v1/Systems/1'}]},
                '/redfish/v1/Systems/1': {'Name': 'Synthetic server', 'Status': {'Health': 'OK'}, 'Thermal': {'@odata.id': '/redfish/v1/Systems/1/Thermal'}},
                '/redfish/v1/Systems/1/Thermal': {'Fans': [{'MemberId': '1', 'Name': 'Synthetic fan', 'Status': {'Health': 'Critical', 'State': 'Enabled'}, 'Reading': 0}]},
            }
            body = json.dumps(resources.get(self.path, {})).encode()
            self.send_response(200 if self.path in resources else 404)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            path = urlsplit(self.path).path
            previous = sum(r['path'] == path for r in records)
            records.append({'path': path, 'query': urlsplit(self.path).query, 'body': body, 'headers': {k.lower(): v for k,v in self.headers.items()}, 'time': time.monotonic()})
            if self.path == '/slow':
                time.sleep(5)
            code = 429 if self.path == '/retry' and previous == 0 else 401 if self.path == '/reject' else 302 if self.path == '/redirect' else 204
            self.send_response(code)
            if code == 429:
                self.send_header('Retry-After', '2')
            if code == 302:
                self.send_header('Location', '/must-not-follow')
            self.send_header('Content-Length', '0')
            self.end_headers()

    def wait_until(predicate, timeout=20):
        deadline = time.monotonic()+timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(.05)
        raise AssertionError('Timed out waiting for isolated webhook fixture')

    with tempfile.TemporaryDirectory(prefix='hm-webhooks-') as directory:
        root = Path(directory)
        def openssl(*args):
            subprocess.run(['openssl', *args], check=True, capture_output=True)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Webhook synthetic CA', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.crt'))
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(root/'tls.key'), '-out', str(root/'tls.csr'))
        (root/'extensions').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-days', '1', '-in', str(root/'tls.csr'), '-CA', str(root/'ca.crt'), '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-extfile', str(root/'extensions'), '-out', str(root/'tls.crt'))
        plain = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        secure = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'tls.crt', root/'tls.key')
        secure.socket = context.wrap_socket(secure.socket, server_side=True)
        for server in (plain, secure):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        command = [str(BINARY), 'dev', '--directory', str(root/'state'), '--port', str(port), '--web-root', str(ROOT/'web/dist')]
        log = (root/'daemon.log').open('w+')
        process = subprocess.Popen(command, stdout=log, stderr=log)
        database = root/'state/monitor.db'
        def request(operation=None, csrf=None):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=40)
            if operation is None:
                connection.request('GET', '/api.cgi')
            else:
                body = {'operation': operation, 'csrf': csrf or request()['data']['csrf']}
                connection.request('POST', '/api.cgi', json.dumps(body), {'Content-Type': 'application/json', 'Origin': origin})
            response = connection.getresponse()
            data = json.loads(response.read())
            connection.close()
            return data
        def started():
            if process.poll() is not None:
                log.seek(0)
                raise AssertionError(log.read())
            try:
                return request()['ok']
            except (OSError, ConnectionError):
                return False
        def sql(statement, parameters=()):
            with sqlite3.connect(database, timeout=10) as conn:
                return conn.execute(statement, parameters).fetchall()
        def fresh(name, mode, scheme='http'):
            address = f'http://127.0.0.1:{plain.server_port}' if scheme == 'http' else f'https://localhost:{secure.server_port}'
            return {'id': None, 'revision': 0, 'url': address+'/'+name, 'credential': None, 'settings': {'name': name, 'enabled': True, 'allow_private': True, 'format': mode}}
        try:
            wait_until(started)
            target = fresh('tls-test', 'generic', 'https')
            assert not request({'action': 'webhook_save', 'webhook': target}, 'invalid')['ok']
            assert request({'action': 'webhook_test', 'webhook': target})['code'] == 'webhook_connection_failed'
            sql("UPDATE audit_log SET created=created-31 WHERE action='webhook.test'")
            target['settings']['ca_pem'] = (root/'ca.crt').read_text()
            assert request({'action': 'webhook_test', 'webhook': target})['ok']
            sql("UPDATE audit_log SET created=created-31 WHERE action='webhook.test'")
            target['url'] = f'https://127.0.0.1:{secure.server_port}/wrong-host'
            assert request({'action': 'webhook_test', 'webhook': target})['code'] == 'webhook_connection_failed'
            sql("UPDATE audit_log SET created=created-31 WHERE action='webhook.test'")
            blocked = fresh('blocked', 'generic'); blocked['settings']['allow_private'] = False
            assert request({'action': 'webhook_test', 'webhook': blocked})['code'] == 'webhook_network_blocked'
            for language,expected_device,expected_message in [('de','Beispielserver','Beispielserver: Lüfter ausgefallen'),('en','Sample server','Sample server: Fan failed')]:
                localized = fresh('language-'+language,'generic')
                localized['settings']['language'] = language
                preview = request({'action':'webhook_preview','webhook':localized})
                assert preview['ok'] and json.loads(preview['preview']['body'])['message']==expected_message
                sql("UPDATE audit_log SET created=created-31 WHERE action='webhook.test'")
                assert request({'action':'webhook_test','webhook':localized})['ok']
                actual=json.loads(next(r for r in records if r['path']=='/language-'+language)['body'])
                assert actual['device']==expected_device and actual['message']==expected_message
                assert actual['health']=='critical' and actual['kind']=='alarm'
            targets = []
            for name, mode in [('text','text'), ('json','json'), ('form','form'), ('multipart','multipart'), ('retry','generic'), ('reject','generic'), ('redirect','generic'), ('slow','generic'), ('fast','generic'), ('https','generic'), ('discord','discord'), ('slack','slack')]:
                target = fresh(name, mode, 'https' if name == 'https' else 'http')
                if name == 'https':
                    target['settings']['ca_pem'] = (root/'ca.crt').read_text()
                    target['settings']['language'] = 'en'
                if mode == 'text':
                    target['settings'].update(template='{{device}}: {{message}}', auth='basic', username='synthetic-user')
                    target['credential'] = 'synthetic-basic-secret'
                if mode == 'json':
                    target['settings']['template'] = '{"id":"{{event_id}}","verified":"{{verified}}","message":"{{message}}"}'
                if mode in ('discord','slack'):
                    target['settings']['chat_template'] = 'Custom {{device}}: {{message}}'
                if mode == 'discord':
                    target['settings']['discord_username'] = 'Hardware Monitor Integration'
                    target['settings']['discord_avatar_url'] = 'https://example.invalid/avatar.png'
                    target['settings']['embeds_template'] = '[{"title":"{{device}}","description":"{{message}}","color":15548997,"fields":[{"name":"Severity","value":"{{health}}","inline":true}]}]'
                if mode in ('form','multipart'):
                    target['settings']['fields'] = [dict(id='a'*32,name='item',value='ü & + = {{message}}',secret=False), dict(id='b'*32,name='item',value='{{event_id}}',secret=False),dict(id='c'*32,name='token',value='synthetic-form-secret',secret=True)]
                    target['settings']['headers'] = [dict(id='d'*32,name='X-Secret',value='synthetic-header-secret',secret=True)]
                preview = request({'action': 'webhook_preview', 'webhook': target})
                assert preview['ok'], preview
                assert 'synthetic-form-secret' not in json.dumps(preview)
                saved = request({'action': 'webhook_save', 'webhook': target})
                assert saved['ok'], saved
                revealed = request({'action':'webhook_reveal_url','id':saved['id'],'revision':saved['revision']})
                assert revealed['ok'] and revealed['url'] == target['url']
                assert request({'action':'webhook_reveal_url','id':saved['id'],'revision':0})['code']=='webhook_conflict'
                target.update(id=saved['id'], revision=saved['revision'])
                targets.append(target)
            for name in ('excluded-discord', 'excluded-slack'):
                target = fresh(name, 'generic')
                target['settings']['selection'] = dict(critical=False, warning=False, recovery=False, repeat=False, hardware_log=False, snmp_trap=False, monitoring=False)
                assert request({'action': 'webhook_save', 'webhook': target})['ok']
            target = fresh('excluded-device', 'generic')
            target['settings']['devices'] = ['another-device']
            assert request({'action': 'webhook_save', 'webhook': target})['ok']
            device = dict(id=None, revision=None, name='Synthetic BMC', endpoint=f'https://localhost:{secure.server_port}', username='monitor', password='synthetic-device-secret', interval_seconds=86400, repeat_seconds=None, alerts_enabled=True, enabled=True, trust_mode='custom', certificate_pem=(root/'ca.crt').read_text())
            saved = request({'action':'save','device':device})
            assert saved['ok'], saved
            wait_until(lambda: all(any(r['path']=='/'+t['settings']['name'] for r in records) for t in targets))
            wait_until(lambda: sql("SELECT COUNT(*) FROM webhook_jobs WHERE http_status=429")[0][0])
            assert not any(r['path']=='/must-not-follow' for r in records)
            first_retry = next(r for r in records if r['path']=='/retry')
            sql("UPDATE webhook_jobs SET next_try=0 WHERE http_status=429")
            sql("UPDATE webhook_endpoints SET next_send=0 WHERE id IN (SELECT endpoint FROM webhook_jobs WHERE http_status=429)")
            wait_until(lambda: len([r for r in records if r['path']=='/retry'])>=2)
            retry = [r for r in records if r['path']=='/retry']
            assert retry[0]['headers']['x-hardware-monitor-delivery'] == retry[1]['headers']['x-hardware-monitor-delivery']
            automatic_english = json.loads(next(r for r in records if r['path']=='/https')['body'])
            assert automatic_english['device']=='Synthetic BMC' and 'Hardware state critical' in automatic_english['message']
            text = next(r for r in records if r['path']=='/text')
            assert text['headers']['authorization'] == 'Basic '+base64.b64encode(b'synthetic-user:synthetic-basic-secret').decode()
            assert text['headers']['content-type'].startswith('text/plain')
            value = json.loads(next(r for r in records if r['path']=='/json')['body'])
            assert isinstance(value['id'], int) and value['verified'] is True
            form = next(r for r in records if r['path']=='/form')
            pairs = parse_qsl(form['body'].decode())
            assert [k for k,_ in pairs] == ['item','item','token'] and pairs[-1][1]=='synthetic-form-secret'
            assert pairs[0][1].startswith('ü & + = ') and form['headers']['x-secret']=='synthetic-header-secret'
            multi = next(r for r in records if r['path']=='/multipart')
            message = BytesParser(policy=default).parsebytes(('Content-Type: '+multi['headers']['content-type']+'\r\nMIME-Version: 1.0\r\n\r\n').encode()+multi['body'])
            fields = [(p.get_param('name',header='content-disposition'), p.get_payload(decode=True).decode()) for p in message.iter_parts()]
            assert [k for k,_ in fields] == ['item','item','token'] and fields[-1][1]=='synthetic-form-secret'
            fast = next(r for r in records if r['path']=='/fast'); slow = next(r for r in records if r['path']=='/slow')
            assert fast['time'] < slow['time']+5, 'A slow destination blocked another recipient'
            wait_until(lambda: sql("SELECT COUNT(*) FROM webhook_jobs WHERE http_status=401 AND permanent=1")[0][0])
            public = json.dumps(request())
            for secret in ('synthetic-basic-secret','synthetic-form-secret','synthetic-header-secret'):
                assert secret not in public
            assert 'webhooks' in public
            exclusions = [job for event in request()['data']['events'] for job in event['webhooks'] if job['name'].startswith('excluded-')]
            assert {job['name'] for job in exclusions} == {'excluded-discord', 'excluded-slack', 'excluded-device'}
            assert all(job['cancelled'] and job['error'] == ('device_filtered' if job['name'] == 'excluded-device' else 'filtered') and job['attempts'] == 0 for job in exclusions)
            assert not any(r['path'].startswith('/excluded-') for r in records)
            discord = next(r for r in records if r['path']=='/discord')
            discord_body = json.loads(discord['body'])
            assert discord_body['username']=='Hardware Monitor Integration' and discord_body['avatar_url']=='https://example.invalid/avatar.png'
            assert discord_body['content'].startswith('Custom ') and discord_body['embeds'][0]['color']==15548997
            assert discord_body['allowed_mentions']=={'parse':[]} and parse_qsl(discord['query'])==[('wait','true')]
            slack_body = json.loads(next(r for r in records if r['path']=='/slack')['body'])
            assert not any(key in slack_body for key in ('username','avatar_url','icon_url'))
            assert slack_body['text'].startswith('Custom ') and slack_body['blocks'][0]['text']['text']==slack_body['text']
            assert not sql('PRAGMA foreign_key_check')
            print('Webhook integration passed: HTTP/HTTPS, CA and hostname validation, four encodings, repeated fields, auth, redaction, automatic BMC alarms, independent workers, 429 retry IDs, terminal 401, redirect refusal, saved URL reveal, custom Discord/Slack/embeds, German/English samples, automatic English delivery and event/device selection exclusions in history without requests')
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait()
            plain.shutdown(); secure.shutdown(); log.close()


if __name__ == '__main__':
    main()
