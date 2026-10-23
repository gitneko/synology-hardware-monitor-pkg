#!/usr/bin/env python3
"""Exercise the real local HTTP/API/polling path with a synthetic TLS BMC."""
import base64
import http.client
import json
import secrets
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT/'target/debug/hardware-monitor'
PASSWORD = 'synthetic-local-device-secret'


class Bmc(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.headers.get('Authorization') != 'Basic ' + base64.b64encode(f'monitor:{PASSWORD}'.encode()).decode():
            self.send_error(401)
            return
        data = {
            '/redfish/v1/': {'Systems': {'@odata.id': '/redfish/v1/Systems'}},
            '/redfish/v1/Systems': {'Members': [{'@odata.id': '/redfish/v1/Systems/1'}]},
            '/redfish/v1/Systems/1': {'Name': 'Local test server', 'Status': {'Health': 'OK'},
                                    'Thermal': {'@odata.id': '/redfish/v1/Systems/1/Thermal'}},
            '/redfish/v1/Systems/1/Thermal': {'Fans': [{'MemberId': '1', 'Name': 'Local fan',
                'Status': {'Health': 'OK', 'State': 'Enabled'}, 'Reading': 42, 'ReadingUnits': 'Percent'}]},
        }
        if self.path not in data:
            self.send_error(404)
            return
        body = json.dumps(data[self.path]).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(body)


def exercise_snmp(root, write, dashboard):
    from snmp_p2_integration import agent
    from snmp_p3_integration import community_packet
    community = secrets.token_hex(16)
    users = [('local_snmp', 'SHA-256', secrets.token_hex(12), secrets.token_hex(12))]
    ids = []
    with agent(root/'snmp-reference', community, users) as agent_port:
        for version in ('v1', 'v2c', 'v3'):
            security = {'version': version}
            credentials = {'kind':'community', 'community':community}
            if version == 'v3':
                security.update(username=users[0][0],auth='sha256',privacy='aes128')
                credentials = {'kind':'usm','auth_password':users[0][2],'priv_password':users[0][3]}
            device = dict(id=None,revision=None,name=f'Local SNMP {version}',primary_protocol='snmp',
                          snmp_poll=dict(host='127.0.0.1',port=agent_port,security=security,profile='generic',timeout_ms=500,retries=1),
                          interval_seconds=30,repeat_seconds=None,alerts_enabled=False,enabled=True,
                          snmp_secrets={'snmp_poll':{'action':'replace','credentials':credentials}})
            if version == 'v1':
                device['snmp_traps'] = dict(enabled=True,allowed_sources=['127.0.0.1'],security={'version':'v2c'},profile='generic')
                device['snmp_secrets']['snmp_traps'] = {'action':'replace','credentials':{'kind':'community','community':community}}
            assert write({'action':'test','device':device})['ok'], 'Local SNMP connection test failed'
            saved = write({'action':'save','device':device})
            assert saved['ok'], 'Local SNMP device save failed'
            ids.append(saved['id'])
        for _ in range(200):
            view = dashboard()
            polled = [d for d in view['devices'] if d['device']['id'] in ids and (d.get('snapshot') or {}).get('snmp')]
            if len(polled) == 3: break
            time.sleep(.05)
        assert len(polled) == 3, 'Local daemon did not poll all three SNMP versions'
        assert {d['snapshot']['snmp']['version'] for d in polled} == {'v1','v2c','v3'}
        assert all(any(o['key']=='snmp:availability' and o['health']=='ok' for o in d['snapshot']['observations']) for d in polled)
        assert next(d for d in polled if d['snapshot']['snmp']['version']=='v3')['snapshot']['snmp']['engine_id']
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reservation:
            reservation.bind(('127.0.0.1',0)); receiver_port=reservation.getsockname()[1]
        revision=dashboard()['snmp_receiver']['revision']
        enabled=write({'action':'snmp_receiver_save','settings':dict(enabled=True,listen_port=receiver_port,listen_addresses=['127.0.0.1']),'revision':revision})
        assert enabled['ok'], 'Local HTTP API did not enable the SNMP receiver'
        packet=community_packet(root,'2c',community)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
            for _ in range(100):
                sender.sendto(packet,('127.0.0.1',receiver_port))
                receipts=write({'action':'snmp_receipts','device':ids[0],'limit':10})
                if receipts['ok'] and receipts['receipts']:break
                time.sleep(.05)
        assert receipts['ok'] and receipts['receipts'], 'Local mode did not receive the independent SNMP trap'
        assert receipts['receipts'][0]['receipt']['version']=='v2c'
        assert any(d['device']['id']==ids[0] and d.get('last_trap_received') for d in dashboard()['devices'])
        view=json.dumps(dashboard())+json.dumps(receipts)
        assert not any(secret in view for secret in (community,users[0][2],users[0][3])), 'Local SNMP credentials were disclosed'
        current=dashboard()['snmp_receiver']['revision']
        assert write({'action':'snmp_receiver_save','settings':dict(enabled=False,listen_port=receiver_port,listen_addresses=['127.0.0.1']),'revision':current})['ok']
        # Keep this fixture isolated from the persistence/Redfish assertions.
        for identifier in ids:
            item=next(d for d in dashboard()['devices'] if d['device']['id']==identifier)
            assert write({'action':'delete','id':identifier,'revision':item['revision']})['ok']
    print('Local SNMP integration passed: HTTP probe/save, v1/v2c/v3 authPriv daemon polling, receiver configuration and independent v2c trap')


def main():
    with tempfile.TemporaryDirectory(prefix='hm-local-test-') as directory:
        root = Path(directory)
        ui = root/'ui'
        (ui/'assets').mkdir(parents=True)
        (ui/'index.html').write_text('<html><head></head><body>Local test UI</body></html>')
        (ui/'assets/app.js').write_text('console.log("test UI");')
        (ui/'assets/leak.js').symlink_to(root/'secret.txt')
        (root/'secret.txt').write_text('private-marker')
        def openssl(*arguments):
            subprocess.run(['openssl', *arguments], check=True, capture_output=True)
        openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=Local Integration CA', '-keyout', str(root/'ca.key'), '-out', str(root/'ca.crt'))
        openssl('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
                '-keyout', str(root/'tls.key'), '-out', str(root/'tls.csr'))
        (root/'extensions.cnf').write_text('subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        openssl('x509', '-req', '-days', '1', '-in', str(root/'tls.csr'), '-CA', str(root/'ca.crt'),
                '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-extfile', str(root/'extensions.cnf'), '-out', str(root/'tls.crt'))
        bmc = ThreadingHTTPServer(('127.0.0.1', 0), Bmc)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'tls.crt', root/'tls.key')
        bmc.socket = context.wrap_socket(bmc.socket, server_side=True)
        threading.Thread(target=bmc.serve_forever, daemon=True).start()
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        command = [str(BINARY), 'dev', '--directory', str(root/'state'), '--port', str(port), '--web-root', str(ui)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def request(method='GET', path='/api.cgi', body=None, headers=None):
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
            options = {'X-HardwareMonitor-Language': 'en'}
            if body is not None:
                options.update({'Content-Type': 'application/json', 'Origin': origin})
            options.update(headers or {})
            connection.request(method, path, json.dumps(body) if body is not None else None, options)
            result = connection.getresponse()
            data = result.read()
            status = result.status
            connection.close()
            return status, data
        def dashboard():
            status, data = request()
            assert status == 200
            result = json.loads(data)
            assert result['ok'], result
            return result['data']
        def write(operation, csrf=None):
            return json.loads(request('POST', body={'csrf': csrf or dashboard()['csrf'], 'operation': operation})[1])
        try:
            for _ in range(200):
                try:
                    view = dashboard()
                    break
                except (ConnectionError, OSError):
                    assert process.poll() is None, process.stderr.read().decode()
                    time.sleep(.05)
            else:
                raise AssertionError('Local server did not start')
            assert view['runtime'] == 'local-development' and view['user']['role'] == 'administrator'
            assert not (root/'state/api.sock').exists()
            assert request(path='/')[0] == 200 and b'/local-runtime.js' in request(path='/')[1]
            assert b'HARDWARE_MONITOR_LOCAL = true' in request(path='/local-runtime.js')[1]
            assert request(path='/assets/app.js')[0] == 200
            for path in ['/master.key', '/../secret.txt', '/assets/../../secret.txt', '/assets/%2e%2e/secret.txt', '/assets/leak.js']:
                assert request(path=path)[0] == 404, path
            for headers in [{'Host': 'attacker.invalid'}, {'Origin': 'https://attacker.invalid'}, {'Sec-Fetch-Site': 'cross-site'}]:
                assert request(headers=headers)[0] == 403
            assert request('POST', body={}, headers={'Origin': ''})[0] == 403
            assert request('OPTIONS')[0] == 405
            assert write({'action': 'events_clear', 'confirm': True}, 'invalid')['code'] == 'write_csrf_invalid'
            # A client cannot select local authentication through the normal Request envelope.
            assert json.loads(request('POST', body={'auth': {}, 'operation': {'action': 'dashboard'}})[1])['ok'] is False
            device = {'id': None, 'revision': None, 'name': 'Local BMC',
                      'endpoint': f'https://localhost:{bmc.server_port}/', 'username': 'monitor',
                      'password': PASSWORD, 'interval_seconds': 30, 'repeat_seconds': None,
                      'alerts_enabled': False, 'enabled': True, 'tls_profile': 'standard',
                      'trust_mode': 'custom', 'certificate_pem': (root/'ca.crt').read_text()}
            probe = write({'action': 'test', 'device': device})
            assert probe['ok'], probe
            saved = write({'action': 'save', 'device': device})
            assert saved['ok'], saved
            for _ in range(200):
                view = dashboard()
                if view['devices'] and view['devices'][0].get('snapshot'):
                    break
                time.sleep(.05)
            exercise_snmp(root, write, dashboard)
            view = dashboard()
            old_csrf = view['csrf']
            item = view['devices'][0]
            assert any(row['reading'] == 42 for row in item['snapshot']['observations']), item
            assert PASSWORD not in json.dumps(view)
            assert (root/'state/master.key').stat().st_mode & 0o777 == 0o600
            # Stop/restart retains the same devices, encrypted credentials and measurements.
            process.terminate()
            output, error = process.communicate(timeout=10)
            assert process.returncode == 0, error.decode()
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for _ in range(200):
                try:
                    retained = dashboard()
                    break
                except (ConnectionError, OSError):
                    time.sleep(.05)
            assert retained['devices'][0]['device']['id'] == item['device']['id']
            assert retained['devices'][0]['snapshot']
            assert write({'action': 'events_clear', 'confirm': True}, old_csrf)['code'] == 'write_csrf_invalid'
            assert write({'action': 'desktop_test'})['code'] == 'desktop_test_unavailable'
            assert PASSWORD.encode() not in output + error
            print('Local development integration passed: UI, real HTTP API, CSRF/origin/Host, TLS Redfish probe/poll, persistence, private state')
        finally:
            if process.poll() is None:
                process.terminate()
            output, error = process.communicate(timeout=10)
            bmc.shutdown()
            assert PASSWORD.encode() not in output + error


if __name__ == '__main__':
    main()
