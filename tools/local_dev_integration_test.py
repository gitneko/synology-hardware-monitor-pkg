#!/usr/bin/env python3
"""Exercise the real local HTTP/API/polling path with a synthetic TLS BMC."""
import base64
import http.client
import json
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
            old_csrf = view['csrf']
            item = view['devices'][0]
            assert any(row['reading'] == 42 for row in item['snapshot']['observations']), item
            assert PASSWORD not in json.dumps(view)
            assert (root/'state/master.key').stat().st_mode & 0o777 == 0o600
            # Real background jobs, binary download and chunk upload through HTTP.
            def completed(job):
                for _ in range(2000):
                    status=write({'action':'job_status','id':job})
                    assert status['ok'],status
                    status=status['status']
                    assert status['state'] not in ['failed','cancelled'],status
                    if status['state']=='ready':return status['result']
                    time.sleep(.01)
                raise AssertionError('job timeout')
            history=view['history']
            assert history['settings']=={'events_days':90,'hardware_logs_days':90}
            assert write({'action':'retention_save','settings':{'events_days':7,'hardware_logs_days':30},'revision':history['revision']})['ok']
            cleanup=write({'action':'cleanup_preview'})['job'];completed(cleanup)
            assert write({'action':'cleanup_run','id':cleanup,'confirm':True})['ok'];completed(cleanup)
            job=write({'action':'backup_export_start','password':'synthetic-backup-password'})['job'];completed(job)
            status,archive=request(path='/api.cgi?download='+job)
            assert status==200 and archive.startswith(b'HWMON-STREAM-1\n') and PASSWORD.encode() not in archive
            status,metadata=request('HEAD',path='/api.cgi?download='+job)
            assert status==200 and metadata==b''
            upload=write({'action':'backup_upload_start'})['job']
            for offset in range(0,len(archive),512*1024):
                part=archive[offset:offset+512*1024]
                result=write({'action':'backup_upload_part','id':upload,'offset':offset,'data':base64.b64encode(part).decode()})
                assert result['ok'] and result['bytes']==offset+len(part),result
            assert write({'action':'backup_inspect_start','id':upload,'bytes':len(archive),'password':'synthetic-backup-password'})['ok']
            summary=completed(upload);assert summary['devices']==1
            assert write({'action':'backup_restore_start','id':upload,'expected_audit':summary['expected_audit'],'confirm':True})['ok']
            assert completed(upload)['restored']
            assert dashboard()['history']['settings']=={'events_days':7,'hardware_logs_days':30}
            assert dashboard()['devices'][0]['device']['enabled'] is False
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
