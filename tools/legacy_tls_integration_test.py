#!/usr/bin/env python3
"""Pinned DHE-only controller tests; synthetic loopback and credentials only."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import warnings

BINARY = Path(sys.argv[1]).resolve()
SECRET = 'synthetic-legacy-secret'
AUTH = 'Basic ' + base64.b64encode(('reader:' + SECRET).encode()).decode()
TOKEN = 'synthetic-session-token-not-for-output'


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def do_GET(self):
        server = self.server
        server.requests += 1
        server.paths.append(self.path)
        server.last_get_stream = self.connection
        basic = self.headers.get('Authorization') == AUTH
        token = server.sessions and server.active_session and self.headers.get('X-Auth-Token') == TOKEN
        server.authorized += basic or token
        server.basic_requests += basic
        server.token_requests += token
        if self.path == server.delay_path:
            time.sleep(17)
        public_root = server.graph and self.path == '/redfish/v1/'
        if not public_root and not (basic or token):
            self.send_response(401)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path == '/redfish/v1/' and server.redirect:
            self.send_response(308)
            self.send_header('Location', server.redirect)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        graph = {
            '/redfish/v1/': {'RedfishVersion': '1.0.2', **{key: {'@odata.id': '/redfish/v1/' + key} for key in ['Systems', 'Chassis', 'Managers']}},
            '/redfish/v1/Systems': {'Members': [{'@odata.id': '/redfish/v1/Systems/R420'}]},
            '/redfish/v1/Chassis': {'Members': [{'@odata.id': '/redfish/v1/Chassis/R420'}]},
            '/redfish/v1/Managers': {'Members': []},
            '/redfish/v1/Systems/R420': {'Name': 'Synthetic R420', 'Status': {'Health': 'OK'}},
            '/redfish/v1/Chassis/R420': {'Thermal': {'@odata.id': '/redfish/v1/Chassis/R420/Thermal'}},
            '/redfish/v1/Chassis/R420/Thermal': {'Temperatures': [{'MemberId': 'Inlet', 'Name': 'Inlet', 'ReadingCelsius': 24, 'Status': {'Health': 'OK'}}]},
        }
        if server.sessions:
            graph['/redfish/v1/']['Links'] = {'Sessions': {'@odata.id': server.session_collection}}
        log_root = '/redfish/v1/Systems/R420/LogServices'
        entries = log_root + '/LC/Entries'
        if server.mode:
            graph['/redfish/v1/Systems/R420']['LogServices'] = {'@odata.id': log_root}
            graph[log_root] = {'Members': [{'@odata.id': log_root + '/LC'}]}
            graph[log_root + '/LC'] = {'Entries': {'@odata.id': entries}}
            if server.mode == 'items':
                graph[entries] = {'Members': [{'Id': str(i), 'Message': 'Synthetic old entry', 'Created': '2026-01-01T00:00:00Z', 'Severity': 'OK'} for i in range(4097)]}
            else:
                graph[entries] = {'Members': [{'@odata.id': entries + '/' + str(i)} for i in range(300)]}
            if self.path.startswith(entries + '/'):
                if server.mode == 'deadline':
                    time.sleep(3)
                graph[self.path] = {'Id': self.path.rsplit('/', 1)[-1], 'Message': 'Synthetic old entry', 'Created': '2026-01-01T00:00:00Z', 'Severity': 'OK'}
        body = b'x' * (2 * 1024 * 1024 + 1) if server.large else json.dumps(graph[self.path] if server.graph else {'RedfishVersion': '1.0.2'}).encode()
        if server.mode == 'invalid' and self.path == entries:
            body = b'{"secret":"synthetic-legacy-secret",broken}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        if self.path == server.close_path:
            if server.close_header:
                self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        try:
            self.wfile.write(body)
        except (ConnectionError, OSError):
            pass
        if server.swap_after_root and self.path == '/redfish/v1/':
            server.context.load_cert_chain(replacement, key)
            self.close_connection = True

    def do_POST(self):
        server = self.server
        if server.reject_reused_auth and self.connection is server.last_get_stream:
            server.reused_auth_attempts += 1
            self.close_connection = True
            return
        server.session_posts += 1
        assert self.path == server.session_collection, 'Only the advertised session collection may receive POST'
        size = int(self.headers['Content-Length'])
        assert size <= 8192
        credentials = json.loads(self.rfile.read(size))
        status = server.session_status
        if credentials != {'UserName': 'reader', 'Password': SECRET}:
            status = 401
        self.send_response(status)
        if status == 201:
            server.active_session = True
            self.send_header('X-Auth-Token', TOKEN)
            self.send_header('Location', server.session_location)
        if status == 307:
            self.send_header('Location', '/redfish/v1/Chassis')
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'{}')

    def do_DELETE(self):
        server = self.server
        if server.reject_reused_auth and self.connection is server.last_get_stream:
            server.reused_auth_attempts += 1
            self.close_connection = True
            return
        server.session_deletes.append(self.path)
        assert self.path == server.session_location, 'Only the returned session URL may be deleted'
        assert self.headers.get('X-Auth-Token') == TOKEN
        server.active_session = False
        self.send_response(204)
        self.send_header('Content-Length', '0')
        self.end_headers()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *_):
        pass

    def get_request(self):
        socket, address = super().get_request()
        self.connections += 1
        return socket, address


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)

    def openssl(*args):
        subprocess.run(['openssl', *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    key, cert, replacement, expired = [root / n for n in ('key.pem', 'cert.pem', 'replacement.pem', 'expired.pem')]
    openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-keyout', key, '-out', cert,
            '-days', '1', '-subj', '/CN=synthetic-old-controller', '-set_serial', '1', '-addext', 'basicConstraints=CA:TRUE')
    # Same private key and subject, but a different certificate: SPKI-only pinning would accept this.
    openssl('req', '-x509', '-key', key, '-sha256', '-out', replacement, '-days', '1',
            '-subj', '/CN=synthetic-old-controller', '-set_serial', '2', '-addext', 'basicConstraints=CA:TRUE')
    csr = root / 'expired.csr'
    openssl('req', '-new', '-key', key, '-out', csr, '-subj', '/CN=synthetic-old-controller')
    (root / 'index').touch()
    (root / 'serial').write_text('03\n')
    config = root / 'ca.cnf'
    config.write_text(f'[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={root}/index\nserial={root}/serial\nnew_certs_dir={root}\ndefault_md=sha256\npolicy=subject\nx509_extensions=extensions\n[subject]\ncommonName=supplied\n[extensions]\nbasicConstraints=CA:TRUE\n')
    openssl('ca', '-selfsign', '-batch', '-notext', '-config', config, '-cert', cert, '-keyfile', key,
            '-in', csr, '-startdate', '20000101000000Z', '-enddate', '20010101000000Z', '-out', expired)
    dh = root / 'dh.pem'
    openssl('genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt', 'group:ffdhe2048', '-out', dh)
    servers = []

    def start(certificate, old_tls=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            context.minimum_version = ssl.TLSVersion.TLSv1_1 if old_tls else ssl.TLSVersion.TLSv1_2
            context.maximum_version = context.minimum_version
        context.set_ciphers('DHE-RSA-AES256-SHA:@SECLEVEL=0' if old_tls else 'DHE-RSA-AES256-GCM-SHA384')
        context.load_dh_params(str(dh))
        context.load_cert_chain(certificate, key)
        server = Server(('127.0.0.1', 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.requests = server.authorized = 0
        server.basic_requests = server.token_requests = 0
        server.sessions = server.active_session = False
        server.session_posts = 0
        server.last_get_stream = None
        server.reject_reused_auth = False
        server.reused_auth_attempts = 0
        server.session_status = 201
        server.session_collection = '/redfish/v1/Sessions'
        server.session_location = '/redfish/v1/Sessions/owned'
        server.session_deletes = []
        server.delay_path = None
        server.redirect = None
        server.large = False
        server.graph = False
        server.mode = None
        server.close_path = None
        server.close_header = True
        server.swap_after_root = False
        server.context = context
        server.paths = []
        server.connections = 0
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    def settings(server, pin=cert):
        return {'id': 'legacy-test', 'name': 'Synthetic iDRAC7',
                'endpoint': f'https://127.0.0.1:{server.server_port}/', 'username': 'reader',
                'interval_seconds': 30, 'repeat_seconds': None, 'alerts_enabled': False,
                'ca_file': None, 'ca_pem': None, 'enabled': True,
                'tls_profile': 'idrac7', 'pinned_certificate_pem': pin.read_text()}

    def probe(config, success, expected_error=None, secret=SECRET):
        file = root / 'device.json'
        file.write_text(json.dumps(config))
        result = subprocess.run([str(BINARY), '--state', str(root / 'state'), 'device-test', '--file', str(file)],
                                input=secret + '\n', text=True, capture_output=True, timeout=20)
        assert (result.returncode == 0) == success, (result.stdout, result.stderr)
        assert SECRET not in result.stdout + result.stderr and TOKEN not in result.stdout + result.stderr
        if expected_error:
            assert expected_error in result.stderr, result.stderr
        return json.loads(result.stdout) if success else None

    try:
        server = start(cert)
        result = probe(settings(server), True)
        assert result['reachable'] and result['redfish_version'] == '1.0.2'
        assert len(result['certificate_fingerprint']) == 95
        assert server.requests == server.authorized == 1
        # No automatic fallback or reinterpretation of a CA import in Standard mode.
        standard = {**settings(server), 'tls_profile': 'standard', 'pinned_certificate_pem': None, 'ca_pem': cert.read_text()}
        probe(standard, False)
        assert server.requests == 1
        # Wrong pin, even when it has the same public key: no HTTP headers or credentials.
        probe(settings(server, replacement), False, 'connection_certificate_mismatch')
        assert server.requests == 1
        swapped = start(replacement)
        probe(settings(swapped), False, 'connection_certificate_mismatch')
        assert swapped.requests == swapped.authorized == 0
        # Explicit reimport permits a deliberately replaced certificate.
        probe(settings(swapped, replacement), True)
        assert swapped.requests == swapped.authorized == 1
        invalid_time = start(expired)
        probe(settings(invalid_time, expired), False, 'connection_certificate_expired')
        assert invalid_time.requests == 0
        older = start(cert, old_tls=True)
        probe(settings(older), False, 'connection_tls_incompatible')
        assert older.requests == 0
        # Same-origin redirects work and cross-origin redirects never contact the other server.
        server.redirect = '/redfish/v1/root'
        before = server.requests
        probe(settings(server), True)
        assert server.requests == before + 2
        before_foreign = swapped.requests
        server.redirect = f'https://127.0.0.1:{swapped.server_port}/redfish/v1/'
        probe(settings(server), False)
        assert swapped.requests == before_foreign
        server.redirect = '/outside-redfish'
        before = server.requests
        probe(settings(server), False)
        assert server.requests == before + 1
        server.redirect = None
        server.large = True
        probe(settings(server), False)
        server.large = False
        # iDRAC's root is public: wrong credentials must fail on its protected collections.
        server.graph = True
        before = server.connections
        server.paths.clear()
        probe(settings(server), False, 'connection_credentials_rejected', secret='wrong-synthetic-secret')
        assert server.paths == ['/redfish/v1/', '/redfish/v1/Systems']
        assert server.connections == before + 1
        before = server.connections
        result = probe(settings(server), True)
        assert result['checked_collections'] == 3
        assert server.connections == before + 1
        # Polling also uses the pinned transport, not only the connection-test path.
        file = root / 'device.json'
        file.write_text(json.dumps(settings(server)))
        before = server.connections
        for command, secret in [('device-put', SECRET + '\n'), ('poll-once', None), ('snapshot', None)]:
            args = [str(BINARY), '--state', str(root / 'poll-state'), command]
            if command == 'device-put':
                args += ['--file', str(file)]
            result = subprocess.run(args, input=secret, text=True, capture_output=True, timeout=20)
            assert result.returncode == 0, result.stderr
            assert SECRET not in result.stdout + result.stderr
        dashboard = json.loads(result.stdout)
        assert dashboard['devices'][0]['snapshot']['capabilities'][0]['outcome'] == 'available'
        snapshot = dashboard['devices'][0]['snapshot']
        assert len(snapshot['capabilities']) == 7
        assert all(c['outcome'] == 'available' for c in snapshot['capabilities'])
        assert any(o['label'] == 'Inlet' and o['reading'] == 24 for o in snapshot['observations'])
        assert server.connections == before + 1, 'The complete graph should share one authenticated TLS connection'
        # Controllers that close a connection explicitly still work after a verified reconnect.
        server.close_path = '/redfish/v1/Systems'
        before = server.connections
        probe(settings(server), True)
        assert server.connections == before + 2
        server.close_header = False
        before = server.connections
        probe(settings(server), True)
        assert server.connections == before + 2
        # A certificate change on an idle reconnect must still stop before HTTP/auth.
        rotating = start(cert)
        rotating.graph = rotating.swap_after_root = True
        probe(settings(rotating), False, 'connection_certificate_mismatch')
        assert rotating.paths == ['/redfish/v1/']
        assert rotating.requests == rotating.authorized == 1
        # Optional log failures/limits must never erase previously read hardware.
        limited = start(cert)
        log_root = '/redfish/v1/Systems/R420/LogServices'
        limited.graph = True
        file.write_text(json.dumps(settings(limited)))
        put = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'device-put', '--file', str(file)], input=SECRET + '\n', text=True, capture_output=True)
        assert put.returncode == 0, put.stderr
        for mode, outcome in [('invalid', 'invalid_response'), ('items', 'item_limit'), ('resources', 'resource_limit')]:
            limited.mode = mode
            limited.paths.clear()
            started = time.monotonic()
            poll = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'poll-once'], text=True, capture_output=True, timeout=105)
            assert poll.returncode == 0, (mode, poll.stderr)
            saved = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'snapshot'], text=True, capture_output=True, check=True)
            assert SECRET not in poll.stdout + poll.stderr + saved.stdout
            device = json.loads(saved.stdout)['devices'][0]
            snap = device['snapshot']
            assert device['last_poll'] is not None
            assert not snap['logs_complete']
            assert any(c['outcome'] == outcome and c['uri'].startswith(log_root) for c in snap['capabilities']), (mode, snap['capabilities'][-1])
            assert any(o['label'] == 'Inlet' and o['reading'] == 24 for o in snap['observations']), mode
            assert any(o['key'] == 'collector' and o['health'] == 'warning' for o in snap['observations']), mode
            assert limited.paths.index('/redfish/v1/Chassis/R420/Thermal') < limited.paths.index(log_root)
            assert len(snap['logs']) <= 4096
            if mode == 'deadline':
                assert 89 <= time.monotonic() - started < 100
            print('PASS: hardware retained with explicit', outcome, flush=True)
        # A mandatory identity failure stays fatal and records a safe URI/reason.
        file.write_text(json.dumps(settings(limited, replacement)))
        put = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'device-put', '--file', str(file)], input=SECRET + '\n', text=True, capture_output=True)
        assert put.returncode == 0
        rejected = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'poll-once'], text=True, capture_output=True)
        assert rejected.returncode != 0
        saved = subprocess.run([str(BINARY), '--state', str(root / 'limited-state'), 'snapshot'], text=True, capture_output=True, check=True)
        alarms = json.loads(saved.stdout)['devices'][0]['alarms']
        assert any(a['key'] == 'collector' and '/redfish/v1/' in a['label'] and 'Serverzertifikat' in a['label'] for a in alarms)
        assert SECRET not in saved.stdout + rejected.stderr
        # Authenticate once, use token-only GETs, then delete exactly our session.
        session = start(cert)
        session.graph = session.sessions = True
        result = probe(settings(session), True)
        assert result['checked_collections'] == 3
        assert session.session_posts == 1 and session.basic_requests == 1 and session.token_requests == 3
        assert session.session_deletes == ['/redfish/v1/Sessions/owned'] and not session.active_session
        # iLO-style URLs keep their exact optional final slash on both writes.
        for collection_slash in ['', '/']:
            for resource_slash in ['', '/']:
                ilo = start(cert)
                ilo.graph = ilo.sessions = True
                ilo.reject_reused_auth = True
                ilo.session_collection = '/redfish/v1/SessionService/Sessions' + collection_slash
                ilo.session_location = '/redfish/v1/SessionService/Sessions/owned' + resource_slash
                result = probe(settings(ilo), True)
                assert result['checked_collections'] == 3
                assert ilo.session_posts == 1 and ilo.token_requests == 3
                assert ilo.session_deletes == [ilo.session_location] and not ilo.active_session
                assert ilo.reused_auth_attempts == 0
        # Even another permitted session collection cannot own this login's session.
        ilo.session_location = '/redfish/v1/Sessions/owned/'
        ilo.session_deletes.clear()
        probe(settings(ilo), False, 'connection_response_invalid')
        assert not ilo.session_deletes
        # Lack of session support keeps the existing Basic-authentication path.
        session.session_status = 403
        session.session_deletes.clear()
        before = session.basic_requests
        probe(settings(session), True)
        assert session.basic_requests == before + 4 and not session.session_deletes
        # Authentication writes must not follow redirects to hardware resources.
        session.session_status = 307
        before = session.requests
        probe(settings(session), False, 'connection_http_error')
        assert session.requests == before + 1
        # An unsafe Location must never become a hardware DELETE request.
        session.session_status = 201
        session.session_location = '/redfish/v1/Chassis/owned'
        probe(settings(session), False, 'connection_response_invalid')
        assert not session.session_deletes
        # A cancelled probe still logs out the known session through a new verified stream.
        delayed = start(cert)
        delayed.graph = delayed.sessions = True
        delayed.delay_path = '/redfish/v1/Chassis'
        probe(settings(delayed), False, 'connection_timeout')
        assert delayed.session_deletes == ['/redfish/v1/Sessions/owned'] and not delayed.active_session
        # Full monitoring uses one password authentication and cleans up its token.
        full = start(cert)
        full.graph = full.sessions = True
        full.reject_reused_auth = True
        full.session_collection = '/redfish/v1/SessionService/Sessions/'
        full.session_location = '/redfish/v1/SessionService/Sessions/owned/'
        file.write_text(json.dumps(settings(full)))
        for command, secret in [('device-put', SECRET + '\n'), ('poll-once', None), ('snapshot', None)]:
            args = [str(BINARY), '--state', str(root / 'session-poll-state'), command]
            if command == 'device-put':args += ['--file',str(file)]
            result = subprocess.run(args,input=secret,text=True,capture_output=True,timeout=20)
            assert result.returncode==0, result.stderr
            assert SECRET not in result.stdout+result.stderr and TOKEN not in result.stdout+result.stderr
        snap = json.loads(result.stdout)['devices'][0]['snapshot']
        assert snap['logs_complete'] and all(c['outcome']=='available' for c in snap['capabilities'])
        assert full.basic_requests==1 and full.token_requests==6 and full.session_posts==1
        assert full.session_deletes==[full.session_location] and not full.active_session
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()

print('PASS: DHE-only TLS 1.2, exact leaf pinning, expiry/TLS 1.1 rejection, safe redirects, size limits, public root with rejected protected login, full graph/sensor polling over one TLS connection, verified reconnect and Standard-mode preservation')
