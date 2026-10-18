#!/usr/bin/env python3
"""Screenshot fixture, loopback only. No DSM identity, real devices or outbound delivery.

Run after npm run build --prefix web; open http://127.0.0.1:18773 and select English.
This server is deliberately separate from the production binary and denies all writes.
"""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]/'web/dist'
NOW = int(time.time())
DEVICE = {'id': 'example-server', 'name': 'Example server', 'endpoint': 'https://bmc.example/',
          'username': 'monitor', 'enabled': True, 'alerts_enabled': True, 'custom_trust': False,
          'interval_seconds': 60, 'repeat_seconds': 3600}
OBSERVATIONS = [
    {'key': 'ps1', 'label': 'Power Supply 1', 'health': 'critical', 'reading': 0, 'unit': 'W'},
    {'key': 'ps2', 'label': 'Power Supply 2', 'health': 'ok', 'reading': 120, 'unit': 'W'},
    {'key': 'temp', 'label': 'Inlet temperature', 'health': 'ok', 'reading': 24, 'unit': '°C'},
    {'key': 'fan', 'label': 'System Fan 1', 'health': 'ok', 'reading': 4800, 'unit': 'RPM'},
]
SELECTION = {key: True for key in ['critical', 'warning', 'recovery', 'repeat', 'hardware_log']}
DATA = {'version': '0.8.0', 'generated': NOW, 'user': {'name': 'demo-admin', 'role': 'administrator'},
        'csrf': 'synthetic-ui-proof', 'notifications': {'mail_enabled': True, 'desktop_enabled': True,
        'desktop_self_test_available': True}, 'audit': [],
        'devices': [{'device': DEVICE, 'revision': 1, 'last_poll': NOW, 'stale': False,
                     'snapshot': {'observations': OBSERVATIONS, 'capabilities': [{'uri': '/redfish/v1/', 'outcome': 'available'}]},
                     'alarms': [{'key': 'ps1', 'label': 'Power Supply 1', 'health': 'critical',
                                 'current_health': 'critical', 'observed': NOW-600, 'covered_by': []}]}],
        'events': [{'id': 2, 'device': DEVICE['id'], 'device_name': DEVICE['name'], 'key': 'ps1',
                    'kind': 'repeat', 'health': 'critical', 'created': NOW, 'message': 'Example server: Hardware health still critical: Power Supply 1',
                    'queued': True, 'delivered': NOW, 'cancelled': False, 'transport': 'smtp', 'total_recipients': 1, 'submitted_recipients': 1},
                   {'id': 1, 'device': DEVICE['id'], 'device_name': DEVICE['name'], 'key': 'ps1',
                    'kind': 'alarm', 'health': 'critical', 'created': NOW-600, 'message': 'Example server: Hardware health critical: Power Supply 1',
                    'queued': True, 'delivered': NOW-600, 'cancelled': False, 'transport': 'smtp', 'total_recipients': 1, 'submitted_recipients': 1}],
        'notification_settings': {'revision': 1, 'settings': {'language': 'en', 'desktop_enabled': True,
                                  'desktop_recipient': 'demo-admin', 'selection': SELECTION}},
        'mail': {'revision': 1, 'has_password': False, 'settings': {'language': 'en', 'enabled': True,
                 'host': 'smtp.example.invalid', 'port': 587, 'security': 'starttls', 'username': '',
                 'from_address': 'monitor@example.invalid', 'from_name': 'Hardware Monitor', 'recipients': ['ops@example.invalid'],
                 'selection': SELECTION, 'ca_pem': None, 'timezone': 'Europe/Zurich', 'date_format': '%Y-%m-%d %H:%M:%S',
                 'subject_template': '[Hardware Monitor] {{health}} – {{device}}',
                 'body_template': '{{message}}\n\nDevice: {{device}}\nTime: {{time_local}}\n'}}}


class Preview(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path in ['/api.cgi', '/webman/login.cgi']:
            result = {'ok': True, 'data': DATA} if self.path == '/api.cgi' else {'success': True, 'SynoToken': 'synthetic-token'}
            payload = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(payload)
        else:
            super().do_GET()

    def do_POST(self):
        self.send_error(405, 'Read-only screenshot fixture')


if __name__ == '__main__':
    assert (ROOT/'index.html').exists(), 'Build the UI first'
    print('Synthetic read-only preview: http://127.0.0.1:18773', flush=True)
    ThreadingHTTPServer(('127.0.0.1', 18773), Preview).serve_forever()
