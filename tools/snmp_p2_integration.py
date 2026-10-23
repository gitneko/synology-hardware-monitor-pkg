#!/usr/bin/env python3
"""Exercise the actual product CLI against independent loopback Net-SNMP.

Random credentials stay in stdin/private temporary files; no NAS, BMC or
notification recipient is involved. This is protocol evidence, not vendor QA.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def private(path, text):
    path.write_text(text)
    path.chmod(0o600)


@contextmanager
def agent(root, community, users, listen_port=None, engine_id_text=None, extra_config=()):
    root.mkdir(mode=0o700)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = listen_port or sock.getsockname()[1]
    (root / 'persistent').mkdir(mode=0o700)
    env = dict(os.environ, MIBS='', SNMPCONFPATH=str(root), SNMP_PERSISTENT_DIR=str(root / 'persistent'))
    config = [f'agentAddress udp:127.0.0.1:{port}', f'persistentDir {root / "persistent"}',
              f'rocommunity {community} 127.0.0.1', 'sysName p2-synthetic-agent']
    config.extend(extra_config)
    if engine_id_text:
        config += [f'engineID {engine_id_text}']
    for username, algorithm, auth, privacy in users:
        config += [f'createUser {username} {algorithm} {auth} AES {privacy}', f'rouser {username} priv']
    private(root / 'snmpd.conf', '\n'.join(config) + '\n')
    private(root / 'snmp.conf', f'defVersion 1\ndefCommunity {community}\n')
    with (root / 'private.log').open('w') as log:
        process = subprocess.Popen(['snmpd', '-f', '-Lo', '-C', '-c', str(root / 'snmpd.conf'),
                                    '-p', str(root / 'snmpd.pid')], stdout=log, stderr=log, env=env)
        try:
            for _ in range(60):
                require(process.poll() is None, 'reference agent exited; private log excluded')
                ready = subprocess.run(['snmpget', '-On', '-t', '0.1', '-r', '0', f'udp:127.0.0.1:{port}',
                                        '1.3.6.1.2.1.1.5.0'], capture_output=True, env=env, timeout=2)
                if ready.returncode == 0:
                    break
                time.sleep(0.03)
            else:
                raise AssertionError('reference readiness timeout')
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def run(binary, state, command, config=None, credentials=None):
    args = [str(binary), '--state', str(state), command]
    if config:
        args += ['--file', str(config)]
    if command == 'device-put':
        args += ['--protocol-secrets']
    output = subprocess.run(args, input=json.dumps(credentials or {}) if command in ('device-put', 'device-test') else '',
                            text=True, capture_output=True, timeout=20)
    # Never include raw process errors in assertion messages.
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='hm-snmp-p2-') as temp:
        root = Path(temp)
        community = secrets.token_hex(16)
        users = [(f'p2_{i}', algorithm, secrets.token_hex(12), secrets.token_hex(12))
                 for i, algorithm in enumerate(('SHA', 'SHA-256'))]
        with agent(root / 'reference', community, users) as port:
            versions = [('v1', None), ('v2c', None)] + [('v3', user) for user in users]
            for number, (version, user) in enumerate(versions):
                security = {'version': version}
                credentials = {'kind': 'community', 'community': community}
                label = version
                if user:
                    username, algorithm, auth, privacy = user
                    security.update(username=username, auth='sha1' if algorithm == 'SHA' else 'sha256', privacy='aes128')
                    credentials = {'kind': 'usm', 'auth_password': auth, 'priv_password': privacy}
                    label += '-' + algorithm
                device = dict(id=f'p2-{number}', name='Synthetic SNMP', primary_protocol='snmp',
                              snmp_poll=dict(host='127.0.0.1', port=port, security=security,
                                             timeout_ms=300, retries=1, profile='generic'),
                              interval_seconds=60, repeat_seconds=None, alerts_enabled=True)
                path = root / f'config-{number}.json'
                private(path, json.dumps(device))
                payload = {'snmp': {'snmp_poll': {'action': 'replace', 'credentials': credentials}}}
                state = root / f'state-{number}'
                probe = run(binary, state, 'device-test', path, payload)
                require(probe.returncode == 0, f'{label}: actual product probe failed')
                data = json.loads(probe.stdout)
                require(data['protocol'] == 'snmp' and data['version'] == version, f'{label}: version mismatch')
                require(isinstance(data.get('elapsed_ms'), int) and 0 <= data['elapsed_ms'] < 20000,
                        f'{label}: bounded probe timing absent')
                require(data['sys_name'] == 'p2-synthetic-agent' and data['statistics']['requests'] > 0,
                        f'{label}: actual identity read missing')
                if version == 'v3':
                    require(data['engine_id'] and data['engine_boots'] is not None, f'{label}: authenticated engine absent')
                put = run(binary, state, 'device-put', path, payload)
                require(put.returncode == 0, f'{label}: actual product save failed')
                poll = run(binary, state, 'poll-once')
                require(poll.returncode == 0, f'{label}: actual product poll failed')
                with sqlite3.connect(state / 'monitor.db') as conn:
                    snapshot = json.loads(conn.execute('SELECT snapshot FROM devices').fetchone()[0])
                require(snapshot['snmp']['version'] == version, f'{label}: persisted provenance absent')
                dashboard = json.loads(run(binary, state, 'snapshot').stdout)
                require(dashboard['devices'][0]['overall_status'] == 'ok',
                        f'{label}: absent optional groups block generic availability assessment')
                require(any(o['key'] == 'snmp:availability' and o['health'] == 'ok' for o in snapshot['observations']),
                        f'{label}: explicit generic assessment scope absent')
                serialized = json.dumps(snapshot) + probe.stdout + poll.stdout + put.stdout
                forbidden = [community] + [value for u in users for value in u[2:]]
                require(not any(value in serialized for value in forbidden), f'{label}: credential disclosure')
                wrong = json.loads(json.dumps(payload))
                if version == 'v3':
                    wrong['snmp']['snmp_poll']['credentials']['auth_password'] = secrets.token_hex(12)
                else:
                    wrong['snmp']['snmp_poll']['credentials']['community'] = secrets.token_hex(16)
                failure = run(binary, state, 'device-test', path, wrong)
                require(failure.returncode != 0 and not failure.stdout.strip(), f'{label}: wrong credentials succeeded')
                require('snmp_' in failure.stderr, f'{label}: error was not sanitized')
                results.append({'case': label, 'probe': True, 'poll_once': True, 'wrong_credentials_rejected': True, 'elapsed_ms': data['elapsed_ms']})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'reference': 'Net-SNMP loopback', 'cases': results}, indent=2) + '\n')
    print(f'Actual product SNMP reference checks passed: {len(results)} configurations')


if __name__ == '__main__':
    main()
