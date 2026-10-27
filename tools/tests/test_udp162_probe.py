#!/usr/bin/env python3
"""Exercise the actual SPK payload, with only the local test endpoint substituted."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import time


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if os.geteuid() == 0:
        raise SystemExit('Run as a non-root user: the diagnostic rejects root.')
    spk = Path(sys.argv[1])
    with tempfile.TemporaryDirectory() as temporary:
        temp = Path(temporary)
        target, var = temp / 'target', temp / 'var'
        target.mkdir()
        var.mkdir()
        with tarfile.open(spk) as archive:
            privilege = json.load(archive.extractfile('conf/privilege'))
            check(privilege in ({'defaults': {'run-as': 'package'}}, {'defaults': {'run-as': 'package'}, 'tool': [{
                'relpath': 'bin/udp162-cap', 'user': 'package', 'group': 'package',
                'permission': '0700', 'capabilities': 'cap_net_bind_service'}]}), 'privilege contract')
            lifecycle = archive.extractfile('scripts/start-stop-status').read().decode()
            with tarfile.open(fileobj=io.BytesIO(archive.extractfile('package.tgz').read()), mode='r:gz') as payload:
                check(payload.extractfile('bin/udp162-cap').read() == payload.extractfile('bin/udp162-baseline').read(), 'identical executables')
                payload.extractall(target, filter='data')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserver:
            reserver.bind(('127.0.0.1', 0))
            port = reserver.getsockname()[1]
        address = f'127.0.0.1:{port}'
        script = temp / 'start-stop-status'
        script.write_text(lifecycle.replace('0.0.0.0:162', address))
        env = {**os.environ, 'SYNOPKG_PKGDEST': str(target), 'SYNOPKG_PKGVAR': str(var)}

        def action(name):
            return subprocess.run(['sh', str(script), name], env=env, capture_output=True, text=True, timeout=15)

        def succeeds(name):
            result = action(name)
            check(result.returncode == 0, f'{name}: {result.stderr}')

        try:
            check(action('status').returncode != 0, 'initial status')
            succeeds('start')
            succeeds('status')
            first_pid = (var / 'listener.pid').read_text()
            succeeds('start')
            check(first_pid == (var / 'listener.pid').read_text(), 'idempotent start')
            check((var / 'baseline.state').read_text() == 'BIND_OK\n', 'unprivileged high-port baseline')
            check('CAP_NET_BIND_SERVICE_effective=Some(false)' in (var / 'probe.log').read_text(), 'local test must have no effective bind capability')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(b'udp162-probe', ('127.0.0.1', port))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if 'received=1 last_bytes=12' in (var / 'listener.state').read_text():
                    break
                time.sleep(0.02)
            check('received=1 last_bytes=12' in (var / 'listener.state').read_text(), 'packet received')
            # A second process must not share or take over the listener port.
            result = subprocess.run([str(target / 'bin/udp162-baseline'), 'once', address, str(temp / 'conflict.state')], capture_output=True, text=True, timeout=3)
            check(result.returncode == 1 and 'AddrInUse' in result.stdout, 'native bind conflict diagnosis')
            succeeds('stop')
            check(action('status').returncode != 0, 'stopped status')
            check(not (var / 'listener.state').exists(), 'remove stale listening state')
            succeeds('stop')
            # Occupied port must fail start, retain diagnostic, and clean up PID.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocker:
                blocker.bind(('127.0.0.1', port))
                check(action('start').returncode != 0, 'occupied port must fail package start')
                check('AddrInUse' in (var / 'probe.log').read_text(), 'persistent conflict log')
                check(action('status').returncode != 0, 'failed start status')
                check(not (var / 'listener.pid').exists(), 'failed start PID cleanup')
            succeeds('start')
            succeeds('stop')
        finally:
            action('stop')
    print('PASS: SPK config and identical payload, baseline, UDP receive, bind conflict, start/status/stop, repeated start/stop, failed-start cleanup and restart. DSM capability assignment remains untested.')


if __name__ == '__main__':
    main()
