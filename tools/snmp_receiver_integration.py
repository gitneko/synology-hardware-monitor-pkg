#!/usr/bin/env python3
"""Actual daemon trap checks against independent Net-SNMP, loopback only.

Uses private generated credentials/configs. Private SQLite fixture setup enables
receiver settings before daemon startup; it introduces no product auth bypass.
No real hardware or notification recipients are involved.
"""
import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time

from snmp_polling_integration import agent, private, require, run
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('snmp_library_reference', ROOT / 'tools/snmp-reference/integration.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def wait_for(test, label, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if test():
            return
        time.sleep(0.03)
    raise AssertionError(label)


def receipts(state):
    with sqlite3.connect(state / 'monitor.db') as db:
        return [(row[0], json.loads(row[1])) for row in db.execute('SELECT device,data FROM snmp_receipts ORDER BY id')]


def clock(root, port, sender, _attempts=0):
    path = root / secrets.token_hex(4)
    path.mkdir(mode=0o700)
    private(path / 'snmp.conf', '\n'.join([
        'defVersion 3', f'defSecurityName {sender["username"]}',
        f'defAuthType {"SHA" if sender["algorithm"] == "sha1" else "SHA-256"}',
        f'defAuthPassphrase {sender["auth_password"]}', 'defPrivType AES',
        f'defPrivPassphrase {sender["priv_password"]}', 'defSecurityLevel authPriv',
    ]) + '\n')
    output = subprocess.run(['snmpget', '-Oqv', '-t', '.5', '-r', '0', f'udp:127.0.0.1:{port}',
                             '1.3.6.1.6.3.10.2.1.2.0', '1.3.6.1.6.3.10.2.1.3.0'],
                            env=reference.environment(path), capture_output=True, text=True, timeout=5)
    require(output.returncode == 0, 'independent engine clock read failed (private output excluded)')
    observed = tuple(int(value.strip()) for value in output.stdout.splitlines())
    if observed[1] == 0:
        # Net-SNMP snmptrap -Z boots,0 substitutes the sender host uptime.
        # Wait for the real agent's first nonzero second, rather than advancing
        # the receiver with a falsely encoded time and weakening replay checks.
        require(_attempts < 2, "reference agent clock stayed at zero")
        time.sleep(1.05)
        return clock(root, port, sender, _attempts + 1)
    return observed


def community_packet(root, version, community, enterprise='1.3.6.1.4.1.674.10892.5.3.2.5'):
    path = root / secrets.token_hex(4)
    path.mkdir(mode=0o700)
    private(path / 'snmp.conf', f'defVersion {version}\ndefCommunity {community}\n')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as capture:
        capture.bind(('127.0.0.1', 0))
        capture.settimeout(3)
        command = ['snmptrap', '-On', '-v', version, f'udp:127.0.0.1:{capture.getsockname()[1]}']
        command += [enterprise, '192.0.2.99', '6', '42', '123'] if version == '1' else ['123', reference.TRAP]
        output = subprocess.run(command, env=reference.environment(path), capture_output=True, timeout=5)
        require(output.returncode == 0, 'independent community trap encoding failed')
        return capture.recvfrom(65535)[0]


def denied_api(path):
    """Exercise actual API scheduling; Linux must still deny DSM auth."""
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(path))
        body = b'{"auth":{"environment":{}}}'
        client.sendall(struct.pack('>I', len(body)) + body)
        def read(n):
            data = b''
            while len(data) < n:
                part = client.recv(n - len(data))
                require(bool(part), 'API closed under trap load')
                data += part
            return data
        size = struct.unpack('>I', read(4))[0]
        require(size <= 65536 and json.loads(read(size))['ok'] is False, 'API auth boundary changed under load')


def resources(pid):
    stat = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    cpu = (int(stat[11]) + int(stat[12])) / os.sysconf('SC_CLK_TCK')
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    rss = next(int(line.split()[1]) for line in status if line.startswith('VmRSS:'))
    return cpu, rss


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--load-seconds', type=int, default=0)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='hm-snmp-receiver-') as temp, ExitStack() as stack:
        root = Path(temp)
        state = root / 'state'
        api_socket = root / 'api.sock'
        community = secrets.token_hex(16)
        senders = []
        agents = []
        for i, algorithm in enumerate(('sha1', 'sha256', 'sha256')):
            user = dict(username='p3-rf' if i == 2 else 'p3-shared', algorithm=algorithm, auth_password=secrets.token_hex(12), priv_password=secrets.token_hex(12))
            owner = stack.enter_context(ExitStack())
            agents.append(owner)
            port = owner.enter_context(agent(root / f'agent-{i}', community, [(user['username'], 'SHA' if algorithm == 'sha1' else 'SHA-256', user['auth_password'], user['priv_password'])], engine_id_text=f'p3-engine-{i}'))
            security = dict(version='v3', username=user['username'], auth=algorithm, privacy='aes128')
            device = dict(id=f'p3-{i}', name='Synthetic SNMP', primary_protocol='snmp',
                          snmp_poll=dict(host='127.0.0.1', port=port, security=security, timeout_ms=300, retries=0, profile='generic'),
                          interval_seconds=60, repeat_seconds=None, alerts_enabled=False)
            path = root / f'device-{i}.json'
            private(path, json.dumps(device))
            credentials = dict(kind='usm', auth_password=user['auth_password'], priv_password=user['priv_password'])
            payload = {'snmp': {'snmp_poll': {'action': 'replace', 'credentials': credentials}, 'snmp_traps': {'action': 'replace', 'credentials': credentials}}}
            probe = run(binary, state, 'device-test', path, {'snmp': {'snmp_poll': payload['snmp']['snmp_poll']}})
            require(probe.returncode == 0, 'actual identity read failed')
            user['engine_id'] = json.loads(probe.stdout)['engine_id']
            device['snmp_traps'] = dict(enabled=True, allowed_sources=['127.0.0.1'], security=security, engine_ids=[user['engine_id']], context_engine_ids=[user['engine_id']])
            if i == 2:
                device.update(primary_protocol='redfish', endpoint='https://127.0.0.1:9/', username='synthetic-reader')
                payload['redfish_password'] = secrets.token_hex(16)
                # A Redfish primary needs only trap credentials for its bounded
                # SNMP identity/time probe, never a second SNMP hardware poll.
                payload['snmp'].pop('snmp_poll')
            private(path, json.dumps(device))
            require(run(binary, state, 'device-put', path, payload).returncode == 0, 'actual device save failed')
            senders.append((device, path, payload, user, port))
        for version in ('v1', 'v2c'):
            device = dict(id=f'p3-{version}', name='Synthetic community trap', primary_protocol='snmp',
                          snmp_poll=dict(host='127.0.0.1', port=senders[0][4], security=dict(version=version), timeout_ms=300, retries=0),
                          snmp_traps=dict(enabled=True, allowed_sources=['127.0.0.1'], security=dict(version=version)),
                          interval_seconds=60, repeat_seconds=None, alerts_enabled=False)
            path = root / f'device-{version}.json'
            private(path, json.dumps(device))
            creds = {'action': 'replace', 'credentials': {'kind': 'community', 'community': community}}
            require(run(binary, state, 'device-put', path, {'snmp': {'snmp_poll': creds, 'snmp_traps': creds}}).returncode == 0, 'community fixture save failed')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(('127.0.0.1', 0))
            listener_port = reserve.getsockname()[1]
        with sqlite3.connect(state / 'monitor.db') as db:
            db.execute('UPDATE snmp_receiver_settings SET config=?,revision=1 WHERE id=1', (json.dumps(dict(enabled=True, listen_port=listener_port, listen_addresses=['127.0.0.1'])),))
            db.execute('UPDATE snmp_runtime SET epoch=epoch+1 WHERE id=1')
        log = stack.enter_context((root / 'private-daemon.log').open('w'))

        def start():
            process = subprocess.Popen([str(binary), '--state', str(state), '--socket', str(api_socket), 'serve'], stdout=log, stderr=log)
            wait_for(lambda: process.poll() is not None or api_socket.exists(), 'daemon did not start')
            require(process.poll() is None, 'daemon exited; private log excluded')
            return process

        process = start()
        try:
            destination = ('127.0.0.1', listener_port)
            origin = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            origin.bind(('127.0.0.1', 0))
            for device, path, payload, sender, port in senders:
                boots, now = clock(root, port, sender)
                packet = reference.trap_packet(root, sender, boots=boots, engine_time=now)
                def send_until_received():
                    origin.sendto(packet, destination)
                    return any(name == device['id'] and receipt['verified'] for name, receipt in receipts(state))
                wait_for(send_until_received, 'v3 did not establish authenticated receive baseline', timeout=15)
                found = [r for name, r in receipts(state) if name == device['id']]
                require(found[0]['engine_id'] == sender['engine_id'], 'engine routing mismatch')
                results.append(f'actual-v3-{sender["algorithm"]}-{"redfish-primary" if device["primary_protocol"] == "redfish" else "snmp-primary"}-bootstrap-and-receipt')
            with sqlite3.connect(state / 'monitor.db') as db:
                rf_raw = db.execute("SELECT snapshot FROM devices WHERE id='p3-2'").fetchone()[0]
            require(rf_raw is None or json.loads(rf_raw).get('snmp') is None, 'Redfish enrollment performed an SNMP hardware poll')
            for version in ('1', '2c'):
                origin.sendto(community_packet(root, version, community), destination)
                name = 'p3-v1' if version == '1' else 'p3-v2c'
                wait_for(lambda: any(device == name for device, _ in receipts(state)), 'community trap missing')
            v1 = next(r for name, r in receipts(state) if name == 'p3-v1')
            require(v1['trap_oid'] == '1.3.6.1.4.1.674.10892.5.3.2.5.0.42' and not v1['verified'] and v1['source'] == '127.0.0.1', 'v1 canonical source/OID mismatch')
            results.append('actual-v1-v2c-and-exact-v1-enterprise-oid')
            device, path, payload, sender, port = senders[0]
            boots, now = clock(root, port, sender)
            valid = reference.trap_packet(root, sender, boots=boots, engine_time=now)
            before = len(receipts(state))
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other_port:
                other_port.bind(('127.0.0.1', 0))
                other_port.sendto(valid, destination)
            time.sleep(.1)
            require(len(receipts(state)) == before, 'duplicate/new-source-port was not coalesced')
            variants = [valid + b'trailing', valid[:-3], b'malformed', b'X' * 16385]
            for changes, level, context in [({'auth_password': secrets.token_hex(12)}, 'authPriv', ''), ({}, 'authNoPriv', ''), ({}, 'noAuthNoPriv', '')]:
                variants.append(reference.trap_packet(root, dict(sender, **changes), boots=boots, engine_time=now, level=level, context=context))
            variants.append(reference.trap_packet(root, sender, boots=boots, engine_time=now, context_engine='8000000002'))
            variants.append(reference.trap_packet(root, sender, boots=boots, engine_time=now, extra_varbinds=127))
            for packet in variants:
                origin.sendto(packet, destination)
                time.sleep(.06)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as wrong_source:
                wrong_source.bind(('127.0.0.2', 0))
                wrong_source.sendto(valid, destination)
            time.sleep(.2)
            require(len(receipts(state)) == before, 'invalid/unapproved notification created receipt')
            results.append('wrong-source-secret-context-security-size-and-malformed-rejected')
            local_state = json.loads((state / 'snmp-engine.json').read_text())
            process.terminate()
            process.wait(timeout=10)
            process = start()
            restarted = json.loads((state / 'snmp-engine.json').read_text())
            require(restarted['engine_id'] == local_state['engine_id'] and restarted['boots'] == local_state['boots'] + 1, 'local engine restart lifecycle failed')
            boots, now = clock(root, port, sender)
            fresh = reference.trap_packet(root, sender, boots=boots, engine_time=now)
            # Give the occurrence a distinct uptime using the reference tool's
            # fixed 123 prefix only after the process-local duplicate cache reset.
            wait_for(lambda: (origin.sendto(fresh, destination), len(receipts(state)) > before)[1], 'receiver restart did not reverify via saved target', timeout=15)
            results.append('persistent-local-boots-and-post-restart-revalidation')
            # An authenticated packet advertising a different engine is never
            # self-enrolling, even from the saved IP and with the correct key.
            agents[0].close()
            with agent(root / 'replacement', community, [(sender['username'], 'SHA', sender['auth_password'], sender['priv_password'])], listen_port=port, engine_id_text='p3-replacement') as replacement_port:
                replacement_device = json.loads(json.dumps(device))
                replacement_device['snmp_poll']['port'] = replacement_port
                replacement_path = root / 'replacement.json'
                private(replacement_path, json.dumps(replacement_device))
                probe_payload = {'snmp': {'snmp_poll': payload['snmp']['snmp_poll']}}
                observed = run(binary, state, 'device-test', replacement_path, probe_payload)
                require(observed.returncode == 0, 'replacement independent identity probe failed')
                replacement_sender = dict(sender, engine_id=json.loads(observed.stdout)['engine_id'])
                replacement_boots, replacement_time = clock(root, replacement_port, replacement_sender)
                replacement_packet = reference.trap_packet(root, replacement_sender, boots=replacement_boots, engine_time=replacement_time)
                before_replacement = len(receipts(state))
                origin.sendto(replacement_packet, destination)
                time.sleep(.2)
                require(len(receipts(state)) == before_replacement, 'unapproved replacement engine accepted')
                # Save the new target while retaining the old approved ID. A
                # fresh probe sees the mismatch, but cannot rewrite approval.
                require(run(binary, state, 'device-put', replacement_path, payload).returncode == 0, 'replacement saved-target update failed')
                for _ in range(30):
                    origin.sendto(replacement_packet, destination)
                    time.sleep(.1)
                require(len(receipts(state)) == before_replacement, 'saved target silently approved a changed engine')
                replacement_device['snmp_traps']['engine_ids'] = [replacement_sender['engine_id']]
                replacement_device['snmp_traps']['context_engine_ids'] = [replacement_sender['engine_id']]
                private(replacement_path, json.dumps(replacement_device))
                require(run(binary, state, 'device-put', replacement_path, payload).returncode == 0, 'explicit engine review failed')
                wait_for(lambda: (origin.sendto(replacement_packet, destination), len(receipts(state)) > before_replacement)[1], 'approved replacement failed fresh verification', timeout=15)
                results.append('changed-engine-rejected-until-explicit-review-and-fresh-saved-target-probe')
            # Exercise the new option through the packaged CLI/daemon too;
            # static release binaries deliberately cannot run local-dev HTTP.
            compat_device,compat_path,compat_payload,compat_sender,compat_port=senders[1]
            compat_device['snmp_traps']['timeliness_poll_only']=True
            compat_device['interval_seconds']=86400
            private(compat_path,json.dumps(compat_device))
            require(run(binary,state,'device-put',compat_path,compat_payload).returncode==0,'compatibility fixture save failed')
            baseline=reference.trap_packet(root,compat_sender,boots=113,engine_time=30000)
            receipt_count=len(receipts(state))
            wait_for(lambda:(origin.sendto(baseline,destination),len(receipts(state))>receipt_count)[1],'strict baseline in compatibility mode failed',timeout=15)
            # Let the baseline receipt's requested poll and minimum-gap timer
            # settle; the next ordinary poll is a day away.
            time.sleep(11)
            def poll_stamp():
                with sqlite3.connect(state/'monitor.db') as db:
                    return db.execute("SELECT COALESCE(last_poll,0) FROM devices WHERE id='p3-1'").fetchone()[0]
            prior_poll=poll_stamp()
            receipt_count=len(receipts(state))
            reset=reference.trap_packet(root,compat_sender,boots=1,engine_time=388)
            origin.sendto(reset,destination)
            wait_for(lambda:poll_stamp()>prior_poll,'static compatibility hint did not trigger primary poll',timeout=15)
            require(len(receipts(state))==receipt_count,'static compatibility hint entered receipt/alarm ingestion')
            results.append('opt-in-backwards-boots-hint-starts-primary-poll-without-receipt')
            if args.load_seconds:
                # The clock-hint case deliberately postponed ordinary polls
                # for a day. Restore a regular cadence before requiring an
                # automatic poll to complete during the 60-second load case.
                compat_device['interval_seconds'] = 30
                compat_device['snmp_traps']['timeliness_poll_only'] = False
                private(compat_path, json.dumps(compat_device))
                require(run(binary, state, 'device-put', compat_path, compat_payload).returncode == 0,
                        'load fixture polling cadence restore failed')
                end = time.monotonic() + args.load_seconds
                sent = 0
                latencies = []
                api_latencies = []
                cpu_before, peak_rss = resources(process.pid)
                with sqlite3.connect(state / 'monitor.db') as db:
                    poll_before = db.execute("SELECT last_poll FROM devices WHERE id='p3-1'").fetchone()[0]
                stopped = threading.Event()
                def flood():
                    nonlocal sent
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as flood_socket, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as unknown:
                        unknown.bind(('127.0.0.2', 0))
                        while not stopped.wait(.01):
                            for _ in range(10):
                                flood_socket.sendto(variants[4], destination)  # plausible USM envelope, invalid HMAC
                                unknown.sendto(b'unknown-source', destination)
                                sent += 2
                flood_thread = threading.Thread(target=flood, daemon=True)
                flood_thread.start()
                while time.monotonic() < end:
                    at = time.monotonic()
                    snapshot = run(binary, state, 'snapshot')
                    require(snapshot.returncode == 0 and process.poll() is None, 'monitoring unavailable under load')
                    latencies.append(time.monotonic() - at)
                    at = time.monotonic()
                    denied_api(api_socket)
                    api_latencies.append(time.monotonic() - at)
                    peak_rss = max(peak_rss, resources(process.pid)[1])
                    time.sleep(.1)
                stopped.set()
                flood_thread.join(timeout=2)
                for _ in range(1000):
                    origin.sendto(b'burst', destination)
                require(max(latencies) < 3, 'snapshot responsiveness exceeded load limit')
                cpu_after, _ = resources(process.pid)
                with sqlite3.connect(state / 'monitor.db') as db:
                    poll_after = db.execute("SELECT last_poll FROM devices WHERE id='p3-1'").fetchone()[0]
                if args.load_seconds >= 60:
                    require(poll_after is not None and (poll_before is None or poll_after > poll_before), 'normal poll did not advance during trap load')
                results.append(dict(case='bounded-approved-and-unknown-source-load', seconds=args.load_seconds, packets=sent + 1000, max_snapshot_seconds=max(latencies), max_denied_api_seconds=max(api_latencies), daemon_cpu_seconds=cpu_after-cpu_before, peak_rss_kib=peak_rss, normal_poll_advanced=poll_after is not None and (poll_before is None or poll_after > poll_before)))
            require(process.poll() is None, 'daemon exited during trap checks')
            with sqlite3.connect(state / 'monitor.db') as db:
                snapshots = list(db.execute('SELECT snapshot FROM devices WHERE snapshot IS NOT NULL'))
            text = json.dumps(snapshots + receipts(state))
            require(community not in text and all(s['auth_password'] not in text and s['priv_password'] not in text for _, _, _, s, _ in senders), 'credential exposure in persisted evidence')
        finally:
            process.terminate()
            process.wait(timeout=10)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'reference': 'Net-SNMP loopback / actual product daemon', 'cases': results}, indent=2) + '\n')
    print(f'Actual daemon SNMP trap checks passed: {len(results)} cases')


if __name__ == '__main__':
    main()
