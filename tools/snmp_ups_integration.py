#!/usr/bin/env python3
"""Actual product UPS profiles against independent Net-SNMP synthetic data.

No manufacturer firmware or real UPS is contacted; no power control or self-test
is initiated. Exercises typed MIB values, sparse phase/alarm rows and persistence.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import sqlite3
import sys
import tempfile
from snmp_p2_integration import agent, private, require, run

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ('ups_generic', 'apc_ups', 'eaton_ups')


def fixture(profile, mode='healthy', minimal=False):
    data = {}

    def put(root, kind, value):
        data[root] = [kind, value]

    if profile == 'ups_generic':
        base = '1.3.6.1.2.1.33.1'
        for suffix, value in [('2.1', 3 if mode == 'fault' else 2), ('4.1', 5 if mode == 'fault' else 3)]:
            put(f'{base}.{suffix}.0', 'integer', value)
        put(f'{base}.6.1.0', 'gauge', 1 if mode in ('fault', 'partial', 'mismatch', 'unknown_alarm') else 0)
        if mode in ('fault', 'unknown_alarm'):
            put(f'{base}.6.2.1.2.17', 'objectid', f'{base}.6.3.8' if mode == 'fault' else '1.3.6.1.4.1.999.42')
        if not minimal:
            put(f'{base}.2.3.0', 'integer', 12)
            put(f'{base}.2.4.0', 'integer', 75)
            put(f'{base}.2.5.0', 'integer', 485)
            put(f'{base}.2.6.0', 'integer', -22)
            put(f'{base}.7.3.0', 'integer', 6)
            for index in (1, 3):
                for column, value in [(2, 230), (3, 125), (4, 1000), (5, 25)]:
                    put(f'{base}.4.4.1.{column}.{index}', 'integer', value)
        if mode == 'partial':
            del data[f'{base}.2.1.0']
    elif profile == 'eaton_ups':
        base = '1.3.6.1.4.1.534.1'
        put(f'{base}.4.5.0', 'integer', 5 if mode == 'fault' else 3)
        put(f'{base}.7.1.0', 'gauge', 1 if mode in ('fault', 'partial', 'mismatch', 'unknown_alarm') else 0)
        if mode in ('fault', 'unknown_alarm'):
            put(f'{base}.7.2.1.2.29', 'objectid', f'{base}.7.7' if mode == 'fault' else '1.3.6.1.4.1.999.42')
        if not minimal:
            put(f'{base}.2.5.0', 'integer', 6 if mode == 'fault' else 4)
            put(f'{base}.2.1.0', 'integer', 720)
            put(f'{base}.2.2.0', 'integer', 48)
            put(f'{base}.2.3.0', 'integer', -2)
            put(f'{base}.2.4.0', 'integer', 75)
            put(f'{base}.8.2.0', 'integer', 2)
            for index in (1, 3):
                for column, value in [(2, 230), (3, 12), (4, 1000)]:
                    put(f'{base}.4.4.1.{column}.{index}', 'integer', value)
        if mode == 'partial':
            del data[f'{base}.4.5.0']
            data.pop(f'{base}.2.5.0', None)
    else:
        base = '1.3.6.1.4.1.318.1.1.1'
        put(f'{base}.2.1.1.0', 'integer', 3 if mode == 'fault' else 2)
        put(f'{base}.4.1.1.0', 'integer', 3 if mode == 'fault' else 2)
        if not minimal:
            put(f'{base}.2.2.1.0', 'gauge', 75)
            put(f'{base}.2.2.2.0', 'gauge', 255 if mode == 'sentinel' else 35)
            put(f'{base}.2.2.3.0', 'timeticks', 4294967295 if mode == 'sentinel' else 72000)
            put(f'{base}.2.2.4.0', 'integer', 2 if mode == 'fault' else 1)
            put(f'{base}.7.2.3.0', 'integer', 1)
            flags = ['0'] * 64
            flags[3] = flags[5] = '1'
            if mode == 'fault':
                flags[8] = '1'
            put(f'{base}.11.1.1.0', 'string', 'UNKNOWN' if mode == 'partial' else ''.join(flags))
        if mode == 'partial':
            del data[f'{base}.2.1.1.0']
    return data


def poll(binary, state):
    result = run(binary, state, 'poll-once')
    require(result.returncode == 0, 'Actual UPS poll failed; raw errors excluded')
    with sqlite3.connect(state/'monitor.db') as connection:
        return json.loads(connection.execute('SELECT snapshot FROM devices').fetchone()[0])


def observation(snapshot, suffix):
    return next(o for o in snapshot['observations'] if o['key'].endswith(':' + suffix))


def alarms(state, prefix):
    with sqlite3.connect(state/'monitor.db') as connection:
        return dict(connection.execute('SELECT key,health FROM alarm_state WHERE key LIKE ?', (prefix + '%',)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix='hm-ups-') as temp:
        root = Path(temp)
        community = secrets.token_hex(16)
        users = [(f'ups_{i}', alg, secrets.token_hex(12), secrets.token_hex(12)) for i, alg in enumerate(('SHA', 'SHA-256'))]
        fixture_path = root/'fixture.json'
        private(fixture_path, '{}')
        command = shlex.join([sys.executable, str(ROOT/'tools/snmp_synology_fixture.py'), str(fixture_path)])
        extra = [f'pass_persist .{base} {command}' for base in ('1.3.6.1.2.1.33', '1.3.6.1.4.1.318', '1.3.6.1.4.1.534')]
        with agent(root/'reference', community, users, extra_config=extra) as port:
            for profile in PROFILES:
                for number, (version, user) in enumerate([('v1', None), ('v2c', None)] + [('v3', u) for u in users]):
                    security = {'version': version}
                    credentials = {'kind': 'community', 'community': community}
                    label = version
                    if user:
                        username, algorithm, auth, privacy = user
                        security.update(username=username, auth='sha1' if algorithm == 'SHA' else 'sha256', privacy='aes128')
                        credentials = {'kind': 'usm', 'auth_password': auth, 'priv_password': privacy}
                        label += '-' + algorithm
                    private(fixture_path, json.dumps(fixture(profile)))
                    config = root/f'{profile}-{number}.json'
                    private(config, json.dumps(dict(id=f'{profile}-{number}', name='Synthetic UPS', primary_protocol='snmp',
                            snmp_poll=dict(host='127.0.0.1', port=port, security=security, profile=profile, timeout_ms=500, retries=1),
                            interval_seconds=60, repeat_seconds=None, alerts_enabled=True)))
                    state = root/f'state-{profile}-{number}'
                    payload = {'snmp': {'snmp_poll': {'action': 'replace', 'credentials': credentials}}}
                    probe = run(args.binary.resolve(), state, 'device-test', config, payload)
                    require(probe.returncode == 0, f'{profile}/{label}: probe failed')
                    require(json.loads(probe.stdout)['complete'], f'{profile}/{label}: healthy coverage incomplete')
                    require(run(args.binary.resolve(), state, 'device-put', config, payload).returncode == 0, 'UPS save failed')
                    healthy = poll(args.binary.resolve(), state)
                    summary = observation(healthy, 'alarms')
                    require(summary['health'] == 'ok', 'Empty/normal alarm state not assessable')
                    require(observation(healthy, 'runtime')['reading'] == (12 if profile == 'ups_generic' else 720), 'UPS runtime scaling failed')
                    if profile != 'apc_ups':
                        require(len([o for o in healthy['observations'] if ':ups_output:' in o['key']]) == (8 if profile == 'ups_generic' else 6), 'Sparse UPS phases lost')
                    require(all(json.loads(h) == 'ok' for h in alarms(state, 'snmp:ups:').values()), 'Healthy UPS generated fault')
                    private(fixture_path, json.dumps(fixture(profile, 'fault')))
                    faulty = poll(args.binary.resolve(), state)
                    require(observation(faulty, 'alarms')['health'] == 'critical', 'UPS overload fault missing')
                    private(fixture_path, json.dumps(fixture(profile, 'partial')))
                    partial = poll(args.binary.resolve(), state)
                    require(observation(partial, 'alarms')['health'] == 'unknown', 'Missing alarm evidence fabricated recovery')
                    require(json.loads(alarms(state, 'snmp:ups:')[summary['key']]) == 'critical', 'Partial UPS poll cleared retained critical fault')
                    private(fixture_path, json.dumps(fixture(profile)))
                    recovered = poll(args.binary.resolve(), state)
                    require(observation(recovered, 'alarms')['health'] == 'ok', 'UPS recovery missing')
                    with sqlite3.connect(state/'monitor.db') as connection:
                        count = connection.execute("SELECT COUNT(*) FROM events WHERE key=? AND kind='recovery'", (summary['key'],)).fetchone()[0]
                        require(count == 1, 'UPS alarm recovery not persisted exactly once')
                    private(fixture_path, json.dumps(fixture(profile, minimal=True)))
                    minimal = poll(args.binary.resolve(), state)
                    if profile != 'apc_ups':
                        require(observation(minimal, 'alarms')['health'] == 'ok', 'Minimal UPS with proven empty alarm table not assessable')
                    require(not any(c['outcome'] != 'available' for c in minimal['capabilities'] if not c.get('optional')), 'Absent optional UPS phase tables blocked assessment')
                    if profile == 'apc_ups':
                        private(fixture_path, json.dumps(fixture(profile, 'sentinel')))
                        sentinel = poll(args.binary.resolve(), state)
                        require(observation(sentinel, 'runtime')['reading'] is None and observation(sentinel, 'temperature')['reading'] is None, 'APC unsupported sentinel displayed as reading')
                    else:
                        private(fixture_path, json.dumps(fixture(profile, 'unknown_alarm')))
                        unknown = poll(args.binary.resolve(), state)
                        require(observation(unknown, 'alarms')['health'] == 'warning', 'Unknown active UPS alarm hidden')
                    rendered = json.dumps([healthy, faulty, partial, recovered, minimal]) + probe.stdout
                    require(not any(secret in rendered for secret in [community] + [p for u in users for p in u[2:]]), 'UPS credential disclosure')
                    results.append(dict(case=f'{profile}/{label}', healthy=True, actual_polling=True, fault=True,
                                        partial_retains=True, recovery_once=True, optional_absence=True, sparse_phases=profile != 'apc_ups'))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'reference': 'Independent Net-SNMP with synthetic vendor/RFC numeric data; no real UPS or firmware acceptance', 'cases': results}, indent=2)+'\n')
    print(f'Actual UPS profile checks passed: {len(results)} configurations')


if __name__ == '__main__':
    main()
