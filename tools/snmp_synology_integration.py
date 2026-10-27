#!/usr/bin/env python3
"""Exercise the DSM profile through actual CLI/probe/store/alarm paths.

Official numeric OIDs, synthetic states and independent Net-SNMP; this is not
Synology firmware/model acceptance. Includes optional-field absence and v1.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import sqlite3
import sys
import tempfile
from snmp_polling_integration import agent, private, require, run

ROOT = Path(__file__).resolve().parents[1]
SYSTEM = '1.3.6.1.4.1.6574.1'
DISKS = '1.3.6.1.4.1.6574.2.1.1'
RAID = '1.3.6.1.4.1.6574.3.1.1'


def fixture(fault=False, old=False, partial=False, maintenance=False):
    data = {f'{SYSTEM}.{suffix}.0': ['integer', 2 if fault else 1] for suffix in ('1', '3', '4.1', '4.2')}
    data[f'{SYSTEM}.2.0'] = ['integer', 42]
    if not old:
        data[f'{SYSTEM}.8.0'] = ['integer', 2 if fault else 1]
    for index in (0, 17):
        for column, value in ((2, f'Old Disk {index}'), (3, 'Synthetic model'), (12, f'Drive {index}')):
            data[f'{DISKS}.{column}.{index}'] = ['string', value]
        data[f'{DISKS}.5.{index}'] = ['integer', 5 if fault and index == 0 else 1]
        data[f'{DISKS}.6.{index}'] = ['integer', -99 if fault and index == 0 else 35 + index]
        if not old:
            data[f'{DISKS}.13.{index}'] = ['integer', 3 if fault and index == 17 else 1]
    # Disjoint sparse RAID rows ensure rows are joined by full numeric index.
    for index, status in ((0, 11 if fault else 1), (8, 12 if fault else 13 if maintenance else 1)):
        data[f'{RAID}.2.{index}'] = ['string', f'Pool {index}']
        data[f'{RAID}.3.{index}'] = ['integer', status]
    if partial:
        del data[f'{SYSTEM}.3.0']
        del data[f'{DISKS}.5.0']
        del data[f'{RAID}.3.8']
    return data


def snapshot(binary, state):
    output = run(binary, state, 'poll-once')
    require(output.returncode == 0, 'DSM actual poll failed; raw errors excluded')
    with sqlite3.connect(state/'monitor.db') as connection:
        return json.loads(connection.execute('SELECT snapshot FROM devices').fetchone()[0])


def observations(data, fragment):
    return [o for o in data['observations'] if fragment in o['key']]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    results = []
    with tempfile.TemporaryDirectory(prefix='hm-dsm-') as temp:
        root = Path(temp)
        community = secrets.token_hex(16)
        users = [(f'dsm_{i}', algorithm, secrets.token_hex(12), secrets.token_hex(12)) for i, algorithm in enumerate(('SHA', 'SHA-256'))]
        fixture_path = root/'fixture.json'
        private(fixture_path, json.dumps(fixture()))
        command = shlex.join([sys.executable, str(ROOT/'tools/snmp_synology_fixture.py'), str(fixture_path)])
        extra = [f'pass_persist .1.3.6.1.4.1.6574 {command}']
        with agent(root/'reference', community, users, extra_config=extra) as port:
            versions = [('v1', None), ('v2c', None)] + [('v3', u) for u in users]
            for number, (version, user) in enumerate(versions):
                security = {'version': version}
                credentials = {'kind': 'community', 'community': community}
                label = version
                if user:
                    username, algorithm, auth, privacy = user
                    security.update(username=username, auth='sha1' if algorithm == 'SHA' else 'sha256', privacy='aes128')
                    credentials = {'kind': 'usm', 'auth_password': auth, 'priv_password': privacy}
                    label += '-' + algorithm
                # The old-DSM absence case is also exercised on SNMPv1, where
                # unsupported OIDs use error-index handling instead of exceptions.
                old = version == 'v1'
                private(fixture_path, json.dumps(fixture(old=old)))
                device = dict(id=f'dsm-{number}', name='Synthetic DSM', primary_protocol='snmp',
                              snmp_poll=dict(host='127.0.0.1', port=port, security=security, profile='synology_dsm', timeout_ms=500, retries=1),
                              interval_seconds=60, repeat_seconds=None, alerts_enabled=True)
                config = root/f'device-{number}.json'
                private(config, json.dumps(device))
                state = root/f'state-{number}'
                payload = {'snmp': {'snmp_poll': {'action': 'replace', 'credentials': credentials}}}
                probe = run(binary, state, 'device-test', config, payload)
                require(probe.returncode == 0, f'{label}: DSM probe failed')
                data = json.loads(probe.stdout)
                require(data['profile'] == 'synology_dsm' and data['complete'], f'{label}: DSM profile not polled')
                require(len([c for c in data['capabilities'] if 'synology_' in c['uri'] and c['outcome'] == 'available']) == 2,
                        f'{label}: DSM table capabilities absent')
                require(run(binary, state, 'device-put', config, payload).returncode == 0, f'{label}: save failed')
                healthy = snapshot(binary, state)
                require(len(observations(healthy, 'synology_disks')) == 2 and len(observations(healthy, 'synology_raid')) == 2, f'{label}: sparse/zero indices lost')
                require(all(o['health'] == 'ok' for o in observations(healthy, 'synology_disks') + observations(healthy, 'synology_raid')), f'{label}: healthy mapping failed')
                require(all(not i['aliases'] for i in healthy['snmp']['identities']), f'{label}: names treated as proven serials')
                private(fixture_path, json.dumps(fixture(fault=True, old=old)))
                faulty = snapshot(binary, state)
                require(observations(faulty, ':power')[0]['health'] == 'critical', f'{label}: power fault absent')
                disks = observations(faulty, 'synology_disks')
                require(disks[0]['health'] == 'critical' and disks[0]['reading'] is None, f'{label}: deployment fault/sentinel failed')
                require(disks[1]['health'] == ('ok' if old else 'critical'), f'{label}: independent disk health missed')
                require([o['health'] for o in observations(faulty, 'synology_raid')] == ['warning', 'critical'], f'{label}: RAID state mapping failed')
                with sqlite3.connect(state/'monitor.db') as connection:
                    require(connection.execute("SELECT COUNT(*) FROM events WHERE kind='alarm'").fetchone()[0] >= 5, f'{label}: alarm pipeline bypassed')
                private(fixture_path, json.dumps(fixture(old=old, maintenance=True)))
                recovered = snapshot(binary, state)
                require(observations(recovered, ':power')[0]['health'] == 'ok', f'{label}: power recovery absent')
                require(observations(recovered, 'synology_raid')[1]['health'] == 'unknown', f'{label}: scrub incorrectly confirmed recovery')
                with sqlite3.connect(state/'monitor.db') as connection:
                    require(connection.execute("SELECT COUNT(*) FROM events WHERE kind='recovery' AND key='snmp:synology:power'").fetchone()[0] == 1, f'{label}: scalar recovery not persisted')
                private(fixture_path, json.dumps(fixture(old=old, partial=True)))
                partial = snapshot(binary, state)
                require(observations(partial, ':power')[0]['health'] == 'unknown', f'{label}: missing scalar became healthy')
                require(observations(partial, 'synology_disks')[0]['health'] == 'unknown', f'{label}: missing deployment became healthy')
                require(observations(partial, 'synology_raid')[1]['health'] == 'unknown', f'{label}: missing RAID status became healthy')
                rendered = json.dumps([healthy, faulty, recovered, partial]) + probe.stdout
                require(not any(secret in rendered for secret in [community] + [p for u in users for p in u[2:]]), f'{label}: credential disclosure')
                results.append(dict(case=label, probe=True, sparse_rows=True, optional_health=not old,
                                    faults=True, scalar_recovery=True, maintenance_unknown=True, partial_unknown=True))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'reference': 'Net-SNMP with test-only numeric DSM pass_persist fixture; no vendor firmware', 'cases': results}, indent=2)+'\n')
    print(f'Actual product DSM profile checks passed: {len(results)} configurations')


if __name__ == '__main__':
    main()
