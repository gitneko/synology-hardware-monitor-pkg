#!/usr/bin/env python3
"""Replay sanitized supplied HPE values through Net-SNMP and the real product.

No target BMC, original identifiers, credentials or event logs are contacted or
shipped. Net-SNMP independently implements v1/v2c/v3 and optional-field errors.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import sqlite3
import sys
import tempfile
from snmp_p2_integration import ROOT, agent, private, require, run

PSU = '1.3.6.1.4.1.232.6.2.9.3.1'
MEMORY = '1.3.6.1.4.1.232.6.2.14.13.1'
FANS = '1.3.6.1.4.1.232.6.2.6.7.1'


def fixture():
    data = {}
    for row in json.loads((ROOT/'tests/fixtures/snmp-hpe-ilo6.json').read_text())['rows']:
        if row['oid'].startswith('1.3.6.1.4.1.232.'):
            data[row['oid']] = ['string', row['text']] if row['type'] == 'OctetString' else ['integer', row['value']]
    return data


def poll(binary, state):
    require(run(binary, state, 'poll-once').returncode == 0, 'HPE poll failed; private raw output excluded')
    with sqlite3.connect(state/'monitor.db') as db:
        return json.loads(db.execute('SELECT snapshot FROM devices').fetchone()[0])


def alarms(state, key, kind):
    with sqlite3.connect(state/'monitor.db') as db:
        return db.execute('SELECT COUNT(*) FROM events WHERE key=? AND kind=?', (key, kind)).fetchone()[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(); binary = args.binary.resolve(); results = []
    with tempfile.TemporaryDirectory(prefix='hm-hpe-') as temp:
        root = Path(temp); community = secrets.token_hex(16)
        users = [(f'hpe_{i}', algorithm, secrets.token_hex(12), secrets.token_hex(12)) for i, algorithm in enumerate(('SHA','SHA-256'))]
        fixture_path = root/'fixture.json'; private(fixture_path,json.dumps(fixture()))
        command = shlex.join([sys.executable,str(ROOT/'tools/snmp_synology_fixture.py'),str(fixture_path)])
        extra = [f'pass_persist .1.3.6.1.4.1.232 {command}', 'sysDescr Integrated Lights-Out 6 1.79 Sep 23 2026', 'sysObjectID .1.3.6.1.4.1.232.9.4.12']
        with agent(root/'reference',community,users,extra_config=extra) as port:
            for number,(version,user) in enumerate([('v1',None),('v2c',None)]+[('v3',u) for u in users]):
                data=fixture(); private(fixture_path,json.dumps(data))
                security={'version':version}; credentials={'kind':'community','community':community}; label=version
                if user:
                    username,algorithm,auth,privacy=user
                    security.update(username=username,auth='sha1' if algorithm=='SHA' else 'sha256',privacy='aes128')
                    credentials={'kind':'usm','auth_password':auth,'priv_password':privacy}; label+='-'+algorithm
                device=dict(id=f'hpe-{number}',name='Synthetic HPE',primary_protocol='snmp',snmp_poll=dict(host='127.0.0.1',port=port,security=security,profile='hpe_ilo5',timeout_ms=500,retries=1),interval_seconds=60,repeat_seconds=None,alerts_enabled=True)
                config=root/f'device-{number}.json'; private(config,json.dumps(device)); state=root/f'state-{number}'
                payload={'snmp':{'snmp_poll':{'action':'replace','credentials':credentials}}}
                require(run(binary,state,'device-put',config,payload).returncode==0,f'{label}: save failed')
                first=poll(binary,state)
                psu=next(o for o in first['observations'] if 'power_supplies:' in o['key'] and o['key'].endswith(':0.2'))
                require(first['assessment_exclusions'].get(psu['key'])=='absent',f'{label}: empty PSU not excluded')
                require(next(o for o in first['observations'] if o['key']=='snmp:storage')['health']=='unknown',f'{label}: missing storage became healthy')
                fans=[o for o in first['observations'] if o['key'].startswith('snmp:fans:')]
                require([o['reading'] for o in fans]==[7,7,41] and all(o['unit']=='%' and o['health']=='ok' for o in fans),f'{label}: percent fan readings failed')
                require(first['snmp']['hpe']['power_state']==2 and not first['snmp']['hpe']['storage_assessable'],f'{label}: power/storage context absent')
                require(sum(1 for o in first['observations'] if o['key'].startswith('snmp:hpe_memory_modules:') and first['assessment_exclusions'].get(o['key'])=='absent')==3,f'{label}: empty DIMMs block assessment')
                presence=f'snmp:hpe:presence:{PSU}.0.2'
                require(alarms(state,presence,'alarm')==0,f'{label}: initially empty slot alarmed')
                data[f'{PSU}.3.0.2']=['integer',3]; data[f'{PSU}.4.0.2']=['integer',2]
                private(fixture_path,json.dumps(data)); poll(binary,state)
                data[f'{PSU}.3.0.2']=['integer',2]; data[f'{PSU}.4.0.2']=['integer',1]
                private(fixture_path,json.dumps(data)); removed=poll(binary,state)
                require(next(o for o in removed['observations'] if o['key']==presence)['health']=='warning',f'{label}: previously populated removal was hidden')
                require(alarms(state,presence,'alarm')==1,f'{label}: removal not persisted across process restart')
                del data[f'{PSU}.3.0.2']; private(fixture_path,json.dumps(data)); poll(binary,state)
                require(alarms(state,presence,'recovery')==0,f'{label}: missing presence falsely recovered')
                data[f'{PSU}.3.0.2']=['integer',3]; data[f'{PSU}.4.0.2']=['integer',2]
                private(fixture_path,json.dumps(data)); poll(binary,state)
                require(alarms(state,presence,'recovery')==1,f'{label}: explicit reinsertion did not recover')
                # A known failed component cannot recover merely by disappearing.
                data[f'{PSU}.4.0.1']=['integer',4]; private(fixture_path,json.dumps(data)); failed=poll(binary,state)
                failed_psu=next(o for o in failed['observations'] if o['key'].startswith('snmp:power_supply:id:'))
                require(failed_psu['health']=='critical',f'{label}: PSU fault lost')
                data[f'{PSU}.3.0.1']=['integer',2]; data[f'{PSU}.4.0.1']=['integer',1]; data[f'{PSU}.11.0.1']=['string','']
                data[f'{MEMORY}.20.1']=['integer',4]
                private(fixture_path,json.dumps(data)); absent=poll(binary,state)
                require(alarms(state,failed_psu['key'],'recovery')==0,f'{label}: absent component cleared retained fault')
                require(next(o for o in absent['observations'] if o['key'].startswith('snmp:memory:id:'))['health']=='warning',f'{label}: memory-specific condition enum lost')
                # Optional new scalars must not poison an SNMPv1 GET PDU.
                for oid in ('1.3.6.1.4.1.232.9.2.2.32.0','1.3.6.1.4.1.232.6.2.9.1.0'):data.pop(oid,None)
                private(fixture_path,json.dumps(data)); optional=poll(binary,state)
                require(optional['snmp']['complete'] and optional['snmp']['hpe']['power_state'] is None,f'{label}: missing optional scalar poisoned poll')
                require(all(o['reading'] is not None for o in optional['observations'] if o['key'].startswith('snmp:fans:')),f'{label}: optional scalar lost healthy fans')
                results.append(dict(case=label,sanitized_capture=True,empty_psu_dimms=True,firmware_percent=True,storage_unknown=True,power_state=True,persisted_removal=True,explicit_recovery=True,retained_fault=True,optional_scalars=True))
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps({'reference':'Independent Net-SNMP replay of sanitized supplied values plus synthetic population/fault transitions; not live BMC or DSM acceptance','cases':results},indent=2)+'\n')
    print(f'Actual product HPE profile checks passed: {len(results)} cases')


if __name__=='__main__':main()
