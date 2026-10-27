#!/usr/bin/env python3
"""Actual CLI + independent Net-SNMP: scoped generic health and interface discovery.

Synthetic loopback data only. No production firewall, switch or recipient.
"""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import sqlite3
import sys
import tempfile
import time
from snmp_polling_integration import agent, private, require, run
ROOT=Path(__file__).resolve().parents[1]
BASE='1.3.6.1.2.1.2.2.1'
EXT='1.3.6.1.2.1.31.1.1.1'
ETH='1.3.6.1.2.1.10.7.2.1'


def fixture(oper=2, missing=False, partial=False, disabled=False, counter=1000, extensions=True):
    result={}
    for index,state in ((7,oper),(19,2)):
        if missing and index==7:continue
        for column,kind,value in ((2,'string',f'Base interface {index}'),(3,'integer',6),(5,'gauge',1_000_000),
                                   (7,'integer',2 if disabled and index==7 else 1),(8,'integer',state),
                                   (10,'counter',counter),(16,'counter',counter*2),(14,'counter',0),(20,'counter',0),(13,'counter',0),(19,'counter',0)):
            if partial and index==7 and column==8:continue
            result[f'{BASE}.{column}.{index}']=[kind,value]
        if extensions:
            for column,kind,value in ((1,'string',f'igc{index}'),(15,'gauge',1),(18,'string',f'Synthetic port {index}'),(19,'timeticks',0)):
                result[f'{EXT}.{column}.{index}']=[kind,value]
            result[f'{ETH}.19.{index}']=['integer',3]
    return result


def saved(binary,state):
    response=run(binary,state,'snapshot');require(response.returncode==0,'snapshot command failed')
    return json.loads(response.stdout)['devices'][0]


def poll(binary,state):
    result=run(binary,state,'poll-once');require(result.returncode==0,'actual network product poll failed; raw errors excluded')
    return saved(binary,state)


def port(device,index):
    return next(i for i in device['snapshot']['snmp']['network']['interfaces'] if i['index']==index)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    binary=args.binary.resolve();results=[]
    with tempfile.TemporaryDirectory(prefix='hm-generic-') as temp:
        root=Path(temp);community=secrets.token_hex(16)
        users=[(f'net_{i}',alg,secrets.token_hex(12),secrets.token_hex(12)) for i,alg in enumerate(('SHA','SHA-256'))]
        fixture_path=root/'fixture.json';private(fixture_path,json.dumps(fixture()))
        command=shlex.join([sys.executable,str(ROOT/'tools/snmp_synology_fixture.py'),str(fixture_path)])
        extra=[f'pass_persist -p 1 .{oid} {command}' for oid in (BASE,EXT,ETH)]
        with agent(root/'reference',community,users,extra_config=extra) as listen_port:
            for number,(version,user) in enumerate([('v1',None),('v2c',None)]+[('v3',u) for u in users]):
                security={'version':version};credentials={'kind':'community','community':community};label=version
                if user:
                    username,algorithm,auth,privacy=user;security.update(username=username,auth='sha1' if algorithm=='SHA' else 'sha256',privacy='aes128');credentials={'kind':'usm','auth_password':auth,'priv_password':privacy};label+='-'+algorithm
                device={'id':f'network-{number}','name':'Synthetic network','primary_protocol':'snmp','snmp_poll':{'host':'127.0.0.1','port':listen_port,'security':security,'profile':'network_generic','timeout_ms':500,'retries':1},'interval_seconds':60,'repeat_seconds':None,'alerts_enabled':False}
                config=root/f'device-{number}.json';private(config,json.dumps(device));state=root/f'state-{number}';payload={'snmp':{'snmp_poll':{'action':'replace','credentials':credentials}}}
                private(fixture_path,json.dumps(fixture()))
                require(run(binary,state,'device-test',config,payload).returncode==0,f'{label}: network probe failed')
                require(run(binary,state,'device-put',config,payload).returncode==0,f'{label}: save failed')
                first=poll(binary,state);require(first['overall_status']=='ok',f'{label}: unused ports block assessment')
                require({i['index'] for i in first['snapshot']['snmp']['network']['interfaces']}=={7,19},f'{label}: discovery did not use synthetic sparse rows')
                require(not port(first,7)['seen_up'],f'{label}: initially down port armed')
                private(fixture_path,json.dumps(fixture(oper=1)));up=poll(binary,state);require(port(up,7)['seen_up'] and up['overall_status']=='ok',f'{label}: active port not armed')
                time.sleep(1.05)
                private(fixture_path,json.dumps(fixture(oper=1,counter=2000)));rate=poll(binary,state)
                key=port(rate,7)['key']+':in_octets';require(any(o['key']==key and o['reading'] is not None and o['reading']>0 for o in rate['snapshot']['observations']),f'{label}: two-sample traffic rate absent')
                # Each CLI invocation is a new process: durable arming is required.
                private(fixture_path,json.dumps(fixture(oper=2)));down=poll(binary,state);require(down['overall_status']=='warning',f'{label}: link loss did not raise persisted alarm')
                private(fixture_path,json.dumps(fixture(disabled=True)));disabled=poll(binary,state);require(disabled['overall_status']=='warning',f'{label}: admin shutdown cleared fault')
                private(fixture_path,json.dumps(fixture(partial=True)));partial=poll(binary,state);require(partial['overall_status']=='warning',f'{label}: missing status cleared fault')
                private(fixture_path,json.dumps(fixture(missing=True)));missing=poll(binary,state);require(missing['overall_status']=='warning' and not port(missing,7)['present'],f'{label}: missing interface cleared fault or baseline')
                private(fixture_path,json.dumps(fixture(oper=2)));still_down=poll(binary,state);require(still_down['overall_status']=='warning' and port(still_down,7)['seen_up'],f'{label}: reappearing down port lost arming')
                private(fixture_path,json.dumps(fixture(oper=1)));recovered=poll(binary,state);require(recovered['overall_status']=='ok',f'{label}: current up did not recover')
                with sqlite3.connect(state/'monitor.db') as db:
                    events=db.execute("SELECT kind FROM events WHERE key=? ORDER BY id",(port(recovered,7)['key'],)).fetchall()
                require([r[0] for r in events]==['alarm','recovery'],f'{label}: duplicate or missing link transitions')
                # Optional ifXTable/EtherLike absence stays neutral; the logical
                # identity uses the same ifDescr fallback in this fixture.
                private(fixture_path,json.dumps(fixture(oper=1,extensions=False)));fallback=poll(binary,state);require(fallback['overall_status']=='ok',f'{label}: optional network groups block health')
                secrets_to_check=[community]+[p for u in users for p in u[2:]]
                require(not any(s in json.dumps([first,up,rate,down,disabled,partial,missing,still_down,recovered,fallback]) for s in secrets_to_check),f'{label}: credential disclosure')
                results.append({'case':label,'discovery':True,'generic_optional_groups':True,'initially_down_neutral':True,'durable_link_alarm':True,'missing_and_partial_retain_fault':True,'one_recovery':True,'traffic_rate':True})
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps({'reference':'actual product CLI / independent Net-SNMP / synthetic logical interfaces; no hardware acceptance','cases':results},indent=2)+'\n');print(f'Actual generic network profile checks passed: {len(results)} configurations')


if __name__=='__main__':main()
