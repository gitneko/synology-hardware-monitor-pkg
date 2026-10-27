#!/usr/bin/env python3
"""Query OSV for exact reference dependency versions; sends public names/versions only."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import tomllib
from urllib.request import Request, urlopen

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--report',type=Path,required=True)
parser.add_argument('--lock',type=Path,default=Path(__file__).parent/'Cargo.lock')
args=parser.parse_args()
lock=tomllib.loads(args.lock.read_text())
packages=[p for p in lock['package'] if p.get('source','').startswith('registry+') or p['name']=='async-snmp']
queries=[{'package':{'name':p['name'],'ecosystem':'crates.io'},'version':p['version']} for p in packages]
request=Request('https://api.osv.dev/v1/querybatch',data=json.dumps({'queries':queries}).encode(),headers={'Content-Type':'application/json'})
with urlopen(request,timeout=45) as response:
    results=json.load(response)['results']
assert len(results)==len(packages)
findings=[{'name':p['name'],'version':p['version'],'advisories':[v['id'] for v in r['vulns']]} for p,r in zip(packages,results) if r.get('vulns')]
args.report.write_text(json.dumps({'checked_at':datetime.now(timezone.utc).isoformat(),'service':'https://api.osv.dev/v1/querybatch','packages':len(packages),'findings':findings},indent=2)+'\n')
print(json.dumps({'packages':len(packages),'findings':findings}))
raise SystemExit(bool(findings))
