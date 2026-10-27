#!/usr/bin/env python3
"""Validate the actual product against local independent SNMP/HTTPS/SMTP fixtures.

All credentials and runtime files are temporary; no NAS, BMC or real recipient is
contacted. Reference tooling is a development/CI prerequisite, never a payload.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--require-static', action='store_true')
    parser.add_argument('--load-seconds', type=int, choices=(0, 60), default=0)
    args = parser.parse_args()
    for name in ('snmpd', 'snmpget', 'snmptrap', 'openssl'):
        if not shutil.which(name):
            parser.error(f'Missing reference tool: {name}; install Net-SNMP and OpenSSL')
    binary = args.binary.resolve()
    version = tomllib.loads((ROOT/'Cargo.toml').read_text())['package']['version']
    observed = subprocess.check_output([str(binary), '--version'], text=True).strip()
    if observed != f'hardware-monitor {version}':
        parser.error('Product binary/source version mismatch; rebuild before reference tests')
    if args.require_static:
        header = subprocess.check_output(['readelf', '-h', str(binary)], text=True)
        segments = subprocess.check_output(['readelf', '-l', str(binary)], text=True)
        dynamic = subprocess.check_output(['readelf', '-d', str(binary)], text=True)
        if 'X86-64' not in header or 'INTERP' in segments or '(NEEDED)' in dynamic:
            parser.error('Expected a static x86-64 executable')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    suites = {}
    for suite in ('polling', 'receiver', 'alarm', 'synology', 'generic', 'ups', 'hpe'):
        report = args.report.with_name(f'{args.report.stem}-{suite}.json')
        command = [sys.executable, str(ROOT/f'tools/snmp_{suite}_integration.py'),
                   str(binary), '--report', str(report)]
        if suite in ('receiver', 'alarm'):
            command += ['--load-seconds', str(args.load_seconds)]
        subprocess.run(command, cwd=ROOT, check=True)
        suites[suite] = json.loads(report.read_text())
    evidence = {'checked_at': datetime.now(timezone.utc).isoformat(),
                'version': version, 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'static_required': args.require_static, 'load_seconds': args.load_seconds,
                'suites': suites}
    args.report.write_text(json.dumps(evidence, indent=2)+'\n')
    print(f'PASS actual product SNMP reference suites: {args.report}')


if __name__ == '__main__':
    main()
