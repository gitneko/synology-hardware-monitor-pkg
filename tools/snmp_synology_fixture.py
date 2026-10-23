#!/usr/bin/env python3
"""Independent Net-SNMP pass_persist handler for synthetic DSM numeric data.

This test-only process implements no SNMP codec or transport. Net-SNMP handles
v1/v2c/v3, GETNEXT/GETBULK, missing values and all authentication/privacy.
"""
import json
from pathlib import Path
import sys


def main():
    path = Path(sys.argv[1])
    for command in sys.stdin:
        command = command.strip()
        if command == 'PING':
            print('PONG', flush=True)
            continue
        if command not in ('get', 'getnext'):
            return
        requested = tuple(map(int, sys.stdin.readline().strip().strip('.').split('.')))
        values = {tuple(map(int, key.split('.'))): value for key, value in json.loads(path.read_text()).items()}
        candidates = sorted(k for k in values if k > requested) if command == 'getnext' else [requested] if requested in values else []
        if not candidates:
            print('NONE', flush=True)
            continue
        key = candidates[0]
        kind, value = values[key]
        print('.' + '.'.join(map(str, key)), kind, value, sep='\n', flush=True)


if __name__ == '__main__':
    main()
