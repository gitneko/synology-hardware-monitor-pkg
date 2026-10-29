#!/usr/bin/env python3
"""Large legacy-database and >120-second initialization acceptance (synthetic only)."""
import argparse
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
from upgrade_integration import seed, check_migration, invoke, postinst, require


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--legacy-binary', type=Path)
    parser.add_argument('--database-mib', type=int, default=1152)
    parser.add_argument('--pause-seconds', type=int, default=125)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    require(args.database_mib >= 1024 and args.pause_seconds > 120, 'Acceptance must exceed the reported size/time boundary')
    binary = args.binary.resolve()
    legacy = args.legacy_binary.resolve() if args.legacy_binary else None
    cases = []
    with tempfile.TemporaryDirectory(prefix='hm-upgrade-startup-') as directory:
        root = Path(directory)
        large = root/'large'/'private'
        before = seed(large, legacy)
        db = sqlite3.connect(large/'monitor.db')
        try:
            db.execute('CREATE TABLE startup_padding(id INTEGER PRIMARY KEY,data BLOB NOT NULL)')
            # Auxiliary padding isolates database-copy cost; actual device,
            # alarm, history, credential and schema checks use the legacy seed.
            db.executemany('INSERT INTO startup_padding VALUES(?,zeroblob(1048576))',
                           ((index,) for index in range(args.database_mib)))
            db.commit()
            db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        finally:
            db.close()
        database_bytes = (large/'monitor.db').stat().st_size
        at = time.monotonic()
        try:
            result = subprocess.run([str(binary), '--state', str(large), '--socket', str(large.parent/'api.sock'), 'service', 'start'],
                                    capture_output=True, text=True, timeout=900)
            require(result.returncode == 0, 'Large legacy database startup failed; private output excluded')
            check_migration(large, before)
            invoke(binary, large, 'service', 'status')
        finally:
            invoke(binary, large, 'service', 'stop', success=False)
        elapsed = time.monotonic()-at
        backups = list(large.glob('pre-snmp-schema1-*'))
        with sqlite3.connect(backups[0]/'monitor.db') as copy:
            require(copy.execute('SELECT count(*) FROM startup_padding').fetchone()[0] == args.database_mib,
                    'Large pre-migration backup is incomplete')
            require(copy.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'Large backup integrity failed')
        require(postinst(binary, large).returncode == 0, 'Repair after large migration failed')
        require(len(list(large.glob('pre-snmp-schema1-*'))) == len(backups), 'Repair repeated the completed large migration backup')
        cases.append({'case':'large-legacy-start-migrate-backup-integrity-and-repeat-repair', 'passed':True,
                      'database_bytes':database_bytes, 'startup_seconds':round(elapsed,3)})
        print('PASS large legacy database, preserved backup and repeated repair', flush=True)

        slow = root/'slow'/'private'
        before = seed(slow, legacy)
        lock = sqlite3.connect(slow/'monitor.db')
        lock.execute('BEGIN EXCLUSIVE')
        process = subprocess.Popen([str(binary), '--state', str(slow), '--socket', str(slow.parent/'api.sock'), 'service', 'start'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        paused = False
        try:
            # The writer keeps initialization unfinished. Pause this test's
            # controller process (not a NAS process) to model a slow IO/scheduling
            # interval, then release the writer while the controller is stopped.
            time.sleep(1)
            require(process.poll() is None and not (slow/'daemon.pid').exists(), 'Initialization did not remain pending')
            os.kill(process.pid, signal.SIGSTOP)
            paused = True
            lock.rollback()
            lock.close()
            pause_at = time.monotonic()
            until = pause_at + args.pause_seconds
            while time.monotonic() < until:
                time.sleep(max(0, min(1, until-time.monotonic())))
            os.kill(process.pid, signal.SIGCONT)
            paused = False
            _output, _error = process.communicate(timeout=60)
            require(process.returncode == 0, 'Initialization longer than 120 seconds consumed the daemon readiness budget')
            invoke(binary, slow, 'service', 'status')
            check_migration(slow, before)
            cases.append({'case':'pending-initialization-paused-beyond-old-readiness-budget', 'passed':True,
                          'controlled_pause_seconds':round(time.monotonic()-pause_at,3)})
            print('PASS initialization delayed beyond 120 seconds still starts and reports ready', flush=True)
        finally:
            if paused:
                os.kill(process.pid, signal.SIGCONT)
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
            lock.close()
            invoke(binary, slow, 'service', 'stop', success=False)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({'cases':cases, 'native_DSM_acceptance':False,
                                      'note':'Controlled Linux process pause models a delayed initialization; not a measured NAS IO speed.'}, indent=2)+'\n')


if __name__ == '__main__':
    main()
