#!/usr/bin/env python3
"""Direct schema-1 upgrade/start/repair regressions using private synthetic state.

The default fixture follows the 0.8.0 schema (base commit 2dcc528), not a current
schema with SNMP tables removed. --legacy-binary can additionally create the
state with an actual archived 0.8.0 executable. No real device/delivery is enabled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import sqlite3
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LEGACY_SCHEMA = '''
CREATE TABLE schema_version(version INTEGER NOT NULL);
INSERT INTO schema_version VALUES(1);
CREATE TABLE devices(id TEXT PRIMARY KEY,config TEXT NOT NULL,secret BLOB NOT NULL,last_poll INTEGER,snapshot TEXT,logs_initialized INTEGER NOT NULL DEFAULT 0,revision INTEGER NOT NULL DEFAULT 0);
CREATE TABLE alarm_state(device TEXT NOT NULL REFERENCES devices(id),key TEXT NOT NULL,health TEXT NOT NULL,label TEXT NOT NULL,observed INTEGER NOT NULL,emitted INTEGER,PRIMARY KEY(device,key));
CREATE TABLE events(id INTEGER PRIMARY KEY,device TEXT NOT NULL,key TEXT NOT NULL,kind TEXT NOT NULL,health TEXT NOT NULL,message TEXT NOT NULL,created INTEGER NOT NULL);
CREATE TABLE hardware_logs(device TEXT NOT NULL,fingerprint TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(device,fingerprint));
CREATE TABLE outbox(id INTEGER PRIMARY KEY,event_id INTEGER NOT NULL UNIQUE REFERENCES events(id),delivered INTEGER,attempts INTEGER NOT NULL DEFAULT 0,next_try INTEGER NOT NULL DEFAULT 0,cancelled INTEGER NOT NULL DEFAULT 0,transport TEXT);
CREATE TABLE alarm_control(device TEXT NOT NULL,key TEXT NOT NULL,token TEXT NOT NULL,acknowledged INTEGER NOT NULL DEFAULT 0,actor TEXT,acknowledged_at INTEGER,reason TEXT,signature TEXT NOT NULL DEFAULT '',reannounce INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(device,key),FOREIGN KEY(device,key) REFERENCES alarm_state(device,key) ON DELETE CASCADE);
CREATE TABLE mail_settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL,secret BLOB NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE notification_settings(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT NOT NULL,revision INTEGER NOT NULL);
'''


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def invoke(binary, state, *command, success=True):
    result = subprocess.run([str(binary), '--state', str(state), '--socket', str(state.parent/'api.sock'), *command],
                            capture_output=True, text=True, timeout=45)
    if success:
        require(result.returncode == 0, f'Upgrade check failed: {command[0]}; private log/output excluded')
    return result


def seed(state, legacy=None):
    state.mkdir(mode=0o700, parents=True)
    device = dict(id='legacy-device', name='Synthetic legacy', endpoint='https://127.0.0.1:1/', username='reader',
                  interval_seconds=60, repeat_seconds=None, alerts_enabled=True, ca_file=None, enabled=False)
    if legacy:
        config = state.parent/'legacy-device.json'
        config.write_text(json.dumps(device)); config.chmod(0o600)
        result = subprocess.run([str(legacy), '--state', str(state), 'device-put', '--file', str(config)],
                                input=secrets.token_hex(16), text=True, capture_output=True, timeout=20)
        require(result.returncode == 0, 'Archived legacy executable could not create fixture')
    else:
        key = state/'master.key'; key.write_bytes(secrets.token_bytes(32)); key.chmod(0o600)
        with sqlite3.connect(state/'monitor.db') as db:
            db.executescript(LEGACY_SCHEMA)
            # Opaque bytes are preserved, not interpreted, by database migration.
            db.execute('INSERT INTO devices(id,config,secret) VALUES(?,?,?)', (device['id'], json.dumps(device), secrets.token_bytes(64)))
    now = int(time.time())
    with sqlite3.connect(state/'monitor.db') as db:
        # These tables/fields also existed in later 0.8.0 builds. They are added
        # to the archived 0018 fixture to cover the later acknowledgement data.
        for statement in LEGACY_SCHEMA.split(';'):
            if statement.strip().startswith('CREATE TABLE alarm_control'):
                db.execute(statement.replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', 1))
        saved = json.loads(db.execute('SELECT config FROM devices').fetchone()[0]); saved['enabled'] = False
        db.execute('UPDATE devices SET config=?', (json.dumps(saved),))
        db.execute('UPDATE devices SET last_poll=?,snapshot=?,logs_initialized=1', (now, json.dumps({'observations':[], 'capabilities':[], 'logs':[], 'logs_complete':True})))
        db.execute('INSERT INTO alarm_state VALUES(?,?,?,?,?,?)', (device['id'], 'legacy-fan', '"critical"', 'Synthetic fan', now, now))
        db.execute('INSERT INTO events(id,device,key,kind,health,message,created) VALUES(1,?,?,?,?,?,?)', (device['id'], 'legacy-fan', 'alarm', '"critical"', 'Synthetic retained event', now))
        db.execute('INSERT INTO hardware_logs VALUES(?,?,?)', (device['id'], 'legacy-log', '{"message":"Synthetic old log"}'))
        db.execute('INSERT INTO outbox(id,event_id,next_try) VALUES(1,1,?)', (now,))
        db.execute('INSERT INTO alarm_control(device,key,token,acknowledged,actor,acknowledged_at,reason) VALUES(?,?,?,?,?,?,?)',
                   (device['id'], 'legacy-fan', 'synthetic-ack-token', 1, 'synthetic-admin', now, 'Synthetic review'))
        if not legacy:
            db.execute('INSERT INTO mail_settings VALUES(1,?,?,7)', ('{"enabled":false}', secrets.token_bytes(48)))
            db.execute('INSERT INTO notification_settings VALUES(1,?,8)', ('{"desktop_enabled":false}',))
        db.execute('PRAGMA journal_mode=DELETE')
    (state/'monitor.db').chmod(0o600)
    return retained(state)


def retained(state):
    with sqlite3.connect(state/'monitor.db') as db:
        values = {table: db.execute(f'SELECT * FROM {table} ORDER BY 1,2').fetchall()
                  for table in ('alarm_state', 'hardware_logs', 'alarm_control', 'mail_settings', 'notification_settings')}
        columns = {row[1] for row in db.execute('PRAGMA table_info(outbox)')}
        extra = ','.join(name if name in columns else fallback for name,fallback in [('cancelled','0'),('transport','NULL')])
        values['outbox'] = db.execute('SELECT id,event_id,delivered,attempts,next_try,'+extra+' FROM outbox ORDER BY id').fetchall()
        values['devices'] = db.execute('SELECT id,secret,last_poll,snapshot,logs_initialized,revision FROM devices').fetchall()
        values['events'] = db.execute('SELECT id,device,key,kind,health,message,created FROM events').fetchall()
    values['master.key'] = (state/'master.key').read_bytes()
    return values


def check_migration(state, before):
    require(retained(state) == before, 'Legacy state, acknowledgement, delivery settings or key changed')
    backups = list(state.glob('pre-snmp-schema1-*'))
    require(len(backups) == 1, 'Expected one complete pre-migration backup')
    require(not list(state.glob('.pre-snmp-schema1-*.partial')), 'Successful migration left incomplete backup')
    require((backups[0]/'master.key').read_bytes() == before['master.key'], 'Rollback key mismatch')
    for path in (backups[0], backups[0]/'master.key', backups[0]/'monitor.db'):
        require(path.stat().st_mode & 0o077 == 0, 'Rollback files are not private')
    with sqlite3.connect(backups[0]/'monitor.db') as db:
        require(db.execute('SELECT version FROM schema_version').fetchone()[0] == 1, 'Rollback snapshot is not schema 1')
    with sqlite3.connect(state/'monitor.db') as db:
        require(db.execute('SELECT version FROM schema_version').fetchone()[0] == 2, 'Upgrade did not reach schema 2')
        config = json.loads(db.execute('SELECT config FROM devices').fetchone()[0])
        require(config['primary_protocol'] == 'redfish' and config['snmp_poll'] is None and config['snmp_traps'] is None, 'Legacy device changed protocol')
        settings = json.loads(db.execute('SELECT config FROM snmp_receiver_settings').fetchone()[0])
        require(not settings['enabled'], 'Upgrade enabled trap reception')


def postinst(binary, state):
    source = (ROOT/'packaging/scripts/postinst').read_text()
    invocation = shlex.join([str(binary), '--state', str(state), '--socket', str(state.parent/'api.sock')])
    script = source.replace('/var/packages/HardwareMonitor/target/bin/hardware-monitor', invocation).replace('/var/packages/HardwareMonitor/etc/private', shlex.quote(str(state)))
    return subprocess.run(['sh', '-c', script], capture_output=True, text=True, timeout=45)


def lifecycle(binary, state):
    require(invoke(binary, state, 'service', 'status', success=False).returncode == 3, 'DSM stopped status must be 3')
    try:
        invoke(binary, state, 'service', 'start')
        invoke(binary, state, 'service', 'status')
        invoke(binary, state, 'service', 'start')
    finally:
        invoke(binary, state, 'service', 'stop')
    require(invoke(binary, state, 'service', 'status', success=False).returncode == 3, 'DSM stopped status must remain 3')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--legacy-binary', type=Path)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args(); binary = args.binary.resolve(); legacy = args.legacy_binary.resolve() if args.legacy_binary else None
    results = []
    with tempfile.TemporaryDirectory(prefix='hm-upgrade-') as directory:
        root = Path(directory)
        fresh = root/'fresh'/'private'
        require(postinst(binary, fresh).returncode == 0, 'Fresh postinst initialization failed')
        lifecycle(binary, fresh)
        results.append({'case':'fresh-postinst-and-DSM-status', 'passed':True})
        state = root/'legacy'/'private'; before = seed(state, legacy)
        require(postinst(binary, state).returncode == 0, 'Direct upgrade postinst failed')
        check_migration(state, before)
        for _ in range(2):
            require(postinst(binary, state).returncode == 0, 'Repair/repeated postinst failed')
            check_migration(state, before)
        require((state/'service.log').stat().st_mode & 0o077 == 0, 'Initialization log not private')
        lifecycle(binary, state)
        results.append({'case':'direct-schema1-postinst-upgrade-and-repeat-repair', 'passed':True})
        slow = root/'slow'/'private'; before = seed(slow, legacy)
        with sqlite3.connect(slow/'monitor.db') as lock:
            lock.execute('BEGIN EXCLUSIVE')
            outcome = {}
            def start():
                at = time.monotonic()
                outcome['result'] = invoke(binary, slow, 'service', 'start', success=False)
                outcome['elapsed'] = time.monotonic() - at
            worker = threading.Thread(target=start); worker.start()
            time.sleep(6); lock.rollback(); worker.join(timeout=35)
            require(not worker.is_alive(), 'Delayed startup remained blocked')
        try:
            require(outcome['result'].returncode == 0 and outcome['elapsed'] >= 5.5, 'Startup did not tolerate a delay beyond the old five-second limit')
            invoke(binary, slow, 'service', 'status')
            check_migration(slow, before)
        finally:
            invoke(binary, slow, 'service', 'stop')
        results.append({'case':'direct-schema1-delayed-start-with-six-second-database-lock', 'passed':True, 'startup_seconds':round(outcome['elapsed'],3)})
        failed = root/'failed'/'private'; seed(failed, legacy)
        with sqlite3.connect(failed/'monitor.db') as db:
            raw = json.loads(db.execute('SELECT config FROM devices').fetchone()[0]); raw['id'] = 'wrong-device'; db.execute('UPDATE devices SET config=?',(json.dumps(raw),))
        require(postinst(binary, failed).returncode != 0, 'Invalid legacy configuration was silently accepted')
        with sqlite3.connect(failed/'monitor.db') as db:
            require(db.execute('SELECT version FROM schema_version').fetchone()[0] == 1, 'Failed migration changed schema')
            require(not db.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='protocol_secrets')").fetchone()[0], 'Failed migration left partial schema')
            raw['id']='legacy-device'; db.execute('UPDATE devices SET config=?',(json.dumps(raw),))
        require(postinst(binary, failed).returncode == 0, 'Retry after corrected legacy configuration failed')
        lifecycle(binary, failed)
        results.append({'case':'failed-migration-atomic-and-retry-after-correction', 'passed':True})
        unknown = root/'not-a-directory'; unknown.write_text('synthetic')
        require(invoke(binary, unknown, 'service', 'status', success=False).returncode == 4, 'Unknown DSM status must be 4')
        results.append({'case':'DSM-unknown-status-distinct-from-stopped', 'passed':True})
    report = {'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(), 'fixture':'archived actual legacy executable' if legacy else 'independent schema-1 SQL fixture from 0.8.0',
              'legacy_version':subprocess.check_output([str(legacy),'--version'],text=True).strip() if legacy else None,
              'cases':results, 'native_DSM_acceptance':False}
    args.report.parent.mkdir(parents=True, exist_ok=True); args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(f'PASS direct upgrade, initialization, repair and DSM status checks: {len(results)} cases')


if __name__ == '__main__':
    main()
