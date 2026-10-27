#!/usr/bin/env python3
"""Synthetic loopback interoperability tests against independent Net-SNMP tools.

Credentials are randomly generated, written to private temporary configs and
passed to the candidate on stdin. No NAS/BMC, real credentials or recipients.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import random
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time

SYS_DESCR = '1.3.6.1.2.1.1.1.0'
SYS_NAME = '1.3.6.1.2.1.1.5.0'
MISSING = '1.3.6.1.4.1.55555.99.0'
TRAP = '1.3.6.1.6.3.1.1.5.3'
ENGINE_A = '800013700150304141'
ENGINE_B = '800013700150304242'


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def private_write(path, text):
    path.write_text(text)
    path.chmod(0o600)


def environment(directory):
    env = dict(os.environ, MIBS='', SNMPCONFPATH=str(directory),
               SNMP_PERSISTENT_DIR=str(directory / 'persistent'))
    (directory / 'persistent').mkdir(exist_ok=True)
    return env


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def poll(binary, config):
    result = subprocess.run([str(binary)], input=json.dumps(dict(config, action='poll'))+'\n',
                            text=True, capture_output=True, timeout=15)
    require(result.returncode == 0, 'candidate polling invocation failed (details excluded)')
    return json.loads(result.stdout)


@contextmanager
def agent(root, community, passwords):
    port = free_port()
    root.mkdir(mode=0o700)
    config = root / 'snmpd.conf'
    # Private process-local agent. No system config is read (-C), no system
    # persistent path, trap destinations or external interface is configured.
    lines = [f'agentAddress udp:127.0.0.1:{port}', f'persistentDir {root / "persistent"}',
             f'rocommunity {community} 127.0.0.1', 'sysName p0-synthetic-agent']
    for name, algorithm, auth, privacy in passwords:
        lines += [f'createUser {name} {algorithm} {auth} AES {privacy}', f'rouser {name} priv']
    private_write(config, '\n'.join(lines)+'\n')
    with (root/'agent.log').open('w') as log:
        process = subprocess.Popen(['snmpd', '-f', '-Lo', '-C', '-c', str(config),
                                    '-p', str(root/'agent.pid')], stdout=log, stderr=log, env=environment(root))
        try:
            for _ in range(60):
                require(process.poll() is None, 'reference agent exited (private log excluded)')
                # Agent readiness via an independent tool with community in config.
                private_write(root/'snmp.conf', f'defVersion 1\ndefCommunity {community}\n')
                ready = subprocess.run(['snmpget','-On','-t','0.1','-r','0', f'udp:127.0.0.1:{port}',SYS_NAME],
                                       env=environment(root),capture_output=True,timeout=2)
                if ready.returncode == 0:
                    break
                time.sleep(0.03)
            else:
                raise AssertionError('reference agent readiness timeout')
            yield f'127.0.0.1:{port}'
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


class Receiver:
    def __init__(self, binary, senders):
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, bufsize=1)
        self.outputs = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.control(dict(action='receive', senders=senders), wait=False)
        ready = self.next()
        self.address = ready['ready']

    def _read(self):
        for line in self.process.stdout:
            self.outputs.put(json.loads(line))
        self.outputs.put({'process_exited': True})

    def next(self):
        try:
            result = self.outputs.get(timeout=8)
        except queue.Empty:
            raise AssertionError('candidate receiver timed out') from None
        require('process_exited' not in result, 'candidate receiver exited (details excluded)')
        return result

    def control(self, command, wait=True):
        self.process.stdin.write(json.dumps(command)+'\n')
        self.process.stdin.flush()
        return self.next() if wait else None

    def datagram(self, packet, source='127.0.0.1'):
        host, port = self.address.split(':')
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.bind((source, 0))
            s.sendto(packet,(host,int(port)))
            return self.next()

    def close(self):
        if self.process.poll() is None:
            self.control({'action':'stop'},wait=False)
        self.process.communicate(timeout=5)
        require(self.process.returncode == 0,'candidate receiver shutdown failed')


def sender(name, engine, algorithm):
    return dict(name=name, ip='127.0.0.1', engine_id=engine, username='p0-shared',
                algorithm=algorithm, auth_password=secrets.token_hex(12),
                priv_password=secrets.token_hex(12), boots=1, time=1000)


def trap_packet(root, sender, boots=1, engine_time=1001, level='authPriv', context='', context_engine=None, extra_varbinds=0):
    require(engine_time > 0, 'Net-SNMP -Z zero substitutes host uptime; use a nonzero reference clock')
    directory = root / secrets.token_hex(4)
    directory.mkdir(mode=0o700)
    private_write(directory/'snmp.conf', '\n'.join([
        'defVersion 3', f'defSecurityName {sender["username"]}',
        f'defAuthType {"SHA" if sender["algorithm"]=="sha1" else "SHA-256"}',
        f'defAuthPassphrase {sender["auth_password"]}', 'defPrivType AES',
        f'defPrivPassphrase {sender["priv_password"]}', f'defSecurityLevel {level}',
    ])+'\n')
    # Independent Net-SNMP encoding. Capture once for replay/mutation/peer tests.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as capture:
        capture.bind(('127.0.0.1',0))
        capture.settimeout(3)
        command=['snmptrap','-On','-e','0x'+sender['engine_id'],'-E','0x'+(context_engine or sender['engine_id']),'-Z',f'{boots},{engine_time}',
                 '-n',context,f'udp:127.0.0.1:{capture.getsockname()[1]}','123',TRAP]
        command += [SYS_NAME, 's', 'synthetic'] * extra_varbinds
        result=subprocess.run(command, env=environment(directory),capture_output=True,timeout=5)
        require(result.returncode==0,'Net-SNMP notification encoding failed (details excluded)')
        return capture.recvfrom(65535)[0]


def run(binary):
    for program in ['snmpd','snmpget','snmptrap']:
        require(shutil.which(program),f'reference tool missing: {program}')
    completed=[]
    def passed(name):
        completed.append(name)
        print(f'PASS {name}',flush=True)
    with tempfile.TemporaryDirectory(prefix='hm-snmp-reference-') as temp:
        root=Path(temp)
        community=secrets.token_hex(12)
        credentials=[('p0sha1','SHA',secrets.token_hex(12),secrets.token_hex(12)),
                     ('p0sha256','SHA-256',secrets.token_hex(12),secrets.token_hex(12))]
        with agent(root/'agent',community,credentials) as target:
            basic=dict(target=target,community=community,version='v1')
            response=poll(binary,dict(basic,operations=[
                {'op':'get','oids':[SYS_DESCR,SYS_NAME]},
                {'op':'next','oids':['1.3.6.1.2.1.1.1','1.3.6.1.2.1.1.5']},
                {'op':'get','oids':[SYS_DESCR,MISSING,SYS_NAME]},
                {'op':'get','oids':[SYS_DESCR,SYS_NAME]},
                {'op':'bulk','oids':['1.3.6.1.2.1.1']},
                {'op':'get_partial','oids':[SYS_DESCR,MISSING,SYS_NAME]},
            ]))['results']
            require(len(response[0]['values'])==2 and len(response[1]['values'])==2,'v1 GET/NEXT response shape')
            require(response[2].get('index')==2,'v1 error-index did not identify missing OID')
            require(len(response[3]['values'])==2,'v1 supported OIDs not recoverable')
            require(response[4].get('error')=='rejected','v1 GETBULK was not refused')
            require(len(response[5]['values'])==2 and response[5]['unsupported']==[MISSING],'v1 bounded missing-OID isolation')
            passed('v1-get-batched-next-noSuchName-error-index-and-bulk-refusal')
            for name,algorithm,auth,privacy in credentials:
                response=poll(binary,dict(target=target,version='v3',username=name,
                    algorithm='sha1' if algorithm=='SHA' else 'sha256',auth_password=auth,priv_password=privacy,
                    operations=[{'op':'get','oids':[SYS_NAME]}]))
                require(len(response['results'][0].get('values',[]))==1 and response['engine'],'authenticated v3 read/discovery')
                passed('v3-'+algorithm.lower()+'-aes128-get-and-authenticated-time')
                observed=response['engine']
                bridge=dict(name='polled',ip='127.0.0.1',username=name,engine_id=observed['engine_id'],
                            algorithm='sha1' if algorithm=='SHA' else 'sha256',auth_password=auth,priv_password=privacy,
                            boots=observed['boots'],time=observed['time'])
                receiver=Receiver(binary,[bridge])
                try:
                    receipt=receiver.datagram(trap_packet(root,bridge,boots=observed['boots'],engine_time=observed['time']+1))
                    require(receipt['accepted'],'poll-authenticated time did not seed receiver')
                    # Fresh receiver again, seeded from the same independently
                    # authenticated reference-agent observation after restart.
                finally:
                    receiver.close()
                passed('poll-time-seeds-restarted-receiver-'+algorithm.lower())
                for wrong_field in ['auth_password', 'priv_password']:
                    bad=dict(target=target,version='v3',username=name,
                             algorithm=bridge['algorithm'],auth_password=auth,priv_password=privacy,
                             operations=[{'op':'get','oids':[SYS_NAME]}])
                    bad[wrong_field]=secrets.token_hex(12)
                    rejected=poll(binary,bad)
                    require(rejected['results'][0].get('error') and not rejected['results'][0].get('values'),
                            'wrong v3 credentials supplied health data')
                    # A validly HMAC-authenticated error Report can still update
                    # time when only the privacy key is wrong. It is not health
                    # data or a successful authPriv enrollment probe.
                    if wrong_field=='auth_password':
                        require(rejected['engine'] is None,'wrong auth key populated trusted time')
                passed('reject-wrong-poll-auth-and-privacy-'+algorithm.lower())
            wrong=poll(binary,dict(basic,community=secrets.token_hex(12),operations=[{'op':'get','oids':[SYS_NAME]}]))
            require(wrong['results'][0].get('error')=='timeout','wrong community accepted')
            passed('wrong-community-times-out-with-no-version-downgrade')

        a,b=sender('a',ENGINE_A,'sha1'),sender('b',ENGINE_B,'sha256')
        receiver=Receiver(binary,[a,b])
        try:
            for s in [a,b,a,b]:
                result=receiver.datagram(trap_packet(root,s))
                require(result.get('accepted') and result['sender']==s['name'] and result['oid']==TRAP,f'multi-secret routing: {result}')
            passed('v3-two-engines-shared-username-different-secrets-and-algorithms')
            rejected=[('wrong-secret',dict(a,auth_password=b['auth_password']),'authPriv',''),
                      ('wrong-context',a,'authPriv','unapproved'),
                      ('authNoPriv',a,'authNoPriv',''),('noAuthNoPriv',a,'noAuthNoPriv',''),
                      ('unknown-engine',dict(a,engine_id='800013700150305858'),'authPriv',''),
                      ('unknown-user',dict(a,username='unapproved'),'authPriv','')]
            for name,s,level,context in rejected:
                require(not receiver.datagram(trap_packet(root,s,level=level,context=context))['accepted'],name)
                passed('reject-'+name)
            packet=trap_packet(root,a)
            require(not receiver.datagram(trap_packet(root,a,context_engine=ENGINE_B))['accepted'],
                    'unapproved scoped context engine')
            passed('reject-wrong-context-engine')
            require(receiver.datagram(trap_packet(root,a,extra_varbinds=126))['accepted'],
                    '128 total varbinds unexpectedly rejected')
            require(not receiver.datagram(trap_packet(root,a,extra_varbinds=127))['accepted'],
                    'more than 128 varbinds accepted')
            passed('reject-excess-varbind-count')
            require(not receiver.datagram(packet,source='127.0.0.2')['accepted'],'unapproved source')
            mutated=bytearray(packet);mutated[-1]^=1
            require(not receiver.datagram(mutated)['accepted'],'HMAC mutation')
            deep=b'\x02\x01\x03'
            for _ in range(512):
                deep=b'\x30\x82'+len(deep).to_bytes(2,'big')+deep
            for bad in [packet+b'\x00',packet[:-1],b'\x30\x82\xff\xff',b'\x00'*16385,deep]:
                require(not receiver.datagram(bad)['accepted'],'malformed/oversize frame')
            passed('reject-source-tampering-trailing-truncated-malformed-and-oversized')
            # Inject an aged authenticated observation, not an ad hoc USM clock.
            age=90*86400
            receiver.control(dict(action='seed',name='a',boots=2,time=1000,age_seconds=age))
            require(receiver.datagram(trap_packet(root,a,boots=2,engine_time=1000+age-500))['accepted'],'long-silence drift')
            require(not receiver.datagram(trap_packet(root,a,boots=2,engine_time=1000))['accepted'],'stale sender time')
            require(receiver.datagram(trap_packet(root,a,boots=3,engine_time=5))['accepted'],'higher boots')
            require(not receiver.datagram(trap_packet(root,a,boots=2,engine_time=age+2000))['accepted'],'old boot replay')
            receiver.control(dict(action='seed',name='a',boots=1,time=1))
            require(not receiver.datagram(trap_packet(root,a,boots=2,engine_time=age+2000))['accepted'],'seed rollback')
            require(receiver.datagram(trap_packet(root,a,boots=3,engine_time=10))['accepted'],'receiver survived rejections')
            passed('aged-baseline-clock-drift-reboot-stale-replay-and-seed-rollback')
            started=time.monotonic()
            corpus=random.Random(0x9050)
            seed=trap_packet(root,b)
            for index in range(1000):
                if index%3==0:
                    bad=bytearray(seed)
                    bad[corpus.randrange(len(bad))]^=1<<corpus.randrange(8)
                elif index%3==1:
                    bad=seed[:corpus.randrange(len(seed))]
                else:
                    bad=corpus.randbytes(corpus.randrange(16386))
                require(not receiver.datagram(bad)['accepted'],'mutated/truncated/random frame accepted')
            require(receiver.datagram(trap_packet(root,b))['accepted'],'receiver failed after malformed flood')
            passed('bounded-seeded-malformed-corpus-1000-and-valid-reception-afterwards')
            print(f'INFO malformed corpus elapsed {time.monotonic()-started:.3f}s',flush=True)
        finally:
            receiver.close()
    return completed


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary',type=Path)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    try:
        cases=run(args.binary.resolve())
    except Exception as error:
        # Never echo subprocess command/config/packets that can carry secrets.
        print(f'FAIL {type(error).__name__}: {error}' if isinstance(error,AssertionError) else f'FAIL {type(error).__name__}; private details excluded',flush=True)
        raise SystemExit(1) from None
    if args.report:
        args.report.write_text(json.dumps({'reference':'Net-SNMP','cases':cases,'passed':len(cases)},indent=2)+'\n')
    print(f'{len(cases)} reference interoperability cases passed.')
