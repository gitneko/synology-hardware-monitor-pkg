#!/usr/bin/env python3
"""Actual daemon: independent Net-SNMP traps + controlled HTTPS/SMTP loopback.

All credentials/configs are temporary/private. Fixture SQLite writes configure
channels before startup; production has no authentication bypass. No NAS/BMC or
real recipient is contacted, and synthetic payloads do not prove vendor support.
"""
import argparse
import base64
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import socketserver
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
from snmp_p2_integration import agent, private, require, run
from snmp_p3_integration import clock, reference, wait_for, denied_api, resources

FAN='/redfish/v1/Chassis/1/Thermal#/Fans/Fan1'

class Redfish(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*_): pass
    def do_GET(self):
        server=self.server
        if self.headers.get('Authorization')!=server.auth:
            self.send_response(401);self.send_header('Content-Length','0');self.end_headers();return
        current=server.health
        root='/redfish/v1/'
        if self.path==root:
            body={'@odata.id':root,'Chassis':{'@odata.id':root+'Chassis/'}}
        elif self.path==root+'Chassis/':
            body={'@odata.id':self.path,'Members':[{'@odata.id':root+'Chassis/1/'}]}
        elif self.path==root+'Chassis/1/':
            body={'@odata.id':self.path,'@odata.type':'#Chassis.v1_0_0.Chassis','Status':{'Health':'OK'},'Thermal':{'@odata.id':root+'Chassis/1/Thermal'}}
        elif self.path==root+'Chassis/1/Thermal':
            body={'@odata.id':self.path,'Fans':[{'@odata.id':FAN,'@odata.type':'#Fan.v1_0_0.Fan','Name':'Synthetic fan 1','MemberId':'Fan1','Status':{'Health':current},'Reading':1234,'ReadingUnits':'RPM','Oem':{'Dell':{'FQDD':'Fan.Embedded.1'}}}]}
            if server.block_once:
                server.block_once=False;server.blocked.set();require(server.release.wait(8),'controlled old response was not released')
        else:
            self.send_response(404);self.send_header('Content-Length','0');self.end_headers();return
        raw=json.dumps(body).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)

class SmtpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
class Smtp(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 synthetic SMTP\r\n')
        while line:=self.rfile.readline(65536):
            verb=line.split(b' ',1)[0].strip().upper()
            if verb==b'EHLO':self.wfile.write(b'250 synthetic\r\n')
            elif verb==b'DATA':
                self.wfile.write(b'354 message\r\n');data=[]
                while (part:=self.rfile.readline(65536)) not in (b'.\r\n',b''):data.append(part)
                self.server.messages.append(b''.join(data));self.wfile.write(b'250 accepted\r\n')
            elif verb==b'QUIT':self.wfile.write(b'221 bye\r\n');return
            else:self.wfile.write(b'250 ok\r\n')

def rows(state,sql,params=()):
    with sqlite3.connect(state/'monitor.db') as db:return list(db.execute(sql,params))

def packet(root,sender,boots,engine_time,oid,uptime=123):
    require(engine_time > 0, "Net-SNMP -Z zero substitutes host uptime; use a nonzero observed agent clock")
    conf=root/secrets.token_hex(4);conf.mkdir(mode=0o700)
    private(conf/'snmp.conf','\n'.join(['defVersion 3',f'defSecurityName {sender["username"]}','defAuthType SHA-256',f'defAuthPassphrase {sender["auth_password"]}','defPrivType AES',f'defPrivPassphrase {sender["priv_password"]}','defSecurityLevel authPriv'])+'\n')
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as capture:
        capture.bind(('127.0.0.1',0));capture.settimeout(3)
        command=['snmptrap','-On','-e','0x'+sender['engine_id'],'-E','0x'+sender['engine_id'],'-Z',f'{boots},{engine_time}',f'udp:127.0.0.1:{capture.getsockname()[1]}',str(uptime),oid,'1.3.6.1.4.1.674.10892.5.3.1.6.0','s','Fan.Embedded.1','1.3.6.1.4.1.674.10892.5.3.1.1.0','s','FAN0001']
        result=subprocess.run(command,env=reference.environment(conf),capture_output=True,timeout=5)
        require(result.returncode==0,'independent trap encoding failed (private output excluded)');return capture.recvfrom(65535)[0]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path,required=True);parser.add_argument('--load-seconds',type=int,default=0);args=parser.parse_args();binary=args.binary.resolve();results=[]
    with tempfile.TemporaryDirectory(prefix='hm-snmp-p4-') as tmp,ExitStack() as stack:
        root=Path(tmp);state=root/'state';api=root/'api.sock';cert=root/'cert.pem';key=root/'key.pem'
        ca=root/'ca.pem';ca_key=root/'ca.key';csr=root/'leaf.csr';extensions=root/'leaf.ext'
        private(extensions,'subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        for command in [
            ['req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(ca_key),'-out',str(ca),'-days','1','-subj','/CN=Synthetic P4 CA'],
            ['req','-new','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(csr),'-subj','/CN=127.0.0.1'],
            ['x509','-req','-in',str(csr),'-CA',str(ca),'-CAkey',str(ca_key),'-CAcreateserial','-out',str(cert),'-days','1','-extfile',str(extensions)],
        ]:subprocess.run(['openssl',*command],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        http=ThreadingHTTPServer(('127.0.0.1',0),Redfish);http.daemon_threads=True;http.health='OK';http.block_once=False;http.blocked=threading.Event();http.release=threading.Event();password=secrets.token_hex(16);http.auth='Basic '+base64.b64encode(('reader:'+password).encode()).decode()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);http.socket=context.wrap_socket(http.socket,server_side=True)
        threading.Thread(target=http.serve_forever,daemon=True).start();stack.callback(http.server_close);stack.callback(http.shutdown)
        smtp=SmtpServer(('127.0.0.1',0),Smtp);smtp.messages=[];threading.Thread(target=smtp.serve_forever,daemon=True).start();stack.callback(smtp.server_close);stack.callback(smtp.shutdown)
        sender=dict(username='p4-synthetic',algorithm='sha256',auth_password=secrets.token_hex(12),priv_password=secrets.token_hex(12))
        agent_port=stack.enter_context(agent(root/'agent',secrets.token_hex(16),[(sender['username'],'SHA-256',sender['auth_password'],sender['priv_password'])],engine_id_text='p4-independent-agent'))
        security=dict(version='v3',username=sender['username'],auth='sha256',privacy='aes128')
        poll=dict(host='127.0.0.1',port=agent_port,security=security,timeout_ms=300,retries=0)
        identity_config=root/'identity.json';private(identity_config,json.dumps(dict(id='identity',name='Synthetic identity',primary_protocol='snmp',snmp_poll=poll,interval_seconds=60,repeat_seconds=None,alerts_enabled=False)))
        credentials={'kind':'usm','auth_password':sender['auth_password'],'priv_password':sender['priv_password']}
        identity=run(binary,state,'device-test',identity_config,{'snmp':{'snmp_poll':{'action':'replace','credentials':credentials}}});require(identity.returncode==0,'actual identity read failed');sender['engine_id']=json.loads(identity.stdout)['engine_id']
        device=dict(id='p4',name='Synthetic P4',endpoint=f'https://127.0.0.1:{http.server_port}/',username='reader',ca_pem=ca.read_text(),snmp_poll=poll,snmp_traps=dict(enabled=True,profile='dell_idrac',allowed_sources=['127.0.0.1'],engine_ids=[sender['engine_id']],security=security),interval_seconds=60,repeat_seconds=None,alerts_enabled=True)
        config=root/'device.json';private(config,json.dumps(device));require(run(binary,state,'device-put',config,{'redfish_password':password,'snmp':{'snmp_traps':{'action':'replace','credentials':credentials}}}).returncode==0,'RF/trap fixture save failed')
        require(run(binary,state,'poll-once').returncode==0,'initial RF inventory poll failed')
        snapshot=json.loads(rows(state,'SELECT snapshot FROM devices')[0][0]);require(any(c['key']==FAN and c['aliases']==['Fan.Embedded.1'] for c in snapshot['component_identities']),'actual RF FQDD identity missing')
        before_poll=rows(state,'SELECT last_poll FROM devices')[0][0]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as reserve:reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        with sqlite3.connect(state/'monitor.db') as db:
            db.execute('UPDATE snmp_receiver_settings SET config=?,revision=1 WHERE id=1',(json.dumps(dict(enabled=True,listen_port=port,listen_addresses=['127.0.0.1'])),));db.execute('UPDATE snmp_runtime SET epoch=epoch+1 WHERE id=1')
            mail=dict(enabled=True,host='127.0.0.1',port=smtp.server_address[1],security='plain',username='',from_address='sender@example.invalid',from_name='Synthetic',recipients=['alarm@example.invalid'],subject_template='Synthetic {{kind}} {{event_id}}',body_template='{{message}}\n{{source}} {{verified}} {{provisional}}',ca_pem=None)
            db.execute("INSERT INTO mail_settings VALUES(1,?,x'',1)",(json.dumps(mail),))
        private_log=stack.enter_context((root/'private-daemon.log').open('w'));http.block_once=True
        process=subprocess.Popen([str(binary),'--state',str(state),'--socket',str(api),'serve'],stdout=private_log,stderr=private_log)
        try:
            require(http.blocked.wait(5),'old poll did not reach controlled response')
            boots,now=clock(root,agent_port,sender);fault=packet(root,sender,boots,now,'1.3.6.1.4.1.674.10892.5.3.2.1.0.2153')
            destination=('127.0.0.1',port)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as origin:
                def is_fault():return rows(state,'SELECT health FROM alarm_state WHERE device=? AND key=?',('p4',FAN))==[('"critical"',)]
                wait_for(lambda:(origin.sendto(fault,destination),is_fault())[1],'verified mapped trap did not raise provisional fault',timeout=5)
                require(rows(state,'SELECT last_poll FROM devices')[0][0]==before_poll,'trap rewrote last poll')
                evidence=json.loads(rows(state,'SELECT data FROM observation_evidence WHERE key=?',(FAN,))[0][0]);require(evidence['provisional'] and evidence['active'],'provisional evidence missing')
                results.append('actual-verified-fqdd-trap-raises-partial-canonical-alarm')
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as other:other.sendto(fault,destination)
                http.health='Critical';http.release.set()
                wait_for(lambda:any(o['key']==FAN and o['health']=='unknown' for o in json.loads(rows(state,'SELECT snapshot FROM devices')[0][0])['observations']),'old poll completion')
                time.sleep(.2);require(is_fault(),'older poll OK cleared newer fault')
                results.append('older-inflight-redfish-ok-cannot-clear-newer-trap')
                wait_for(lambda:len(smtp.messages)==1,'initial trap email missing',timeout=8)
                wait_for(lambda:not json.loads(rows(state,'SELECT data FROM observation_evidence WHERE key=?',(FAN,))[0][0])['provisional'],'confirming RF poll did not confirm',timeout=18)
                require(len(smtp.messages)==1,'confirming poll duplicated initial submission')
                require(rows(state,"SELECT COUNT(*) FROM events WHERE key=? AND kind='alarm'",(FAN,))[0][0]==1,'canonical alarm duplicated')
                results.append('independent-smtp-once-for-trap-and-confirming-primary-poll')
                recovery=packet(root,sender,boots,now+1,'1.3.6.1.4.1.674.10892.5.3.2.1.0.2155')
                try:
                    wait_for(lambda:(origin.sendto(recovery,destination),any(json.loads(r[0]).get('handling')=='recovery_pending' for r in rows(state,'SELECT data FROM snmp_receipts')))[1],'recovery evidence missing')
                except AssertionError:
                    # Only normalized synthetic fixture metadata; never credentials,
                    # raw packets, private process output or device configuration.
                    print(json.dumps({'diagnostic_receipts':[{k:v for k,v in json.loads(r[0]).items() if k in ('trap_oid','verified','handling','component_key','version')} for r in rows(state,'SELECT data FROM snmp_receipts')], 'identity_rows':[json.loads(r[0]) for r in rows(state,'SELECT data FROM component_identity')], 'evidence_rows':[json.loads(r[0]) for r in rows(state,'SELECT data FROM observation_evidence')]}),flush=True)
                    raise
                require(is_fault(),'recovery trap cleared canonical fault');require(len(smtp.messages)==1,'recovery trap generated notification')
                http.health='OK';require(run(binary,state,'poll-once').returncode==0,'fresh primary recovery poll failed')
                wait_for(lambda:len(smtp.messages)==2,'confirmed recovery email missing')
                require(rows(state,'SELECT health FROM alarm_state WHERE key=?',(FAN,))==[('"ok"',)],'fresh primary OK did not recover')
                results.append('recovery-trap-is-hint-and-fresh-primary-ok-recovers-once')
                http.health='Critical';origin.sendto(fault,destination)  # identical first payload/uptime, within 30 seconds
                wait_for(is_fault,'fault/recovery/fault was lost in duplicate window')
                wait_for(lambda:len(smtp.messages)==3,'new fault occurrence email missing')
                results.append('fault-recovery-fault-with-identical-payload-preserved')
                if args.load_seconds:
                    pool=[packet(root,sender,boots,now+1,'1.3.6.1.4.1.674.10892.5.3.2.1.0.2153',2000+i) for i in range(64)]
                    bad=packet(root,dict(sender,auth_password=secrets.token_hex(12)),boots,now+1,'1.3.6.1.4.1.674.10892.5.3.2.1.0.2153',3000)
                    stop=threading.Event();valid_enabled=threading.Event();stack.callback(stop.set);sent=[0]
                    def flood():
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as known, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as unknown:
                            unknown.bind(('127.0.0.2',0));i=0
                            while not stop.wait(.1):
                                if valid_enabled.is_set():known.sendto(pool[i%len(pool)],destination);sent[0]+=1
                                if i%2==0:known.sendto(bad,destination);sent[0]+=1
                                for _ in range(8 if i%2==0 else 9):unknown.sendto(b'unknown-source',destination);sent[0]+=1
                                i+=1
                    thread=threading.Thread(target=flood,daemon=True);thread.start()
                    # Prove submissions progress under the same flood, then add
                    # sustained valid fault input without additional transitions.
                    http.health='OK';require(run(binary,state,'poll-once').returncode==0,'recovery unavailable under load')
                    wait_for(lambda:len(smtp.messages)==4,'recovery delivery stalled under load',timeout=8)
                    http.health='Critical';origin.sendto(fault,destination)  # primary recovery, no normal-state trap; same payload again
                    wait_for(is_fault,'fault input unavailable under load');valid_enabled.set()
                    wait_for(lambda:len(smtp.messages)==5,'fault delivery stalled under load',timeout=8)
                    poll_before=rows(state,'SELECT last_poll FROM devices')[0][0];cpu_before,rss_peak=resources(process.pid);latencies=[];api_latencies=[];end=time.monotonic()+args.load_seconds
                    while time.monotonic()<end:
                        at=time.monotonic();require(run(binary,state,'snapshot').returncode==0,'snapshot unavailable under load');latencies.append(time.monotonic()-at)
                        at=time.monotonic();denied_api(api);api_latencies.append(time.monotonic()-at);rss_peak=max(rss_peak,resources(process.pid)[1]);time.sleep(.1)
                    stop.set();thread.join(timeout=2);cpu_after,_=resources(process.pid)
                    require(rows(state,'SELECT last_poll FROM devices')[0][0]>poll_before,'automatic primary polls did not advance under load')
                    require(len(smtp.messages)==5,'repeated valid faults duplicated submission under load')
                    require(max(latencies)<3 and max(api_latencies)<3,'API responsiveness exceeded load limit')
                    results.append(dict(case='valid-invalid-unknown-source-load-with-live-polls-api-and-smtp',seconds=args.load_seconds,packets=sent[0],max_snapshot_seconds=max(latencies),max_denied_api_seconds=max(api_latencies),daemon_cpu_seconds=cpu_after-cpu_before,peak_rss_kib=rss_peak,smtp_submissions=5))
                require(process.poll() is None,'daemon exited during P4 checks')
        finally:
            http.release.set();process.terminate();process.wait(timeout=10)
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps({'reference':'actual product daemon / Net-SNMP / controlled HTTPS / local SMTP','cases':results},indent=2)+'\n');print(f'Actual daemon P4 checks passed: {len(results)} cases')

if __name__=='__main__':main()
