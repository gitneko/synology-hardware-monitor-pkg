#!/usr/bin/env python3
"""Local TLS Redfish integration. Synthetic data; never connects to real equipment."""
import base64
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "target/debug/hardware-monitor"
VERSION = subprocess.check_output([str(BINARY), "--version"], text=True).strip().split()[-1]
state = {"storage_failures": 0, "storage_forced_status": 0, "fan_state": "Enabled", "health": "Critical", "storage": True, "log": "old", "redirect": False, "reject": False}
requests = []
HPE_STORAGE = {item['uri']: item['body'] for item in json.loads((ROOT/'tests/fixtures/hpe-smartstorage-hierarchy.json').read_text())['resources']}
HPE_APPLICABILITY = {item['uri']: item['body'] for item in json.loads((ROOT/'tests/fixtures/hpe-applicability.json').read_text())['resources']}
HPE_CONTROLLER = '/redfish/v1/Systems/1/SmartStorage/ArrayControllers/2/'
HPE_FAILED = HPE_CONTROLLER + 'DiskDrives/0/'
state['hpe_storage'] = False
SESSION_TOKEN = 'synthetic-standard-session-token'
state.update(sessions=False, session_active=False, session_posts=0, session_deletes=0, session_redirect=False, session_collection='/redfish/v1/Sessions', session_location='/redfish/v1/Sessions/owned')

class Mock(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        requests.append(self.path)
        if self.headers.get("Authorization") != "Basic " + base64.b64encode(b"monitor:integration-secret").decode() and not (state['session_active'] and self.headers.get('X-Auth-Token')==SESSION_TOKEN):
            self.send_error(401); return
        if state["reject"]:
            self.send_error(401); return
        if self.path == "/redfish/v1/":
            self.send_response(308)
            self.send_header("Location", "https://example.invalid/redfish/v1/" if state["redirect"] else "/redfish/v1/root/")
            self.end_headers(); return
        data = {
            "/redfish/v1/root/": {"Systems": {"@odata.id": "/redfish/v1/Systems"},"Chassis":{"@odata.id":"/redfish/v1/Chassis"}},
            "/redfish/v1/Chassis":{"Members":[{"@odata.id":"/redfish/v1/Chassis/Test"}]},
            "/redfish/v1/Chassis/Test":{"Power":{"@odata.id":"/redfish/v1/Chassis/Test/Power"},"PowerSubsystem":{"@odata.id":"/redfish/v1/Chassis/Test/PowerSubsystem"}},
            "/redfish/v1/Chassis/Test/Power":{"PowerSupplies":[{"@odata.id":"/redfish/v1/Chassis/Test/Power#/PowerSupplies/0","@odata.type":"#Power.v1_7_1.PowerSupply","Name":"PS1 Status","SerialNumber":"SYNTHETIC-PS1","Status":{"Health":"Critical","State":"UnavailableOffline"}}]},
            "/redfish/v1/Chassis/Test/PowerSubsystem":{"PowerSupplies":{"@odata.id":"/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies"}},
            "/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies":{"Members":[{"@odata.id":"/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies/PSU.Slot.1"}]},
            "/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies/PSU.Slot.1":{"@odata.id":"/redfish/v1/Chassis/Test/PowerSubsystem/PowerSupplies/PSU.Slot.1","@odata.type":"#PowerSupply.v1_5_0.PowerSupply","Name":"PS1 Status","SerialNumber":"SYNTHETIC-PS1","Status":{"Health":"Critical","State":"UnavailableOffline"}},
            "/redfish/v1/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/NonNumeric"}], "Members@odata.nextLink": "/redfish/v1/Systems?$skip=1"},
            "/redfish/v1/Systems?$skip=1": {"Members": []},
            "/redfish/v1/Systems/NonNumeric": {"Name": "Synthetic server", "Status": {"Health": "OK"}, "Storage": {"@odata.id": "/redfish/v1/Systems/NonNumeric/Storage"}, "Thermal": {"@odata.id": "/redfish/v1/Chassis/A/Thermal"}, "LogServices": {"@odata.id": "/redfish/v1/Systems/NonNumeric/LogServices"}},
            "/redfish/v1/Systems/NonNumeric/Storage": {"Members": []},
            "/redfish/v1/Chassis/A/Thermal": {"Fans": [{"MemberId": "FanA", "Name": "Fan A", "Status": {"Health": state["health"], "State": state["fan_state"]}, "Reading": 32, "ReadingUnits": "Percent"}]},
            "/redfish/v1/Systems/NonNumeric/LogServices": {"Members": [{"@odata.id": "/redfish/v1/Systems/NonNumeric/LogServices/IML"}]},
            "/redfish/v1/Systems/NonNumeric/LogServices/IML": {"Entries": {"@odata.id": "/redfish/v1/Systems/NonNumeric/LogServices/IML/Entries"}},
            "/redfish/v1/Systems/NonNumeric/LogServices/IML/Entries": {"Members": [{"Id": state["log"], "Message": "Synthetic historical fault", "Severity": "Critical", "EntryType": "Event", "Created": "2026-10-17T12:00:00Z"}]},
        }
        if self.path.endswith("/Storage") and (state["storage_failures"] or state["storage_forced_status"]):
            if state["storage_failures"]: state["storage_failures"] -= 1
            self.send_error(state["storage_forced_status"] or 500); return
        if not state["storage"] and self.path.endswith("/Storage"):
            self.send_error(403); return
        if state['hpe_storage']:
            data.update(HPE_STORAGE)
            data['/redfish/v1/root/'] = {'Systems': {'@odata.id': '/redfish/v1/Systems/'}, 'Chassis': {'@odata.id': '/redfish/v1/Chassis/'}}
            # The selected fixture excludes unrelated inventories.
            data['/redfish/v1/Systems/1/'] = json.loads(json.dumps(data['/redfish/v1/Systems/1/']))
            for name in ['Storage', 'LogServices']:
                data['/redfish/v1/Systems/1/'].pop(name, None)
            data['/redfish/v1/Chassis/1/'] = json.loads(json.dumps(data['/redfish/v1/Chassis/1/']))
            for name in ['Thermal', 'Power']:
                data['/redfish/v1/Chassis/1/'].pop(name, None)
            data.update(HPE_APPLICABILITY)
            data['/redfish/v1/Systems/1/']['Storage'] = {'@odata.id': '/redfish/v1/Systems/1/Storage/'}
            for name in ['Thermal','Power']:
                data['/redfish/v1/Chassis/1/'][name] = {'@odata.id': f'/redfish/v1/Chassis/1/{name}/'}
        if self.path not in data:
            self.send_error(404); return
        if state['sessions'] and self.path == '/redfish/v1/root/':
            data[self.path]['Links'] = {'Sessions': {'@odata.id': state['session_collection']}}
        payload = json.dumps(data[self.path]).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)

    def do_POST(self):
        assert self.path == state['session_collection']
        state['session_posts'] += 1
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body == {'UserName':'monitor','Password':'integration-secret'}
        self.send_response(307 if state['session_redirect'] else 201)
        self.send_header('Location','/redfish/v1/Chassis' if state['session_redirect'] else state['session_location'])
        self.send_header('X-Auth-Token',SESSION_TOKEN)
        self.send_header('Content-Length','2')
        self.end_headers(); self.wfile.write(b'{}')
        state['session_active'] = not state['session_redirect']

    def do_DELETE(self):
        assert self.path == state['session_location']
        assert self.headers.get('X-Auth-Token') == SESSION_TOKEN
        state['session_deletes'] += 1
        state['session_active'] = False
        self.send_response(204); self.send_header('Content-Length','0'); self.end_headers()

with tempfile.TemporaryDirectory(prefix="hardware-monitor-test-") as temp:
    temp = Path(temp)
    def openssl(*args):
        subprocess.run(["openssl", *args], check=True, capture_output=True)
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Integration CA", "-keyout", str(temp/"ca.key"), "-out", str(temp/"ca.crt"))
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(temp/"server.key"), "-out", str(temp/"server.csr"))
    (temp/"ext.cnf").write_text("subjectAltName=DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    openssl("x509", "-req", "-days", "1", "-in", str(temp/"server.csr"), "-CA", str(temp/"ca.crt"), "-CAkey", str(temp/"ca.key"), "-CAcreateserial", "-extfile", str(temp/"ext.cnf"), "-out", str(temp/"server.crt"))
    server = ThreadingHTTPServer(("127.0.0.1", 0), Mock)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(temp / "server.crt", temp / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    config = {"id": "ilo-test", "name": "Synthetic iLO", "endpoint": f"https://localhost:{server.server_port}/", "username": "monitor", "interval_seconds": 30, "repeat_seconds": None, "alerts_enabled": True, "ca_file": str(temp / "ca.crt")}
    config_file = temp / "device.json"
    def run(*args, password=None, success=True, env=None):
        p = subprocess.run([str(BINARY), "--state", str(temp / "private"), "--socket", str(temp / "api.sock"), *args], input=password, capture_output=True, env=env)
        assert (p.returncode == 0) == success, (args, p.stderr.decode())
        assert b"integration-secret" not in p.stdout + p.stderr
        assert SESSION_TOKEN.encode() not in p.stdout + p.stderr
        return p.stdout
    def put():
        config_file.write_text(json.dumps(config))
        run("device-put", "--file", str(config_file), password=b"integration-secret\n")
    def snapshot():
        return json.loads(run("snapshot"))
    try:
        # Self-signed server is rejected until its CA is explicitly trusted.
        config["ca_file"] = None; put(); run("poll-once", success=False)
        assert snapshot()["events"][0]["kind"] == "alarm"
        # Connection test refuses unknown trust and performs no collection or writes.
        config_file.write_text(json.dumps(config))
        run("device-test", "--file", str(config_file), password=b"integration-secret\n", success=False)
        config["ca_file"] = str(temp / "ca.crt"); put()
        requests.clear()
        root_test = json.loads(run("device-test", "--file", str(config_file), password=b"integration-secret\n"))
        assert root_test["reachable"] is True and root_test["systems"] is True
        assert root_test["checked_collections"] == 2
        assert requests == ["/redfish/v1/", "/redfish/v1/root/", "/redfish/v1/Systems", "/redfish/v1/Chassis"]
        state['sessions'] = True
        run('device-test','--file',str(config_file),password=b'integration-secret\n')
        assert state['session_posts']==state['session_deletes']==1 and not state['session_active']
        for collection_slash in ['', '/']:
            for resource_slash in ['', '/']:
                state['session_collection'] = '/redfish/v1/SessionService/Sessions' + collection_slash
                state['session_location'] = '/redfish/v1/SessionService/Sessions/owned' + resource_slash
                before = state['session_deletes']
                run('device-test','--file',str(config_file),password=b'integration-secret\n')
                assert state['session_deletes'] == before + 1 and not state['session_active']
        state['session_collection'] = '/redfish/v1/Sessions'
        state['session_location'] = '/redfish/v1/Sessions/owned'
        state['session_redirect'] = True
        requests.clear()
        run('device-test','--file',str(config_file),password=b'integration-secret\n',success=False)
        assert requests == ['/redfish/v1/','/redfish/v1/root/']
        state['sessions'] = state['session_redirect'] = False
        # Web-imported PEM trust takes the same strict TLS path as CLI CA files.
        inline = {**config, "ca_file": None, "ca_pem": (temp/"ca.crt").read_text()}
        config_file.write_text(json.dumps(inline))
        run("device-test", "--file", str(config_file), password=b"integration-secret\n")
        state["reject"] = True
        run("device-test", "--file", str(config_file), password=b"integration-secret\n", success=False)
        state["reject"] = False; state["redirect"] = True
        run("device-test", "--file", str(config_file), password=b"integration-secret\n", success=False)
        state["redirect"] = False
        run("poll-once")
        initial = snapshot()
        ps1=initial["devices"][0]["snapshot"]
        assert len([o for o in ps1["observations"] if o["label"]=="PS1 Status"])==1
        assert len(ps1["resource_aliases"])==1
        assert len([a for a in initial["devices"][0]["alarms"] if a["label"]=="PS1 Status"])==1
        assert len([e for e in initial["events"] if "PS1 Status" in e["message"]])==1

        assert not any(e["kind"] == "hardware_log" for e in initial["events"])
        assert any("?$skip=1" in p for p in requests)
        assert any("NonNumeric" in c["uri"] for c in initial["devices"][0]["snapshot"]["capabilities"])
        count = len(initial["events"]); run("poll-once"); assert len(snapshot()["events"]) == count
        # Retry a transient server failure once without a false coverage alarm.
        state["storage_failures"] = 1; requests.clear(); run("poll-once")
        retried = next(c for c in snapshot()["devices"][0]["snapshot"]["capabilities"] if c["uri"].endswith("/Storage"))
        assert retried["outcome"] == "available" and retried["attempts"] == 2 and retried["http_status"] == 200
        assert sum(p.endswith("/Storage") for p in requests) == 2
        assert len(snapshot()["events"]) == count
        # Persistent failures remain visible with actual status and bounded attempts.
        state["storage_forced_status"] = 500; requests.clear(); run("poll-once")
        failed = next(c for c in snapshot()["devices"][0]["snapshot"]["capabilities"] if c["uri"].endswith("/Storage"))
        assert failed["http_status"] == 500 and failed["attempts"] == 2
        assert sum(p.endswith("/Storage") for p in requests) == 2
        assert any(e["key"].startswith("coverage:") and "HTTP 500" in e["message"] and e["device_name"] == config["name"] for e in snapshot()["events"])
        state["storage_forced_status"] = 0; run("poll-once"); count = len(snapshot()["events"])
        # An explicit Critical remains an alarm while the failed component is offline.
        state["fan_state"] = "UnavailableOffline"; run("poll-once")
        offline = snapshot()["devices"][0]
        assert any(o["health"] == "critical" and o["label"] == "Fan A" and o["reading"] is None for o in offline["snapshot"]["observations"])
        assert any(a["health"] == "critical" and a["label"] == "Fan A" for a in offline["alarms"])
        assert len(snapshot()["events"]) == count
        state["fan_state"] = "Enabled"
        # Partial coverage produces its own warning and retains the existing fan fault.
        state["storage"] = False; state["health"] = "Unknown"; requests.clear(); run("poll-once")
        partial = snapshot()
        assert sum(p.endswith("/Storage") for p in requests) == 1  # no retry on 403
        assert any(a["health"] == "critical" and a["label"] == "Fan A" for a in partial["devices"][0]["alarms"])
        assert any(c["outcome"] == "forbidden_permission_or_license" for c in partial["devices"][0]["snapshot"]["capabilities"])
        state["storage"] = True; state["health"] = "OK"; state["log"] = "new"; run("poll-once")
        recovered = snapshot()
        assert any(e["kind"] == "recovery" and "Fan A" in e["message"] for e in recovered["events"])
        assert sum(e["kind"] == "hardware_log" for e in recovered["events"]) == 1
        assert next(e for e in recovered["events"] if e["kind"] == "hardware_log")["source_created"] == "2026-10-17T12:00:00Z"
        state["redirect"] = True; run("poll-once", success=False); state["redirect"] = False
        state["reject"] = True; run("poll-once", success=False); state["reject"] = False
        for path in (temp / "private").glob("*"):
            assert path.stat().st_mode & 0o077 == 0
            if path.is_file(): assert b"integration-secret" not in path.read_bytes()
        run("backup", "--directory", str(temp/"backup"))
        with sqlite3.connect(temp/"backup/monitor.db") as backup:
            assert backup.execute("SELECT count(*) FROM devices").fetchone()[0] == 1
        assert (temp/"backup/master.key").read_bytes() == (temp/"private/master.key").read_bytes()
        (temp/"private/master.key").rename(temp/"saved.key")
        run("snapshot", success=False)
        (temp/"saved.key").rename(temp/"private/master.key")
        # Exercise the real HTTPS walker, persistence and derived assessment on
        # the sanitized HPE hierarchy, including both physical and DataDrives links.
        state['hpe_storage'] = True
        state['sessions'] = True
        before_logout = state['session_deletes']
        requests.clear()
        run('poll-once')
        hpe = snapshot()['devices'][0]
        assert hpe['overall_status'] == 'critical'
        assert all(c['outcome'] == 'available' for c in hpe['snapshot']['capabilities']), hpe['snapshot']['capabilities']
        assert HPE_FAILED in requests
        assert HPE_CONTROLLER + 'LogicalDrives/1/DataDrives/' in requests
        failed = next(o for o in hpe['snapshot']['observations'] if o['key'] == HPE_FAILED)
        assert failed['health'] == 'critical' and '1I:1:1' in failed['label']
        exclusions=hpe['snapshot']['assessment_exclusions']
        assert len(exclusions)==28
        assert list(exclusions.values()).count('absent')==23
        assert list(exclusions.values()).count('empty_controller')==4
        assert list(exclusions.values()).count('informational')==1
        assert HPE_FAILED not in exclusions
        assert all(o['key'] in exclusions for o in hpe['snapshot']['observations'] if o['health']=='unknown')
        for parent in ['/redfish/v1/Systems/1/', '/redfish/v1/Chassis/1/', '/redfish/v1/Systems/1/SmartStorage/', HPE_CONTROLLER, HPE_CONTROLLER + 'LogicalDrives/1/']:
            assert hpe['alarm_statuses'][parent]['derived']
            assert HPE_FAILED in hpe['alarm_statuses'][parent]['causes']
        assert not state['session_active'] and state['session_deletes'] == before_logout + 1
        state['hpe_storage'] = state['sessions'] = False
        run("service", "start")
        run("service", "status")
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5); client.connect(str(temp / "api.sock"))
            body = b'{"auth":{"environment":{}}}'; client.sendall(struct.pack(">I", len(body)) + body)
            size = struct.unpack(">I", client.recv(4))[0]
            response = b""
            while len(response) < size: response += client.recv(size - len(response))
            assert json.loads(response)["ok"] is False
        cgi = run("cgi", env={**os.environ, "REQUEST_METHOD": "GET"})
        assert b"Status: 403 Forbidden" in cgi
        base_env={**os.environ,"REQUEST_METHOD":"GET","HTTP_COOKIE":""}
        probe=run("cgi",env={**base_env,"QUERY_STRING":"probe=1"})
        assert b"Status: 200 OK" in probe
        assert json.loads(probe.split(b"\r\n\r\n",1)[1])["code"] == "cgi_ready"
        diagnostic=run("cgi",env={**base_env,"QUERY_STRING":"diagnose=1"})
        assert b"Status: 200 OK" in diagnostic
        assert json.loads(diagnostic.split(b"\r\n\r\n",1)[1])["ok"] is False
        # A plausible-looking cookie must still pass the fixed native DSM helper.
        fake_env={**base_env,"HTTP_COOKIE":"id=private-cookie-test-marker","REMOTE_ADDR":"127.0.0.1","SERVER_ADDR":"127.0.0.1","HTTP_X_SYNO_TOKEN":"private-token-test-marker","QUERY_STRING":"diagnose=1"}
        diagnostic=run("cgi",env=fake_env)
        assert b"private-cookie-test-marker" not in diagnostic and b"private-token-test-marker" not in diagnostic
        body=json.loads(diagnostic.split(b"\r\n\r\n",1)[1])
        assert body["ok"] is False and body["code"] == "dsm_helper_unavailable"
        assert set(body)=={"ok","code","source","version"}
        # Standard CGI marker also dispatches correctly when argv[0] is not api.cgi.
        dispatched=subprocess.check_output([str(BINARY)],env={**base_env,"QUERY_STRING":"probe=1","GATEWAY_INTERFACE":"CGI/1.1"})
        assert b'"code":"cgi_ready"' in dispatched
        posted=run("cgi",env={**base_env,"REQUEST_METHOD":"POST","QUERY_STRING":"probe=1"})
        assert b"Status: 200 OK" in posted
        assert json.loads(posted.split(b"\r\n\r\n",1)[1])["code"]=="cgi_cookie_missing_or_invalid"
        run("service", "stop"); run("service", "status", success=False)
        # Even if a future daemon accidentally includes a dashboard in diagnostics,
        # the CGI must restrict its diagnostic response to the fixed envelope.
        with socket.socket(socket.AF_UNIX) as mock:
            mock.bind(str(temp/"api.sock"));mock.listen(1);mock.settimeout(5)
            received=[]
            def mock_reply():
                connection,_=mock.accept()
                with connection:
                    header=connection.recv(4);length=struct.unpack(">I",header)[0]
                    request=b""
                    while len(request)<length:request+=connection.recv(length-len(request))
                    received.append(json.loads(request))
                    payload=json.dumps({"ok":True,"code":"authenticated","data":{"secret":"must-never-leave"}}).encode()
                    connection.sendall(struct.pack(">I",len(payload))+payload)
            worker=threading.Thread(target=mock_reply);worker.start()
            diagnostic=run("cgi",env=fake_env);worker.join(6)
            assert not worker.is_alive() and received[0]["auth"]["diagnostic"] is True
            assert received[0]["auth"]["environment"]["HTTP_X_SYNO_TOKEN"] == "private-token-test-marker"
            assert b"must-never-leave" not in diagnostic
            assert json.loads(diagnostic.split(b"\r\n\r\n",1)[1])=={"ok":True,"code":"authenticated","source":"hardware-monitor","version":VERSION}
            # POST bodies and CGI-provided origin/HTTPS context survive the bridge.
            body={"csrf":"synthetic-package-token","operation":{"action":"save","device":{"id":None,"revision":None,"certificate_pem":None,"name":"Synthetic", "endpoint":"https://bmc.example/", "username":"monitor", "password":"integration-secret", "interval_seconds":60,"repeat_seconds":None,"alerts_enabled":False,"enabled":True,"trust_mode":"system"}}}
            payload=json.dumps(body).encode()
            post_env={**fake_env,"QUERY_STRING":"","REQUEST_METHOD":"POST","CONTENT_TYPE":"application/json","CONTENT_LENGTH":str(len(payload)),"HTTPS":"on","HTTP_HOST":"nas.example:5001","HTTP_ORIGIN":"https://nas.example:5001","HTTP_SEC_FETCH_SITE":"same-origin","HTTP_X_HARDWAREMONITOR_LANGUAGE":"en"}
            worker=threading.Thread(target=mock_reply);worker.start()
            posted=run("cgi",env=post_env,password=payload);worker.join(6)
            assert not worker.is_alive()
            forwarded=received[-1]
            assert forwarded["locale"]=="en"
            expected=json.loads(json.dumps(body["operation"]))
            expected["device"]["tls_profile"]="standard"
            snmp_defaults=dict(primary_protocol="redfish",snmp_poll=None,snmp_traps=None,snmp_secrets={"snmp_poll":{"action":"keep"},"snmp_traps":{"action":"keep"}})
            expected["device"].update(snmp_defaults)
            assert forwarded["csrf"]==body["csrf"] and forwarded["operation"]==expected
            assert forwarded["auth"]["environment"]["HTTP_ORIGIN"]==post_env["HTTP_ORIGIN"]
            assert forwarded["auth"]["environment"]["HTTPS"]=="on"
            assert b"Status: 200 OK" in posted
            # The new explicit profile and certificate survive the same bridge.
            pinned=json.loads(json.dumps(body))
            pinned["operation"]["device"].update(tls_profile="idrac7",trust_mode="pinned",certificate_pem=(temp/"ca.crt").read_text())
            payload=json.dumps(pinned).encode();post_env["CONTENT_LENGTH"]=str(len(payload))
            worker=threading.Thread(target=mock_reply);worker.start()
            posted=run("cgi",env=post_env,password=payload);worker.join(6)
            pinned_expected=json.loads(json.dumps(pinned["operation"]))
            pinned_expected["device"].update(snmp_defaults)
            assert not worker.is_alive() and received[-1]["operation"]==pinned_expected
            # Protocol configuration and secret actions survive the same typed bridge.
            snmp_body={"csrf":body["csrf"],"operation":{"action":"save","device":{"id":None,"revision":None,"name":"Synthetic SNMP","primary_protocol":"snmp","snmp_poll":{"host":"::1","security":{"version":"v1"}},"snmp_secrets":{"snmp_poll":{"action":"replace","credentials":{"kind":"community","community":"synthetic-snmp-community"}}},"interval_seconds":60,"repeat_seconds":None,"alerts_enabled":False,"enabled":False}}}
            payload=json.dumps(snmp_body).encode();post_env["CONTENT_LENGTH"]=str(len(payload))
            worker=threading.Thread(target=mock_reply);worker.start()
            posted=run("cgi",env=post_env,password=payload);worker.join(6)
            assert not worker.is_alive()
            forwarded_device=received[-1]["operation"]["device"]
            assert forwarded_device["primary_protocol"]=="snmp" and forwarded_device["endpoint"]==""
            assert forwarded_device["snmp_poll"]["security"]=={"version":"v1"}
            assert forwarded_device["snmp_secrets"]=={"snmp_poll":snmp_body["operation"]["device"]["snmp_secrets"]["snmp_poll"],"snmp_traps":{"action":"keep"}}
            # Explicit, incident-bound reset survives the same CGI bridge.
            reset={"csrf":"synthetic-package-token","operation":{"action":"alarm_reset","id":"synthetic-device","revision":1,"key":"/redfish/v1/Chassis/1/Power/#PowerSupplies/1","token":"synthetic-incident-token","confirm":True}}
            payload=json.dumps(reset).encode();post_env["CONTENT_LENGTH"]=str(len(payload))
            worker=threading.Thread(target=mock_reply);worker.start()
            posted=run("cgi",env=post_env,password=payload);worker.join(6)
            assert not worker.is_alive() and received[-1]["operation"]==reset["operation"]
            # A backup larger than the normal form limit crosses the CGI bridge;
            # regular device forms retain their strict 128 KiB limit.
            backup={"csrf":"synthetic-package-token","operation":{"action":"backup_inspect","file":"A"*(200*1024),"password":"synthetic-backup-password"}}
            payload=json.dumps(backup).encode();post_env["CONTENT_LENGTH"]=str(len(payload))
            worker=threading.Thread(target=mock_reply);worker.start()
            posted=run("cgi",env=post_env,password=payload);worker.join(6)
            assert not worker.is_alive() and received[-1]["operation"]==backup["operation"]
            body["operation"]["device"]["name"]="X"*(200*1024)
            payload=json.dumps(body).encode();post_env["CONTENT_LENGTH"]=str(len(payload))
            rejected=run("cgi",env=post_env,password=payload)
            assert json.loads(rejected.split(b"\r\n\r\n",1)[1])["code"]=="write_body_invalid"
        (temp/"api.sock").unlink()

        print("PASS: TLS trust/rejection, safe 308 redirects, pagination, discovery, unknown/partial coverage, alarm dedup/recovery, log baseline/dedup, encrypted storage, daemon lifecycle, unauthenticated API/CGI denial and redacted diagnostics; large backup CGI forwarding with ordinary form size limits")
    finally:
        run("service", "stop")
        server.shutdown(); thread.join()
