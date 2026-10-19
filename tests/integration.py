#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Real Varlink/XFRM lifecycle tests. Run in a disposable network namespace."""
import copy
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

class Varlink:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(path)
        self.pending = b""
    def receive(self):
        while b"\0" not in self.pending:
            b = self.socket.recv(4096)
            if not b: raise EOFError("Varlink peer disconnected")
            self.pending += b
            assert len(self.pending) <= 131072
        frame, self.pending = self.pending.split(b"\0", 1)
        return json.loads(frame)
    def send(self, method, parameters=None, more=False):
        self.socket.sendall(json.dumps(dict(method=method, parameters=parameters or {}, **({"more": True} if more else {}))).encode() + b"\0")
    def call(self, method, parameters=None):
        self.send(method if "." in method else "io.ranet.Kernel." + method, parameters)
        return self.receive()

def endpoint(address="192.0.2.1", port=13000): return dict(address=address, port=port)
def sa_id(spi=0x10203, interface=41):
    return dict(src=endpoint(), dst=endpoint("192.0.2.2"), spi=spi, mark=dict(value=0, mask=0), interfaceId=interface)
def sa_config(life=0, inbound=False, update=False):
    return dict(reqid=42, acquireSequence=0, encryption=dict(id=20, name="", key="00"*20),
        integrity=dict(id=1024, name="", key=""),
        lifetime=dict(timeLife=life, timeRekey=max(0,life-1), byteLife="0", byteRekey="0", packetLife="0", packetRekey="0"),
        replayWindow=128, esn=True, udpEncapsulation=True, outputMark=dict(value=123, mask=0xffffffff),
        tfc=0, copyDf=True, copyEcn=True, copyDscp=0, inbound=inbound, update=update)
def selector(v6=False):
    return dict(**{"from": "::" if v6 else "0.0.0.0", "to": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" if v6 else "255.255.255.255"}, protocol=0, fromPort=0, toPort=65535)
def policy(interface=41, direction=1, v6=False):
    return dict(direction=direction, src=selector(v6), dst=selector(v6), mark=dict(value=0,mask=0), interfaceId=interface)
def policy_config(spi=0x10203):
    return dict(kind=1, priority=1, manualPriority=0, src=endpoint(), dst=endpoint("192.0.2.2"), reqid=42, policyCount=2, espSpi=spi)

def client(path):
    status = Path("/proc/self/status").read_text()
    assert os.geteuid() == 65534
    for cap in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]: assert f"{cap}:\t0000000000000000" in status
    control = Varlink(path)
    opened = control.call("OpenSession", dict(interfacesUse="", interfacesIgnore=""))
    token = opened["parameters"]["token"]
    watch = Varlink(path); watch.send("io.ranet.Kernel.WatchEvents", dict(token=token), more=True)
    assert watch.receive()["parameters"]["event"]["kind"] == "ready"
    print(json.dumps(opened), flush=True)
    for line in sys.stdin:
        req = json.loads(line)
        if "collect" in req:
            collected = []
            deadline = time.monotonic() + req["collect"]
            watch.socket.settimeout(0.05)
            try:
                while time.monotonic() < deadline:
                    try: collected.append(watch.receive()["parameters"]["event"])
                    except socket.timeout: pass
            finally:
                watch.socket.settimeout(10)
            reply = {"parameters": {"events": collected}}
        elif "event" in req:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                reply = watch.receive()
                if reply.get("parameters", {}).get("event", {}).get("kind") == req["event"]:
                    break
            else: raise AssertionError("event timed out")
        elif req.get("other"):
            other = Varlink(path); reply = other.call(req["method"], req.get("parameters")); other.socket.close()
        else: reply = control.call(req["method"], req.get("parameters"))
        print(json.dumps(reply), flush=True)
        if req.get("method") == "CloseSession" and "error" not in reply: break
    watch.socket.close(); control.socket.close()

def run(binary):
    assert os.geteuid() == 0
    assert os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino, "use unshare --net"
    binary = str(Path(binary).resolve())
    def ip(*args): return subprocess.check_output(["ip", *map(str,args)], text=True)
    def links(): return json.loads(ip("-j", "-d", "link", "show", "type", "xfrm"))
    def states(): return ip("xfrm", "state")
    def wait(predicate):
        for _ in range(200):
            if predicate(): return
            time.sleep(.05)
        assert predicate(), "condition timed out"
    ip("link", "set", "lo", "up")
    ip("link", "add", "underlay", "type", "dummy")
    ip("link", "set", "underlay", "up")
    ip("addr", "add", "192.0.2.1/24", "dev", "underlay")
    ip("-6", "addr", "add", "2001:db8:1::1/64", "dev", "underlay", "nodad")
    ip("link", "add", "foreign", "type", "xfrm", "if_id", 77)
    ip("xfrm", "state", "add", "src", "192.0.2.10", "dst", "192.0.2.11", "proto", "esp", "spi", "0xaaaa", "mode", "tunnel", "aead", "rfc4106(gcm(aes))", "0x"+"00"*20, "128")
    with tempfile.TemporaryDirectory(prefix="kernel-rust-rpc-") as d:
        directory = Path(d); directory.chmod(0o755); path = str(directory / "kernel.sock")
        with open(directory/"daemon.log", "w+") as log:
            daemon = subprocess.Popen([binary,"--socket",path,"--group","65534"], stdout=log, stderr=log)
            child = None
            try:
                wait(lambda: Path(path).exists() or daemon.poll() is not None)
                assert daemon.poll() is None
                info = os.stat(path)
                assert info.st_uid == 0 and info.st_gid == 65534 and info.st_mode & 0o777 == 0o660
                # No UID or primary/supplementary group matching the socket:
                # Linux must reject the connection before any RPC is sent.
                subprocess.run([
                    "setpriv", "--reuid=65533", "--regid=65533", "--clear-groups",
                    "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                    sys.executable, "-c", "import socket, sys\n"
                    "try:\n socket.socket(socket.AF_UNIX).connect(sys.argv[1])\n"
                    "except PermissionError:\n pass\n"
                    "else:\n raise AssertionError('unauthorized client connected')\n", path,
                ], check=True)
                if shutil.which("varlinkctl"):
                    desc = subprocess.check_output(["varlinkctl","introspect",path,"io.ranet.Kernel"],text=True)
                    assert "InstallSa" in desc and "WatchEvents" in desc
                client_file = directory / "client.py"; client_file.write_text(Path(__file__).read_text()); client_file.chmod(0o644)
                child = subprocess.Popen(["setpriv","--reuid=65534","--regid=65534","--clear-groups","--bounding-set=-all","--inh-caps=-all","--ambient-caps=-all",sys.executable,str(client_file),"--client",path], stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
                assert "token" in json.loads(child.stdout.readline())["parameters"]
                def raw(method=None, parameters=None, **kwargs):
                    child.stdin.write(json.dumps(dict(method=method,parameters=parameters or {},**kwargs))+"\n"); child.stdin.flush()
                    line = child.stdout.readline(); assert line, "client exited"; return json.loads(line)
                def rpc(method, **parameters):
                    reply = raw(method, parameters); assert "error" not in reply, reply; return reply.get("parameters",{})
                def failure(method, err, **parameters):
                    reply = raw(method,parameters); assert reply == {"error":"io.ranet.Kernel.KernelError","parameters":{"errno":err}}, reply
                assert raw("OpenSession",dict(interfacesUse="",interfacesIgnore=""),other=True)["error"].endswith("SessionBusy")
                assert raw("FlushSas",other=True)["error"].endswith("InvalidSession")
                assert raw("UnknownMethod")["error"] == "org.varlink.service.MethodNotFound"
                assert raw("AllocateSpi",dict(src=endpoint()))["error"] == "org.varlink.service.InvalidParameter"
                rpc("BypassPort",family=2,port=13000); rpc("BypassPort",family=10,port=13000)
                failure("BypassPort",errno.EINVAL,family=2,port=500)
                assert len(ip("xfrm","policy","list").split("priority 32")) == 5
                for destination, source, gateway in [
                    ("203.0.113.2", "192.0.2.1", "192.0.2.254"),
                    ("2001:db8:2::2", "2001:db8:1::1", "2001:db8:1::fe"),
                ]:
                    family = ["-6"] if ":" in destination else []
                    ip(*family, "route", "add", destination, "via", gateway, "dev", "underlay")
                    assert rpc("GetSourceAddress", destination=endpoint(destination))["address"]["address"] == source
                    assert rpc("GetSourceAddress", destination=endpoint(destination), source=endpoint(source))["address"]["address"] == source
                    route = rpc("GetNextHop", destination=endpoint(destination))
                    assert route["gateway"]["address"] == gateway and route["interface"] == "underlay", route
                    replacement = "2001:db8:1::fd" if family else "192.0.2.253"
                    ip(*family, "route", "replace", destination, "via", replacement, "dev", "underlay")
                    assert rpc("GetNextHop", destination=endpoint(destination))["gateway"]["address"] == replacement
                failure("GetNextHop", errno.EOPNOTSUPP, destination=endpoint("203.0.113.2"), prefix=24)
                ip("link", "set", "foreign", "up")
                ip("route", "add", "192.0.2.2/32", "dev", "foreign")
                failure("GetSourceAddress", errno.ENETUNREACH, destination=endpoint("192.0.2.2"))
                ip("route", "del", "192.0.2.2/32")
                ip("route", "add", "unreachable", "default", "table", "100")
                ip("rule", "add", "to", "203.0.113.0/24", "lookup", "100", "priority", "100")
                failure("GetSourceAddress", errno.EHOSTUNREACH, destination=endpoint("203.0.113.2"))
                ip("rule", "del", "priority", "100")
                ip("route", "flush", "table", "100")
                # A route burst must not flood WatchEvents, lose address
                # changes, or make its control session unusable.
                child.stdin.write(json.dumps({"collect": 1}) + "\n"); child.stdin.flush()
                ip("addr", "add", "192.0.2.3/24", "dev", "underlay")
                batch = "".join(f"route add 172.17.{i // 256}.{i % 256}/32 dev underlay table 1234\n" for i in range(1000))
                subprocess.run(["ip", "-batch", "-"], input=batch, text=True, check=True)
                events = json.loads(child.stdout.readline())["parameters"]["events"]
                assert 0 < len(events) < 50, len(events)
                assert any(e["kind"] == "roam" and e["addressChanged"] for e in events), events
                assert rpc("GetInterface", address=endpoint())["interface"] == "underlay"
                assert rpc("GetInterface", address=endpoint("192.0.2.3"))["interface"] == "underlay"
                ip("route", "flush", "table", "1234")
                failure("InstallSa",errno.EINVAL,id=sa_id(interface=0),config=sa_config())
                failure("InstallSa",errno.EEXIST,id=sa_id(interface=77),config=sa_config())
                bad = sa_config(); bad["encryption"]["id"] = 65535
                failure("InstallSa",errno.EOPNOTSUPP,id=sa_id(interface=90),config=bad)
                assert [l["ifname"] for l in links()] == ["foreign"]
                a,b = sa_id(),sa_id(spi=0x10204)
                rpc("InstallSa",id=a,config=sa_config()); link = next(l for l in links() if l["ifname"] == "ranet00000029")
                assert link["mtu"] == 1400 and "UP" in link["flags"]
                index = link["ifindex"]
                assert "output-mark 0x7b" in states(), states()
                rpc("InstallSa",id=b,config=sa_config())
                rpc("RemoveSa",id=a)
                assert next(l for l in links() if l["ifname"] == "ranet00000029")["ifindex"] == index
                for v6 in [False, True]:
                    for direction in [0,1,2]: rpc("InstallPolicy",id=policy(v6=v6,direction=direction),config=policy_config(spi=b["spi"]))
                assert rpc("QuerySa",id=b)["bytes"] == "0"
                assert "lastUse" in rpc("QueryPolicy",id=policy())
                failure("CloseSession",errno.EBUSY)
                rpc("RemoveSa",id=b)
                assert [l["ifname"] for l in links()] == ["foreign"], "policies must not keep interfaces alive"
                rpc("FlushPolicies")
                # Flush only session tunnel policies: port bypass must survive.
                assert "priority 32" in ip("xfrm","policy")
                # Inbound larval SPI allocation and conversion to an interface SA.
                spi = rpc("AllocateSpi",src=endpoint(),dst=endpoint("192.0.2.2"),minimum=0xc0000000,maximum=0xcfffffff)["spi"]
                inbound = sa_id(spi=spi,interface=43)
                rpc("InstallSa",id=inbound,config=sa_config(inbound=True,update=True))
                rpc("RemoveSa",id=inbound)
                expiring = sa_id(spi=0x10205,interface=44)
                rpc("InstallSa",id=expiring,config=sa_config(life=3,inbound=True))
                event = raw(event="expire")["parameters"]["event"]
                assert event["expiry"]["spi"] == expiring["spi"]
                if not event["expiry"]["hard"]:
                    assert raw(event="expire")["parameters"]["event"]["expiry"]["hard"]
                wait(lambda: [l["ifname"] for l in links()] == ["foreign"])
                rpc("FlushSas")
                assert "0x0000aaaa" in states() and "0x000102" not in states(), states()
                rpc("CloseSession"); child.wait(timeout=5); assert child.returncode == 0
                assert not ip("xfrm","policy").strip()
                # A clean close releases ownership and permits a new session.
                again = Varlink(path); assert "error" not in again.call("OpenSession",dict(interfacesUse="",interfacesIgnore="")); assert "error" not in again.call("CloseSession"); again.socket.close()
                excluded = Varlink(path)
                assert "error" not in excluded.call("OpenSession",dict(interfacesUse="",interfacesIgnore="underlay"))
                assert excluded.call("GetSourceAddress",dict(destination=endpoint("203.0.113.2")))["parameters"]["errno"] == errno.ENETUNREACH
                assert "error" not in excluded.call("CloseSession"); excluded.socket.close()
                # Losing charon preserves active kernel objects, while the
                # daemon still cleans an interface when its last SA expires.
                lost = Varlink(path); assert "error" not in lost.call("OpenSession",dict(interfacesUse="",interfacesIgnore=""))
                assert "error" not in lost.call("InstallSa",dict(id=sa_id(spi=0x12345,interface=50),config=sa_config(life=3,inbound=True)))
                lost.socket.close()
                assert "0x00012345" in states()
                probe = Varlink(path)
                assert probe.call("OpenSession",dict(interfacesUse="",interfacesIgnore=""))["error"].endswith("SessionBusy")
                probe.socket.close()
                wait(lambda: [l["ifname"] for l in links()] == ["foreign"])
                print("PASS: socket group authorization and denied nonmember, standard Varlink, IPv4/IPv6 FIB lookups and routing policy, coalesced route/address events, capability-free client, SA/interface lifetime, overlapping rekey, rollback, foreign objects, larval SPI, hard expiry, scoped cleanup and disconnected-client expiry")
            except BaseException:
                log.seek(0); print(log.read(),file=sys.stderr); raise
            finally:
                if child and child.poll() is None: child.kill(); child.wait()
                daemon.terminate(); daemon.wait(timeout=5)

if __name__ == "__main__":
    if sys.argv[1] == "--client": client(sys.argv[2])
    else: run(sys.argv[1])
