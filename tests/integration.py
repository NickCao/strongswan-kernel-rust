#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Real Varlink/XFRM lifecycle tests. Run in a disposable network namespace."""
import copy
import errno
import ipaddress
import json
import os
import re
from pathlib import Path
import shutil
import signal
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
    def links(): return json.loads(ip("-j", "-d", "-N", "link", "show", "type", "xfrm"))
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
    ip("-6", "addr", "add", "fe80::123/64", "dev", "underlay", "nodad")
    ip("addr", "add", "169.254.1.1/16", "dev", "underlay")
    ip("link", "add", "spare", "type", "dummy")
    ip("addr", "add", "198.18.1.1/24", "dev", "spare")
    ip("link", "add", "foreign", "type", "xfrm", "if_id", 77)
    ip("link", "set", "foreign", "up")
    overlay_addresses = ["198.51.100.1", "2001:db8:77::1"]
    ip("addr", "add", overlay_addresses[0] + "/24", "dev", "foreign")
    ip("-6", "addr", "add", overlay_addresses[1] + "/64", "dev", "foreign", "nodad")
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
                for address in overlay_addresses:
                    failure("GetInterface", errno.ENOENT, address=endpoint(address))
                addresses = {a["address"] for a in rpc("ListAddresses", which=1)["addresses"]}
                assert {"192.0.2.1", "2001:db8:1::1"} <= addresses, addresses
                assert addresses.isdisjoint(overlay_addresses), addresses
                assert not any(ipaddress.ip_address(address).is_link_local for address in addresses), addresses
                assert "198.18.1.1" not in addresses, addresses
                assert "198.18.1.1" in {a["address"] for a in rpc("ListAddresses", which=3)["addresses"]}
                for address in overlay_addresses:
                    destination = "2001:db8:2::2" if ":" in address else "203.0.113.2"
                    assert rpc("GetSourceAddress", destination=endpoint(destination), source=endpoint(address))["address"]["address"] == address
                    assert rpc("GetNextHop", destination=endpoint(destination), source=endpoint(address))["interface"] == "underlay"
                # The source's interface does not constrain the egress. Honor
                # the FIB's preferred source for both address families too.
                for destination, source, gateway in [
                    ("198.19.0.2", overlay_addresses[0], "192.0.2.254"),
                    ("2001:db8:19::2", overlay_addresses[1], "2001:db8:1::fe"),
                ]:
                    family = ["-6"] if ":" in destination else []
                    ip(*family, "route", "add", destination, "via", gateway, "dev", "underlay", "src", source)
                    assert rpc("GetSourceAddress", destination=endpoint(destination))["address"]["address"] == source
                    route = rpc("GetNextHop", destination=endpoint(destination))
                    assert route["gateway"]["address"] == gateway and route["interface"] == "underlay", route
                    ip(*family, "route", "del", destination)
                assert all(s["interface"] != "foreign" for s in rpc("ListSubnets")["subnets"])
                ip("route", "add", "192.0.2.2/32", "dev", "foreign")
                failure("GetSourceAddress", errno.ENETUNREACH, destination=endpoint("192.0.2.2"))
                failure("GetNextHop", errno.ENETUNREACH, destination=endpoint("192.0.2.2"), source=endpoint())
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
                # A tracked SA that vanished in the kernel can be installed
                # again through the update-to-add retry without losing xfrmi.
                ip("xfrm", "state", "delete", "src", b["src"]["address"], "dst", b["dst"]["address"],
                   "proto", "esp", "spi", b["spi"])
                rpc("InstallSa",id=b,config=sa_config(update=True))
                assert next(l for l in links() if l["ifname"] == "ranet00000029")["ifindex"] == index
                # Interface repair uses recorded SA ownership, independently
                # of policies and without changing the installed SAs.
                name = "ranet00000029"
                def tunnel():
                    return next((l for l in links() if l["ifname"] == name), None)
                def configured():
                    link = tunnel()
                    return (link is not None and link["mtu"] == 1400
                            and int(link.get("group", 0)) == 17227
                            and int(str(link["linkinfo"]["info_data"]["if_id"]), 0) == 41
                            and {"UP", "MULTICAST"} <= set(link["flags"])
                            and not link.get("master"))
                before_repair = states()
                # Attributes outside the managed spec survive in-place repair.
                ip("link", "set", name, "alias", "user-managed", "txqueuelen", 123,
                   "promisc", "on", "allmulticast", "on")
                ip("addr", "add", "198.18.41.1/32", "dev", name)
                def extras_preserved():
                    link = tunnel()
                    assert link["ifalias"] == "user-managed" and link["txqlen"] == 123, link
                    assert {"PROMISC", "ALLMULTI"} <= set(link["flags"]), link
                    assert "198.18.41.1/32" in ip("-o", "addr", "show", "dev", name)
                ip("link", "set", name, "down", "mtu", 1280, "multicast", "off")
                wait(configured)
                assert tunnel()["ifindex"] == index
                extras_preserved()
                ip("link", "add", "accidental", "type", "vrf", "table", "5678")
                ip("link", "set", "accidental", "up")
                ip("link", "set", name, "master", "accidental")
                wait(configured)
                ip("link", "set", name, "name", "renamed")
                wait(configured)
                assert tunnel()["ifindex"] == index
                extras_preserved()
                # The opaque logical identity remains 41 while native if_id
                # drifts. Repair reads if_id from configuration, not identity.
                ip("link", "set", name, "type", "xfrm", "if_id", 66)
                wait(configured)
                assert tunnel()["ifindex"] == index
                extras_preserved()
                ip("link", "del", name)
                wait(configured)
                assert tunnel()["ifindex"] != index
                index = tunnel()["ifindex"]

                # Leaving the ownership group releases an interface. A foreign
                # replacement stays untouched even when its index is reused.
                # A foreign interface holding ID 41 blocks recreation meanwhile.
                ip("link", "set", name, "group", 0)
                ip("link", "set", name, "type", "xfrm", "if_id", 66)
                ip("link", "add", "guard41", "type", "xfrm", "if_id", 41)
                ip("link", "del", name)
                ip("link", "add", name, "index", index, "type", "xfrm", "if_id", 66)
                ip("link", "set", name, "down", "mtu", 1280, "multicast", "off")
                replacement_index = tunnel()["ifindex"]
                assert replacement_index == index
                failure("InstallSa", errno.EEXIST, id=b, config=sa_config(update=True))
                time.sleep(.3)
                assert tunnel()["ifindex"] == replacement_index and tunnel()["mtu"] == 1280
                assert "UP" not in tunnel()["flags"] and "MULTICAST" not in tunnel()["flags"]
                ip("link", "del", name)
                ip("link", "del", "guard41")
                wait(configured)
                assert tunnel()["ifindex"] != replacement_index
                assert states() == before_repair, "interface repair must not modify SAs"
                # Trap policies must forward kernel acquire attributes and
                # selectors through Varlink for both inner address families.
                for family, source, destination in [
                    (socket.AF_INET, "192.0.2.1", "198.18.0.1"),
                    (socket.AF_INET6, "2001:db8:1::1", "2001:db8:3::1"),
                ]:
                    trap = policy(v6=family == socket.AF_INET6)
                    config = policy_config(spi=0); config["reqid"] = 44 if family == socket.AF_INET6 else 43
                    rpc("InstallPolicy",id=trap,config=config)
                    flags = ["-6"] if family == socket.AF_INET6 else []
                    ip(*flags, "route", "add", destination, "dev", "ranet00000029", "src", source)
                    with socket.socket(family, socket.SOCK_DGRAM) as udp:
                        udp.bind((source, 0)); source_port = udp.getsockname()[1]
                        try: udp.sendto(b"acquire", (destination, 32123))
                        except BlockingIOError: pass  # No SA exists for this reqid yet.
                        acquire = raw(event="acquire")["parameters"]["event"]["acquire"]
                    assert acquire["reqid"] == config["reqid"] and acquire["sequence"] > 0, acquire
                    for selector, address, port in [(acquire["src"], source, source_port), (acquire["dst"], destination, 32123)]:
                        assert selector["from"] == selector["to"] == address, acquire
                        assert selector["protocol"] == 17 and selector["fromPort"] == selector["toPort"] == port, acquire
                    ip(*flags, "route", "del", destination)
                    rpc("RemovePolicy",id=trap,config=config)
                # A specific ICMP code must outrank the type-only policy.
                for v6, protocol, icmp_type in [(False, 1, 3), (True, 58, 128)]:
                    priorities = []
                    for code in [0, 1]:
                        icmp = policy(v6=v6)
                        icmp["src"].update(protocol=protocol, fromPort=icmp_type << 8 | code,
                                           toPort=icmp_type << 8 | code)
                        config = policy_config(spi=b["spi"])
                        rpc("InstallPolicy",id=icmp,config=config)
                        args = ["src", "::/0" if v6 else "0.0.0.0/0",
                                "dst", "::/0" if v6 else "0.0.0.0/0",
                                "proto", str(protocol), "type", str(icmp_type)]
                        if code:
                            args += ["code", str(code)]
                        installed = ip("xfrm", "policy", "get", *args, "dir", "out", "if_id", "41")
                        priorities.append(int(re.search(r"priority (\d+)", installed)[1]))
                        rpc("RemovePolicy",id=icmp,config=config)
                    assert priorities[1] < priorities[0], priorities
                for v6 in [False, True]:
                    for direction in [0,1,2]: rpc("InstallPolicy",id=policy(v6=v6,direction=direction),config=policy_config(spi=b["spi"]))
                # Reconciliation repairs only desired policies. Exercise the
                # real kernel inventory, including normalized bypass defaults.
                foreign_policy = ["src", "203.0.113.0/24", "dst", "203.0.114.0/24",
                                  "dir", "out", "if_id", "77"]
                ip("xfrm", "policy", "add", *foreign_policy, "priority", "1234", "action", "block")
                def policy_specs():
                    return set(re.split(r"(?=^src )", ip("xfrm", "policy"), flags=re.M)[1:])
                def outbound_policy():
                    return subprocess.run(["ip", "-s", "xfrm", "policy", "get",
                        "src", "0.0.0.0/0", "dst", "0.0.0.0/0", "dir", "out", "if_id", "41"],
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False).stdout
                expected = policy_specs()
                assert len(expected) == 11, expected
                # Suppress background traffic before XFRM, so an SA's replay
                # counters cannot advance during comparison.
                subprocess.run(["tc", "qdisc", "add", "dev", "ranet00000029", "clsact"], check=True)
                subprocess.run(["tc", "filter", "add", "dev", "ranet00000029", "egress",
                                "matchall", "action", "drop"], check=True)
                original_states = states()
                original_add_time = re.search(r"\badd (.+) use ", outbound_policy())[1]
                time.sleep(5.3)  # At least one periodic audit, without changes.
                assert re.search(r"\badd (.+) use ", outbound_policy())[1] == original_add_time
                assert policy_specs() == expected
                ip("xfrm", "policy", "delete", "src", "0.0.0.0/0", "dst", "0.0.0.0/0", "dir", "out", "if_id", "41")
                wait(lambda: policy_specs() == expected)
                ip("xfrm", "policy", "update", "src", "0.0.0.0/0", "dst", "0.0.0.0/0",
                   "dir", "out", "if_id", "41", "priority", "7", "action", "block")
                wait(lambda: policy_specs() == expected)
                # Unsupported native flags must remain visible as a mismatch
                # after decoding to the shared policy configuration model.
                priority = re.search(r"priority (\d+)", outbound_policy())[1]
                ip("xfrm", "policy", "update", "src", "0.0.0.0/0", "dst", "0.0.0.0/0",
                   "dir", "out", "if_id", "41", "priority", priority, "flag", "localok",
                   "tmpl", "src", b["src"]["address"], "dst", b["dst"]["address"],
                   "proto", "esp", "spi", b["spi"], "mode", "tunnel", "reqid", "42")
                wait(lambda: policy_specs() == expected)
                # A newer reference takes precedence. After it is removed,
                # pending repair must use the surviving reference's SPI.
                for attempt in range(20):
                    replacement = policy_config(spi=0x20000 + attempt)
                    rpc("InstallPolicy",id=policy(),config=replacement)
                    ip("xfrm", "policy", "delete", "src", "0.0.0.0/0", "dst", "0.0.0.0/0", "dir", "out", "if_id", "41")
                    rpc("RemovePolicy",id=policy(),config=replacement)
                wait(lambda: policy_specs() == expected)
                ip("xfrm", "policy", "flush")
                # The admin also flushed the foreign policy; it is not ours
                # to recreate. Restore all six tunnel and four bypass policies.
                expected = {spec for spec in expected if "if_id 0x4d" not in spec}
                wait(lambda: policy_specs() == expected)
                assert len(expected) == 10
                assert states() == original_states, "policy repair must not modify SAs"
                unused = rpc("QuerySa",id=b)
                assert (unused["bytes"], unused["packets"], unused["lastUse"]) == ("0", "0", 0), unused
                assert rpc("QueryPolicy",id=policy())["lastUse"] == 0
                failure("CloseSession",errno.EBUSY)
                rpc("RemoveSa",id=b)
                assert [l["ifname"] for l in links()] == ["foreign"], "policies must not keep interfaces alive"
                ip("xfrm", "policy", "delete", "src", "0.0.0.0/0", "dst", "0.0.0.0/0", "dir", "out", "if_id", "41")
                rpc("FlushPolicies")
                # Flush only session tunnel policies: port bypass must survive.
                assert "priority 32" in ip("xfrm","policy")
                after_flush = policy_specs()
                time.sleep(5.3)
                assert policy_specs() == after_flush and len(after_flush) == 4, "deleted policies must not return"
                # Final-SA removal must not resurrect a missing interface or
                # delete a foreign interface that replaced the owned object.
                for attempt in range(5):
                    temporary = sa_id(spi=0x30000 + attempt, interface=60)
                    rpc("InstallSa", id=temporary, config=sa_config())
                    temporary_name = "ranet0000003c"
                    if attempt == 4:
                        ip("link", "set", temporary_name, "group", 0)
                        ip("link", "set", temporary_name, "type", "xfrm", "if_id", 160)
                    else:
                        ip("link", "del", temporary_name)
                    rpc("RemoveSa", id=temporary)
                    time.sleep(.15)
                    assert any(l["ifname"] == temporary_name for l in links()) == (attempt == 4)
                ip("link", "del", temporary_name)
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
                filtered = Varlink(path)
                assert "error" not in filtered.call("OpenSession",dict(interfacesUse="",interfacesIgnore="spare"))
                def listed(which):
                    return {a["address"] for a in filtered.call("ListAddresses",dict(which=which))["parameters"]["addresses"]}
                # DOWN/IGNORED modify REGULAR; they are not address classes.
                assert listed(4) == set()
                assert "198.18.1.1" not in listed(5)
                assert "198.18.1.1" in listed(7)
                ip("link", "set", "spare", "up")
                wait(lambda: "198.18.1.1" in listed(5))
                assert "198.18.1.1" not in listed(1)
                # Ignoring an interface for discovery must still allow its
                # address as a source over the permitted underlay route.
                ip("route", "add", "198.19.0.2/32", "via", "192.0.2.254", "dev", "underlay", "src", "198.18.1.1")
                def multihomed_source():
                    assert filtered.call("GetSourceAddress",dict(destination=endpoint("203.0.113.2"),source=endpoint("198.18.1.1")))["parameters"]["address"]["address"] == "198.18.1.1"
                    assert filtered.call("GetSourceAddress",dict(destination=endpoint("198.19.0.2")))["parameters"]["address"]["address"] == "198.18.1.1"
                    assert filtered.call("GetNextHop",dict(destination=endpoint("198.19.0.2")))["parameters"]["interface"] == "underlay"
                multihomed_source()
                ip("link", "set", "spare", "down")
                wait(lambda: "198.18.1.1" not in listed(5))
                multihomed_source()
                ip("route", "del", "198.19.0.2/32")
                assert "error" not in filtered.call("CloseSession"); filtered.socket.close()
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
                print("PASS: socket group authorization and denied nonmember, standard Varlink, IPv4/IPv6 FIB lookups and routing policy, address scope/type filtering, multihomed sources and egress-interface exclusions, ICMP policy priorities, policy and interface repair without SA changes, rekey references and teardown, coalesced route/address events, capability-free client, SA/interface lifetime, overlapping rekey, update-to-add retry, IPv4/IPv6 acquire events, rollback, foreign replacements, larval SPI, hard expiry, scoped cleanup including missing objects, and disconnected-client expiry")
            except BaseException:
                log.seek(0); print(log.read(),file=sys.stderr); raise
            finally:
                if child and child.poll() is None: child.kill(); child.wait()
                daemon.terminate(); daemon.wait(timeout=5)

    foreign_policy = ["src", "203.0.113.0/24", "dst", "203.0.114.0/24",
                      "dir", "out", "if_id", "77"]
    ip("xfrm", "policy", "add", *foreign_policy, "priority", "1234", "action", "block")
    expected_policies = ip("xfrm", "policy")
    for attempt, (signum, disconnect) in enumerate([
        (signal.SIGTERM, False), (signal.SIGINT, False), (signal.SIGTERM, True),
    ]):
        with tempfile.TemporaryDirectory(prefix="kernel-rust-shutdown-") as d:
            path = str(Path(d) / "kernel.sock")
            with open(Path(d) / "daemon.log", "w+") as log:
                daemon = subprocess.Popen([binary, "--socket", path], stdout=log, stderr=log)
                control = None
                try:
                    wait(lambda: Path(path).exists() or daemon.poll() is not None)
                    assert daemon.poll() is None
                    control = Varlink(path)
                    def call(method, **parameters):
                        reply = control.call(method, parameters)
                        assert "error" not in reply, reply
                        return reply.get("parameters", {})
                    call("OpenSession", interfacesUse="", interfacesIgnore="")
                    owned = sa_id(spi=0x40000 + attempt, interface=61 + attempt)
                    call("InstallSa", id=owned, config=sa_config())
                    allocated = call("AllocateSpi", src=owned["src"], dst=owned["dst"],
                                     minimum=0xd0000000, maximum=0xdfffffff)["spi"]
                    call("BypassPort", family=socket.AF_INET, port=13000)
                    call("BypassPort", family=socket.AF_INET6, port=13000)
                    for direction in [0, 1, 2]:
                        call("InstallPolicy", id=policy(interface=owned["interfaceId"], direction=direction),
                             config=policy_config(spi=owned["spi"]))
                    # A queued request and idle connections must not obstruct
                    # shutdown or install objects after the final reconciliation.
                    idle = Varlink(path)
                    control.send("io.ranet.Kernel.InstallPolicy", dict(
                        id=policy(interface=owned["interfaceId"], v6=True),
                        config=policy_config(spi=owned["spi"])))
                    assert len(links()) == 2
                    before_sas = states()
                    if disconnect:
                        control.socket.close()
                    daemon.send_signal(signum)
                    assert daemon.wait(timeout=10) == 0
                    idle.socket.close()
                    assert ip("xfrm", "policy") == expected_policies
                    assert [link["ifname"] for link in links()] == ["foreign"]
                    assert states() == before_sas, "shutdown must leave SAs and SPI reservations unchanged"
                    for spi in [owned["spi"], allocated]:
                        ip("xfrm", "state", "delete", "src", owned["src"]["address"],
                           "dst", owned["dst"]["address"], "proto", "esp", "spi", spi)
                except BaseException:
                    log.seek(0); print(log.read(), file=sys.stderr); raise
                finally:
                    if control:
                        control.socket.close()
                    if daemon.poll() is None:
                        daemon.kill(); daemon.wait()
    ip("xfrm", "policy", "delete", *foreign_policy)
    print("PASS: SIGTERM/SIGINT reconcile policies and interfaces to empty with active or disconnected clients, preserve foreign objects, and leave SAs and SPI reservations unchanged")

    # Group membership survives daemon crashes. Reuse recognizable interfaces,
    # remove every unwanted owned kind, and preserve interfaces in other groups.
    with tempfile.TemporaryDirectory(prefix="kernel-rust-inventory-") as d:
        directory = Path(d)
        with open(directory / "daemon.log", "w+") as log:
            daemons, controls = [], []
            def start(attempt):
                path = str(directory / f"kernel-{attempt}.sock")
                daemon = subprocess.Popen([
                    binary, "--socket", path, "--ifname-prefix", "resume",
                    "--interface-group", "17229",
                ], stdout=log, stderr=log)
                daemons.append(daemon)
                wait(lambda: Path(path).exists() or daemon.poll() is not None)
                assert daemon.poll() is None
                control = Varlink(path)
                controls.append(control)
                assert "error" not in control.call("OpenSession", dict(interfacesUse="", interfacesIgnore=""))
                return daemon, control
            def call(control, method, **parameters):
                reply = control.call(method, parameters)
                assert "error" not in reply, reply
                return reply.get("parameters", {})
            def inventory():
                return json.loads(ip("-j", "-d", "-N", "link"))
            def owned():
                return [link for link in inventory() if int(link.get("group", 0)) == 17229]
            try:
                daemon, control = start(0)
                first = sa_id(spi=0x50000, interface=70)
                call(control, "InstallSa", id=first, config=sa_config())
                original = owned()[0]["ifindex"]
                ip("link", "set", "resume00000046", "alias", "retained-after-crash", "txqueuelen", 321)
                daemon.kill(); assert daemon.wait(timeout=5) == -signal.SIGKILL
                control.socket.close()
                assert owned()[0]["ifindex"] == original and "0x00050000" in states()
                # The native if_id can drift independently of the encoded
                # opaque logical identity. Restart must restore the desired one.
                ip("link", "set", "resume00000046", "type", "xfrm", "if_id", 170)
                ip("link", "set", "resume00000046", "down", "mtu", 1280, "multicast", "off")
                ip("link", "add", "owned-orphan", "group", 17229, "type", "dummy")
                ip("link", "add", "resume00000048", "group", 17230, "type", "dummy")

                daemon, control = start(1)
                second = sa_id(spi=0x50001, interface=70)
                call(control, "InstallSa", id=second, config=sa_config())
                recovered = next(link for link in owned() if link["ifname"] == "resume00000046")
                assert recovered["ifindex"] == original, recovered
                assert recovered["mtu"] == 1400 and {"UP", "MULTICAST"} <= set(recovered["flags"]), recovered
                assert int(str(recovered["linkinfo"]["info_data"]["if_id"]), 0) == 70, recovered
                assert recovered["ifalias"] == "retained-after-crash" and recovered["txqlen"] == 321, recovered
                assert not any(link["ifname"] == "owned-orphan" for link in inventory())
                assert "0x00050000" in states(), "interface discovery must not adopt or remove old SAs"
                # A known ID with the wrong kind is updated; Linux replaces it.
                ip("link", "add", "resume00000047", "group", 17229, "type", "dummy")
                third = sa_id(spi=0x50002, interface=71)
                call(control, "InstallSa", id=third, config=sa_config())
                repaired = next(link for link in owned() if link["ifname"] == "resume00000047")
                assert repaired["linkinfo"]["info_kind"] == "xfrm", repaired
                assert control.call("InstallSa", dict(id=sa_id(spi=0x50003, interface=72), config=sa_config()))["parameters"]["errno"] == errno.EEXIST
                assert next(link for link in inventory() if link["ifname"] == "resume00000048")["linkinfo"]["info_kind"] == "dummy"
                before_sas = states()
                daemon.kill(); assert daemon.wait(timeout=5) == -signal.SIGKILL
                control.socket.close()
                ip("link", "add", "owned-bridge", "group", 17229, "type", "bridge")

                daemon, control = start(2)
                call(control, "CloseSession")
                assert not owned(), "empty desired state must remove all discovered owned kinds"
                assert states() == before_sas, "interface crash cleanup must leave SAs unchanged"
                assert any(link["ifname"] == "resume00000048" for link in inventory())
                assert any(link["ifname"] == "foreign" for link in links())
                daemon.terminate(); assert daemon.wait(timeout=5) == 0
                for sa in [first, second, third]:
                    ip("xfrm", "state", "delete", "src", sa["src"]["address"],
                       "dst", sa["dst"]["address"], "proto", "esp", "spi", sa["spi"])
                ip("link", "del", "resume00000048")
            except BaseException:
                log.seek(0); print(log.read(), file=sys.stderr); raise
            finally:
                for control in controls:
                    control.socket.close()
                for daemon in daemons:
                    if daemon.poll() is None:
                        daemon.kill(); daemon.wait()
    print("PASS: configurable numeric ownership group, wrong-kind repair, opaque identity independent of native if_id, crash inventory reuse and cleanup, unmanaged settings preserved, and foreign groups untouched")

if __name__ == "__main__":
    if sys.argv[1] == "--client": client(sys.argv[2])
    else: run(sys.argv[1])
