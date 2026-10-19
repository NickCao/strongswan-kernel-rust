#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Real IKEv2 tunnel between two capability-free charons and Rust daemons.

Run after Cargo/cargo-c installation into a disposable prefix:
unshare --net -- python3 tests/tunnel.py /tmp/strongswan-rust-install --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python
"""
import argparse
import json
import os
import re
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

def run(prefix, cbc=False, vici_python=None, dynamic_user=False):
    assert os.geteuid() == 0
    assert os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino, "use unshare --net"
    prefix = Path(prefix).resolve()
    if vici_python is not None:
        sys.path.insert(0, str(vici_python))
    try:
        import vici as vici_module
    except ModuleNotFoundError:
        raise SystemExit("Install the Python vici library or pass --vici-python /path/to/strongswan/src/libcharon/plugins/vici/python")
    keys = {}
    for peer in [1,2]:
        private = subprocess.check_output(["openssl","genpkey","-algorithm","ED25519"])
        public = subprocess.check_output(["openssl","pkey","-pubout"],input=private)
        keys[peer] = private, public
    runtime_env = {**os.environ, "LD_LIBRARY_PATH": str(prefix / "lib/ipsec") + (":" + os.environ["LD_LIBRARY_PATH"] if os.environ.get("LD_LIBRARY_PATH") else "")}
    procs = []
    namespaces = []
    logs = []
    units = []
    def cmd(args, **kwargs):
        kwargs.setdefault("env", runtime_env)
        return subprocess.check_output([str(a) for a in args], text=True, stderr=subprocess.STDOUT, **kwargs)
    def ns(peer, *args): return cmd(["ip", "netns", "exec", namespaces[peer-1], *args])
    def start(peer, args, logpath):
        log = open(logpath, "w+"); os.chown(logpath,65534,65534); logs.append(log)
        p = subprocess.Popen(["ip", "netns", "exec", namespaces[peer-1], *map(str, args)], stdout=log, stderr=subprocess.STDOUT, start_new_session=True, env=runtime_env)
        procs.append(p); return p
    def wait_file(path, processes):
        for _ in range(500):
            if path.exists(): return
            assert all(p.poll() is None for p in processes), "daemon/charon exited during startup"
            time.sleep(0.01)
        raise AssertionError(f"timed out waiting for {path}")
    with tempfile.TemporaryDirectory(prefix="kernel-rust-tunnel-") as directory:
        root = Path(directory); root.chmod(0o755)
        try:
            for peer in [1, 2]:
                name = f"kr-{os.getpid()}-{peer}"
                cmd(["ip", "netns", "add", name]); namespaces.append(name)
            cmd(["ip", "link", "add", "kr-left", "type", "veth", "peer", "name", "kr-right"])
            for peer, iface in [(1, "kr-left"), (2, "kr-right")]:
                cmd(["ip", "link", "set", iface, "netns", namespaces[peer-1]])
                ns(peer, "ip", "link", "set", "lo", "up")
                ns(peer, "ip", "link", "set", iface, "name", "eth0")
                ns(peer, "ip", "link", "set", "eth0", "up")
                ns(peer, "ip", "addr", "add", f"192.0.2.{peer}/24", "dev", "eth0")
                ns(peer, "ip", "addr", "add", f"10.{peer}.0.1/32", "dev", "lo")
                ns(peer, "ip", "-6", "addr", "add", f"fd10:{peer}::1/128", "dev", "lo")
            peers = {}
            for peer in [1, 2]:
                pdir = root / str(peer); pdir.mkdir(mode=0o755)
                unit = f"kernel-rust-{os.getpid()}-{peer}"
                if dynamic_user:
                    # systemd owns this directory and removes it with the unit.
                    runtime = Path("/run") / unit
                else:
                    runtime = pdir / "run"; runtime.mkdir(); os.chown(runtime, 65534, 65534)
                kernel_socket = pdir / "kernel.sock"
                daemon = start(peer, [prefix / "bin/charon-kernel-daemon", "--socket", kernel_socket, "--group", "nogroup" if dynamic_user else "65534"], pdir / "kernel.log")
                wait_file(kernel_socket, [daemon])
                config = pdir / "strongswan.conf"
                config.write_text(f"""charon {{
    port = 13001
    port_nat_t = 13000
    install_routes = no
    load = random nonce x509 pubkey pkcs1 pem openssl kdf kernel-rust socket-default vici
    plugins {{
        kernel-rust {{
            socket = {kernel_socket}
        }}
        vici {{
            socket = unix://{Path('/run') if dynamic_user else runtime}/charon.vici
        }}
    }}
    filelog {{
        stdout {{
            path = /dev/stdout
            default = 1
            knl = 2
            flush_line = yes
        }}
    }}
}}
""")
                config.chmod(0o644)
                if dynamic_user:
                    units.append(unit)
                    charon = start(peer, [
                        "systemd-run", "--quiet", "--wait", "--pipe", "--collect",
                        f"--unit={unit}", "--service-type=exec",
                        "--property=DynamicUser=yes",
                        "--property=SupplementaryGroups=nogroup",
                        "--property=CapabilityBoundingSet=",
                        "--property=AmbientCapabilities=",
                        f"--property=NetworkNamespacePath=/run/netns/{namespaces[peer-1]}",
                        f"--property=RuntimeDirectory={unit}",
                        "--property=RuntimeDirectoryMode=0755",
                        f"--property=BindPaths={runtime}:/run",
                        # DynamicUser isolates /tmp. Expose only the root-owned
                        # disposable prefix and configuration, read-only.
                        f"--property=BindReadOnlyPaths={prefix} {root}",
                        f"--setenv=STRONGSWAN_CONF={config}",
                        f"--setenv=LD_LIBRARY_PATH={runtime_env['LD_LIBRARY_PATH']}",
                        "--", prefix / "libexec/ipsec/charon", "--debug-knl", "2", "--debug-cfg", "2",
                    ], pdir / "charon.log")
                else:
                    # PID files are isolated too. /run is private to this mount
                    # namespace; the outer VM's runtime directory is untouched.
                    # From this child PID namespace SO_PEERCRED reports pid 0 for
                    # the external daemon; only its UID is required by the client.
                    script = pdir / "start.sh"
                    script.write_text("""#!/bin/sh
set -eu
mount --make-rprivate /
mount --bind "$1" /run
export STRONGSWAN_CONF="$2"
exec setpriv --reuid=65534 --regid=65534 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all "$3" --debug-knl 2 --debug-cfg 2
""")
                    charon = start(peer, ["unshare", "--mount", "--pid", "--fork", "--mount-proc", "/bin/sh", script, runtime, config, prefix / "libexec/ipsec/charon"], pdir / "charon.log")
                vici = runtime / "charon.vici"
                wait_file(vici, [daemon, charon])
                other = 3-peer
                swanctl = pdir / "swanctl.conf"
                public_file = pdir / "public.pem"; public_file.write_bytes(keys[peer][1])
                remote_file = pdir / "remote.pem"; remote_file.write_bytes(keys[other][1])
                esp = "esp_proposals = aes128-sha256-esn" if cbc else ""
                swanctl.write_text(f"""connections {{
    test {{
        version = 2
        local_addrs = 192.0.2.{peer}
        remote_addrs = 192.0.2.{other}
        local_port = 13000
        remote_port = 13000
        encap = yes
        mobike = no
        if_id_in = %unique
        if_id_out = %unique
        local {{
            auth = pubkey
            pubkeys = {public_file}
            id = peer-{peer}
        }}
        remote {{
            auth = pubkey
            pubkeys = {remote_file}
            id = peer-{other}
        }}
        children {{
            net {{
                local_ts = 0.0.0.0/0, ::/0
                remote_ts = 0.0.0.0/0, ::/0
                mode = tunnel
                {esp}
                set_mark_out = 123
                rekey_time = 30s
                life_time = 60s
                rand_time = 0s
            }}
        }}
    }}
}}
""")
                peers[peer] = {"dir": pdir, "runtime": runtime, "unit": unit, "vici": vici, "config": config, "swanctl": swanctl}
                env = {**runtime_env, "STRONGSWAN_CONF": str(config)}
                vsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); vsock.connect(str(vici))
                session = vici_module.Session(vsock)
                assert session.load_key({"type":"any","data":keys[peer][0]})["success"] == b"yes"
                vsock.close()
                cmd([prefix / "sbin/swanctl", "--load-conns", "--file", swanctl, "--uri", f"unix://{vici}"], env=env)
            def ctl(peer, *args):
                return cmd([prefix / "sbin/swanctl", *args, "--uri", f"unix://{peers[peer]['vici']}"], env={**runtime_env, "STRONGSWAN_CONF": str(peers[peer]["config"])}, timeout=30)
            initiated = ctl(1, "--initiate", "--child", "net")
            assert "established" in initiated, initiated
            client_uids = set()
            for peer in [1, 2]:
                # Confirm the actual IKE process, independently of the wrapper,
                # has its expected UID and no capabilities in any set.
                pid = int((peers[peer]["runtime"] / "charon.pid").read_text())
                if dynamic_user:
                    status = Path(f"/proc/{pid}/status").read_text()
                    uid = int(re.search(r"^Uid:\s+(\d+)", status, re.M)[1])
                    assert 61184 <= uid <= 65519, status
                    assert uid not in client_uids, "units must have distinct dynamic users"
                    client_uids.add(uid)
                    assert re.search(r"^Uid:\s+(.*)", status, re.M)[1].split() == [str(uid)] * 4
                    assert re.search(r"^Gid:\s+(.*)", status, re.M)[1].split() == [str(uid)] * 4
                    assert "65534" in re.search(r"^Groups:\s*(.*)", status, re.M)[1].split(), status
                    assert Path(f"/proc/{pid}/exe").resolve() == prefix / "libexec/ipsec/charon"
                    candidates = [status]
                else:
                    # PID is relative to its namespace. Locate it by namespace
                    # and executable through the VM's /proc.
                    candidates = []
                    for entry in Path("/proc").iterdir():
                        if not entry.name.isdigit(): continue
                        try:
                            if entry.joinpath("exe").resolve() != prefix / "libexec/ipsec/charon": continue
                            status = entry.joinpath("status").read_text()
                            if f"NSpid:\t{entry.name}\t{pid}" in status and f"Uid:\t65534\t65534\t65534\t65534" in status: candidates.append(status)
                        except (OSError, PermissionError): pass
                assert candidates, "could not inspect unprivileged charon"
                for status in candidates:
                    for cap in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]: assert f"{cap}:\t0000000000000000" in status, status
            interface_indices = {}
            for peer in [1, 2]:
                listing = ctl(peer, "--list-sas", "--raw")
                outbound = int(re.search(r"if-id-out=([0-9a-f]+)", listing)[1], 16)
                links = json.loads(ns(peer, "ip", "-j", "-d", "link", "show", "type", "xfrm"))
                assert len(links) == 1, links
                assert all("UP" in link["flags"] and link["mtu"] == 1400 for link in links)
                interface_indices[peer] = {link["ifname"]:link["ifindex"] for link in links}
                out = f"ranet{outbound:08x}"
                assert out in interface_indices[peer]
                ns(peer, "ip", "route", "add", f"10.{3-peer}.0.1/32", "dev", out)
                ns(peer, "ip", "-6", "route", "add", f"fd10:{3-peer}::1/128", "dev", out)
            for peer in [1,2]:
                for ipv6 in [False, True]:
                    source = f"fd10:{peer}::1" if ipv6 else f"10.{peer}.0.1"
                    dest = f"fd10:{3-peer}::1" if ipv6 else f"10.{3-peer}.0.1"
                    ping = ns(peer, "ping", "-c", "3", "-W", "2", "-I", source, dest)
                    assert "0% packet loss" in ping, ping
                state = ns(peer, "ip", "-s", "xfrm", "state")
                assert "output-mark 0x7b" in state and "encap type espinudp sport 13000 dport 13000" in state, state
                assert any(int(v) > 0 for v in re.findall(r"(\d+)\(packets\)",state)), state
            before = ns(1, "ip", "xfrm", "state")
            rekeyed = ctl(1, "--rekey", "--child", "net")
            assert "rekey" in rekeyed, rekeyed
            for _ in range(200):
                after = ns(1, "ip", "xfrm", "state")
                if after != before: break
                time.sleep(0.05)
            assert after != before, "rekey did not change SAs"
            assert "0% packet loss" in ns(1, "ping", "-c", "3", "-W", "2", "-I", "10.1.0.1", "10.2.0.1")
            for peer in [1,2]:
                links = json.loads(ns(peer,"ip","-j","-d","link","show","type","xfrm"))
                assert {l["ifname"]:l["ifindex"] for l in links} == interface_indices[peer], "rekey recreated an interface"
            ctl(1, "--terminate", "--ike", "test")
            for _ in range(200):
                if all(not ns(peer,"ip","xfrm","state").strip() and not json.loads(ns(peer,"ip","-j","link","show","type","xfrm")) for peer in [1,2]): break
                time.sleep(.05)
            for peer in [1,2]:
                assert not ns(peer,"ip","xfrm","state").strip()
                assert not json.loads(ns(peer,"ip","-j","link","show","type","xfrm"))
                policies = ns(peer,"ip","xfrm","policy","list","nosock")
                assert "if_id" not in policies and "priority 32" in policies, policies
            print("PASS: Ed25519 raw public key authentication, two capability-free charons on high UDP ports, wildcard IPv4/IPv6 tunnel selectors, daemon-created XFRM interfaces, encrypted traffic/counters, rekey without interface churn, automatic final-SA cleanup")
            if dynamic_user:
                print(f"PASS: systemd DynamicUser charons with distinct UIDs {sorted(client_uids)}, dynamic primary groups, and socket access through a supplementary group")
        finally:
            if isinstance(sys.exc_info()[1], subprocess.CalledProcessError): print(sys.exc_info()[1].output, file=sys.stderr)
            if sys.exc_info()[0]:
                for log in logs:
                    log.seek(0); print(f"{log.name}:\n{log.read()[-18000:]}", file=sys.stderr)
            for unit in reversed(units):
                subprocess.run(["systemctl", "stop", unit], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for p in reversed(procs):
                if p.poll() is None:
                    try: os.killpg(p.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
            for p in procs:
                try: p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try: os.killpg(p.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    p.wait()
            for log in logs: log.close()
            for name in namespaces: cmd(["ip", "netns", "delete", name])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", type=Path)
    parser.add_argument("--cbc", action="store_true")
    parser.add_argument("--vici-python", type=Path)
    parser.add_argument("--dynamic-user", action="store_true", help="run charons as actual systemd DynamicUser services (needs systemd and group nogroup)")
    args = parser.parse_args()
    run(args.prefix, args.cbc, args.vici_python, args.dynamic_user)
