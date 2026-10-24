#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise ranet's VICI request sequence under route and link churn.

Run in a disposable VM/namespace with charon already running and the upstream
Python vici package on PYTHONPATH. The remote address must be unused.
"""
import argparse
import socket
import subprocess
import threading
import time

import vici


def run(args):
    table = "1234"
    names = []
    errors = []
    updates = 0
    interfaces = [f"churn{i}" for i in range(200)]
    stop = threading.Event()

    def batch(commands):
        subprocess.run(["ip", "-batch", "-"], input=commands, text=True, check=True)

    def churn():
        nonlocal updates
        try:
            while not stop.is_set():
                gateway = args.gateway if updates % 2 else args.alternate_gateway
                batch("".join(
                    f"route replace 198.18.0.{i}/32 via {gateway} "
                    f"dev {args.interface} table {table} proto 192\n"
                    for i in range(1, 101)
                ) + "".join(
                    f"link set dev {interface} mtu {1400 + updates % 2}\n"
                    for interface in interfaces[:100]
                ))
                updates += 1
                stop.wait(0.05)
        except Exception as error:
            errors.append(error)

    batch("".join(
        f"route add 172.16.{i // 256}.{i % 256}/32 dev {args.interface} "
        f"table {table} proto 192\n"
        for i in range(10000)
    ))
    # Unrelated interfaces must not turn each link notification into a full
    # reconciliation pass. Their unused attributes also exercise link dumps.
    batch("".join(f"link add {interface} type dummy\n" for interface in interfaces))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(args.socket)
    client = vici.Session(sock)
    worker = threading.Thread(target=churn)
    worker.start()
    try:
        timings = []
        for attempt in range(2):
            started = time.monotonic()
            for i in range(200):
                name = f"route-churn-{i}"
                client.load_conn({name: {
                    "version": "2",
                    "local_addrs": ["0.0.0.0/0"],
                    "remote_addrs": [args.remote],
                    "local_port": "13000",
                    "remote_port": "13000",
                    "proposals": ["aes128-sha256-x25519"],
                    "encap": "yes",
                    "mobike": "no",
                    "if_id_in": "%unique",
                    "if_id_out": "%unique",
                    "local": {"auth": "psk", "id": f"local-{name}"},
                    "remote": {"auth": "psk", "id": f"remote-{name}"},
                    "children": {"net": {
                        "mode": "tunnel",
                        "local_ts": ["0.0.0.0/0", "::/0"],
                        "remote_ts": ["0.0.0.0/0", "::/0"],
                    }},
                }})
                if attempt == 0:
                    names.append(name)
                sas = list(client.list_sas({"ike": name}))
                if not sas:
                    client.request("initiate", {"ike": name, "child": "net", "timeout": "-1"})
            elapsed = time.monotonic() - started
            assert elapsed < 15, f"VICI stalled for {elapsed:.2f}s under route/link churn"
            timings.append(elapsed)
        assert updates > 0 and not errors, errors
        print(f"PASS: 200 VICI connections loaded/reloaded in {timings}, "
              f"during {updates * 100} route and {updates * 100} link updates", flush=True)
    finally:
        stop.set()
        worker.join()
        for name in names:
            # All test peers are unreachable, so no CHILD_SAs are installed.
            for sa in client.list_sas({"ike": name}):
                for ike in sa.values():
                    client.request("terminate", {"ike-id": ike["uniqueid"], "timeout": "-1"})
            client.unload_conn({"name": name})
        sock.close()
        subprocess.run(["ip", "route", "flush", "table", table], check=True)
        batch("".join(f"link del dev {interface}\n" for interface in interfaces))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default="/run/strongswan/charon.vici")
    parser.add_argument("--interface", default="eth1")
    parser.add_argument("--remote", default="192.0.2.254")
    parser.add_argument("--gateway", default="192.0.2.2")
    parser.add_argument("--alternate-gateway", default="192.0.2.3")
    run(parser.parse_args())
