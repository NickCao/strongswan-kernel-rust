#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the Rust plugin through stock strongSwan 6.1 C function tables.

Both Rust's variadic enumerate callback and C's va_list forwarding to Rust's
venumerate callback are called for addresses and subnets, in a cap-free client.
Run as root inside a disposable network namespace, with an installed prefix.
"""
import argparse
import ctypes as c
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


class Plugin(c.Structure):
    _fields_ = [(name, c.c_void_p) for name in ("get_name", "get_features", "reload", "destroy")]


class Feature(c.Structure):
    _fields_ = [("kind", c.c_int), ("type", c.c_int), ("callback", c.c_void_p), ("data", c.c_void_p)]


class Net(c.Structure):
    _fields_ = [(name, c.c_void_p) for name in (
        "get_features", "get_source_addr", "get_nexthop", "get_interface",
        "create_address_enumerator", "create_local_subnet_enumerator",
        "add_ip", "del_ip", "add_route", "del_route", "destroy")]


class Enumerator(c.Structure):
    _fields_ = [(name, c.c_void_p) for name in ("enumerate", "venumerate", "destroy")]


class Chunk(c.Structure):
    _fields_ = [("ptr", c.c_void_p), ("len", c.c_size_t)]


class Host(c.Structure):
    _fields_ = [(name, c.c_void_p) for name in (
        "clone", "get_sockaddr", "get_sockaddr_len", "get_family", "is_anyaddr",
        "get_address", "get_port", "set_port", "ip_equals", "equals", "destroy")]


def method(pointer, table, field, result, *arguments):
    address = c.cast(pointer, c.POINTER(table)).contents
    return c.CFUNCTYPE(result, c.c_void_p, *arguments)(getattr(address, field))


def child(prefix, config):
    caps = [line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
            if line.startswith(("CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"))]
    assert caps and all(int(value, 16) == 0 for value in caps)
    library = c.CDLL(str(prefix / "lib/ipsec/libstrongswan.so"), mode=c.RTLD_GLOBAL)
    charon = c.CDLL(str(prefix / "lib/ipsec/libcharon.so"), mode=c.RTLD_GLOBAL)
    library.library_init.argtypes = [c.c_char_p, c.c_char_p]
    library.library_init.restype = c.c_bool
    charon.libcharon_init.restype = c.c_bool
    assert library.library_init(os.fsencode(config), b"charon")
    assert charon.libcharon_init()
    c.c_void_p.in_dll(library, "dbg").value = c.cast(library.dbg_default, c.c_void_p).value
    module = c.CDLL(str(prefix / "lib/ipsec/plugins/libstrongswan-kernel-rust.so"))
    assert c.c_char_p.in_dll(module, "kernel_rust_plugin_version").value == b"6.1.0"
    module.kernel_rust_plugin_create.restype = c.c_void_p
    library.enumerator_enumerate_default.argtypes = [c.c_void_p]
    library.enumerator_enumerate_default.restype = c.c_bool
    baseline_fds = None  # The host watcher may lazily open its notification pipe.
    try:
        for session in range(8):
            plugin = module.kernel_rust_plugin_create()
            assert plugin, f"plugin creation failed for session {session}"
            features = c.POINTER(Feature)()
            count = method(plugin, Plugin, "get_features", c.c_int, c.POINTER(c.POINTER(Feature)))(plugin, c.byref(features))
            assert count == 4
            net = c.CFUNCTYPE(c.c_void_p)(features[2].data)()
            assert net
            try:
                for subnets in (False, True):
                    for forwarded in (False, True):
                        if subnets:
                            enumerator = method(net, Net, "create_local_subnet_enumerator", c.c_void_p)(net)
                        else:
                            enumerator = method(net, Net, "create_address_enumerator", c.c_void_p, c.c_int)(net, 1)
                        assert enumerator
                        enumerate_fn = (library.enumerator_enumerate_default if forwarded else
                                        method(enumerator, Enumerator, "enumerate", c.c_bool))
                        values = set()
                        try:
                            for _ in range(4097):
                                host, prefixlen, name = c.c_void_p(), c.c_uint8(), c.c_char_p()
                                arguments = [c.byref(host)]
                                if subnets:
                                    arguments += [c.byref(prefixlen), c.byref(name)]
                                if not enumerate_fn(enumerator, *arguments):
                                    assert not host.value
                                    break
                                assert host.value
                                chunk = method(host, Host, "get_address", Chunk)(host)
                                raw = c.string_at(chunk.ptr, chunk.len)
                                if subnets:
                                    assert name.value == b"test0"
                                    assert prefixlen.value in (24, 64)
                                values.add(raw)
                            else:
                                raise AssertionError("enumerator did not terminate")
                        finally:
                            method(enumerator, Enumerator, "destroy", None)(enumerator)
                        expected = {ipaddress.ip_address("192.0.2.0" if subnets else "192.0.2.99").packed,
                                    ipaddress.ip_address("2001:db8::" if subnets else "2001:db8::63").packed}
                        assert values == expected, (subnets, forwarded, values)
            finally:
                method(net, Net, "destroy", None)(net)
                method(plugin, Plugin, "destroy", None)(plugin)
            count = len(os.listdir("/proc/self/fd"))
            if baseline_fds is None:
                baseline_fds = count
            assert count == baseline_fds, "session leaked descriptors"
    finally:
        charon.libcharon_deinit()
        library.library_deinit()


def run(prefix):
    assert os.geteuid() == 0
    assert os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino, "use unshare --net"
    for args in (["link", "set", "lo", "up"], ["link", "add", "test0", "type", "dummy"],
                 ["link", "set", "test0", "addrgenmode", "none"],
                 ["addr", "add", "192.0.2.99/24", "dev", "test0"],
                 ["-6", "addr", "add", "2001:db8::63/64", "dev", "test0", "nodad"],
                 ["link", "set", "test0", "up"]):
        subprocess.run(["ip", *args], check=True)
    with tempfile.TemporaryDirectory(prefix="kernel-rust-abi-") as directory:
        root = Path(directory)
        root.chmod(0o755)
        socket = root / "kernel.sock"
        config = root / "strongswan.conf"
        config.write_text(f"charon {{\n interfaces_use = test0\n plugins {{\n kernel-rust {{\n socket = {socket}\n }}\n }}\n}}\n")
        script = root / "plugin.py"
        script.write_text(Path(__file__).read_text())
        with subprocess.Popen([str(prefix / "bin/charon-kernel-daemon"), "--socket", str(socket),
                               "--uid", "65534", "--gid", "65534"], stdout=subprocess.DEVNULL) as daemon:
            try:
                for _ in range(500):
                    if socket.exists():
                        break
                    assert daemon.poll() is None
                    time.sleep(0.01)
                else:
                    raise AssertionError("daemon did not start")
                subprocess.run(["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
                                "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
                                sys.executable, str(script), str(prefix), "--child", str(config)], check=True)
            finally:
                daemon.terminate()
                daemon.wait(timeout=10)
    print("PASS: Rust enumerate/venumerate C ABI, IPv4/IPv6 addresses/subnets, eight clean capability-free sessions without descriptor leaks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prefix", type=Path)
    parser.add_argument("--child", type=Path)
    options = parser.parse_args()
    if options.child:
        child(options.prefix.resolve(), options.child)
    else:
        run(options.prefix.resolve())
