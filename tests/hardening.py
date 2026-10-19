#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run as ExecStartPost inside the real service's systemd sandbox."""
import errno
import mmap
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys

service, keyctl = sys.argv[1:]
assert os.geteuid() != 0
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
assert status["Seccomp"].strip() == "2"
assert not Path("/proc/1/status").exists()
assert not Path("/proc/sys").exists()
assert not Path("/proc/meminfo").exists()
assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)

probe = Path("/run") / service / "sandbox-probe"
with probe.open("x"):
    assert probe.stat().st_mode & 0o777 == 0o600
probe.unlink()
try:
    with Path("/etc/sandbox-probe").open("x"):
        raise AssertionError("/etc is writable")
except OSError as error:
    assert error.errno == errno.EROFS, error

try:
    with mmap.mmap(-1, mmap.PAGESIZE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                   prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC):
        raise AssertionError("writable executable memory is allowed")
except OSError as error:
    assert error.errno in (errno.EPERM, errno.EACCES), error

# A private session keyring normally permits this operation to its own user.
result = subprocess.run([keyctl, "new_session"], capture_output=True, text=True)
assert result.returncode != 0 and os.strerror(errno.EPERM) in result.stderr, result

for family in [socket.AF_UNIX, socket.AF_NETLINK]:
    with socket.socket(family, socket.SOCK_RAW if family == socket.AF_NETLINK else socket.SOCK_STREAM):
        pass
for family in ([socket.AF_INET, socket.AF_INET6] if service == "charon-kernel" else [socket.AF_PACKET]):
    try:
        with socket.socket(family, socket.SOCK_DGRAM):
            raise AssertionError(f"forbidden socket family {family} is allowed")
    except OSError as error:
        assert error.errno == errno.EAFNOSUPPORT, error
if service == "strongswan":
    for family in [socket.AF_INET, socket.AF_INET6]:
        with socket.socket(family, socket.SOCK_DGRAM):
            pass
    assert socket.getaddrinfo("localhost", 13000, type=socket.SOCK_DGRAM, flags=socket.AI_ADDRCONFIG)

print("sandbox probe passed", flush=True)
