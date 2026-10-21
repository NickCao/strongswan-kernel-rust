#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Break charon's kernel RPC connection without terminating either service.

Run as root in the test VM. pidfd_getfd duplicates a live descriptor; shutdown
affects the original socket too. No RPC bytes or process memory are modified.
"""
import ctypes
import os
from pathlib import Path
import socket
import sys


def disconnect(pid, path):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.pidfd_getfd.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    libc.pidfd_getfd.restype = ctypes.c_int
    pidfd = os.pidfd_open(pid)
    try:
        for entry in Path(f"/proc/{pid}/fd").iterdir():
            if not entry.readlink().as_posix().startswith("socket:["):
                continue
            duplicate = libc.pidfd_getfd(pidfd, int(entry.name), 0)
            if duplicate < 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code))
            with socket.socket(fileno=duplicate) as candidate:
                if candidate.family != socket.AF_UNIX:
                    continue
                try:
                    peer = candidate.getpeername()
                except OSError:
                    continue
                if peer == path:
                    candidate.shutdown(socket.SHUT_RDWR)
                    return
        raise AssertionError("charon's kernel RPC socket was not found")
    finally:
        os.close(pidfd)


if __name__ == "__main__":
    disconnect(int(sys.argv[1]), sys.argv[2])
