#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Expose Cargo's executable as a Meson build/install artifact."""
import json
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    cargo, manifest, target_dir, output = sys.argv[1:]
    command = [cargo, "build", "--locked", "--release", "--manifest-path", manifest,
               "--target-dir", target_dir, "--message-format=json-render-diagnostics"]
    executable = None
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            message = json.loads(line)
            if (message.get("reason") == "compiler-artifact"
                    and message.get("target", {}).get("name") == "charon-kernel-daemon"
                    and message.get("executable")):
                executable = Path(message["executable"])
            elif message.get("reason") == "compiler-message":
                rendered = message["message"].get("rendered")
                if rendered:
                    print(rendered, file=sys.stderr, end="")
        result = process.wait()
    if result:
        raise SystemExit(result)
    if executable is None:
        raise SystemExit("Cargo did not produce charon-kernel-daemon")
    shutil.copy2(executable, output)


if __name__ == "__main__":
    main()
