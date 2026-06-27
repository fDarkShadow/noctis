#!/usr/bin/env python3
import subprocess
import sys
from packaging.version import Version

REQUIREMENTS = {
    "ansible": {
        "cmd": ["ansible", "--version"],
        "parse": lambda out: out.split("[core ")[1].split("]")[0],
        "min": "2.15",
    },
    "podman": {
        "cmd": ["podman", "--version"],
        "parse": lambda out: out.split()[2],
        "min": "4.0",
    },
    "cargo": {
        "cmd": ["cargo", "--version"],
        "parse": lambda out: out.split()[1],
        "min": "1.75",
    },
}

ok = True
for name, req in REQUIREMENTS.items():
    try:
        out = subprocess.check_output(req["cmd"], stderr=subprocess.DEVNULL, text=True)
        version = req["parse"](out.strip())
        if Version(version) < Version(req["min"]):
            print(f"  ✗ {name} {version} — requires >= {req['min']}")
            ok = False
        else:
            print(f"  ✓ {name} {version}")
    except (subprocess.CalledProcessError, FileNotFoundError, IndexError):
        print(f"  ✗ {name} not found")
        ok = False

sys.exit(0 if ok else 1)
