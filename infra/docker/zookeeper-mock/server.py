#!/usr/bin/env python3
"""Minimal ZooKeeper 4lw mock. vuln: `envi` dumps environment; patched: refused."""
import os, socket, threading
VULN = os.environ.get("ZK_MODE", "patched") == "vuln"
PORT = int(os.environ.get("ZK_PORT", "2181"))
ENVI = (b"Environment:\nzookeeper.version=3.8.0-fake, built on 2023-01-01\n"
        b"host.name=zk01\njava.version=11.0.1\nuser.dir=/opt/zookeeper\n")
DENY = b"envi is not executed because it is not in the whitelist.\n"
def handle(c):
    try:
        c.settimeout(5)
        cmd = c.recv(16)[:4]
        if cmd == b"envi":
            c.sendall(ENVI if VULN else DENY)
    except OSError:
        pass
    finally:
        c.close()
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT)); s.listen(16)
    while True:
        c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
if __name__ == "__main__":
    main()
