#!/usr/bin/env python3
"""Minimal finger mock. vuln: returns user listing; patched: no service (close)."""
import os, socket, threading
VULN = os.environ.get("FINGER_MODE", "patched") == "vuln"
PORT = int(os.environ.get("FINGER_PORT", "79"))
INFO = (b"Login: root       Name: root\r\n"
        b"Directory: /root    Shell: /bin/bash\r\n"
        b"Last login Tue Nov 18 09:12 on tty1\r\n"
        b"Login: admin      Name: admin\r\n"
        b"Directory: /home/admin   Shell: /bin/bash\r\n")
def handle(c):
    f = c.makefile("rb")
    try:
        c.settimeout(5)
        f.readline()  # query line
        if VULN:
            c.sendall(INFO)
        # patched: finger disabled -> send nothing
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
