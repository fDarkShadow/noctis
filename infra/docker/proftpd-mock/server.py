#!/usr/bin/env python3
"""ProFTPd mod_copy control-channel mock for CVE-2015-3306.

Pure protocol simulation of the FTP control channel — it only returns canned
FTP response strings. No subprocess, no exec, no os.system, no real file I/O:
SITE CPFR/CPTO never touch the filesystem, they just reply with a status line.

Modes (PROFTPD_MODE):
  vuln     mod_copy accepts SITE CPFR/CPTO PRE-AUTH (350 / 250), while benign
           commands (PWD, CWD, LIST ...) are rejected pre-auth with 530.
  patched  mod_copy requires login: SITE CPFR is rejected pre-auth (530), same
           as every other command.
  cheat    a naive responder that answers 350 to EVERY command (used only to
           prove the feed's control gate is not fooled by a constant 350).

Plaintext FTP control channel on $FTP_PORT (default 21); only the control
dialogue is modelled, no data connection.
"""
import os
import socket
import threading

MODE = os.environ.get("PROFTPD_MODE", "patched")
VULN = MODE == "vuln"
CHEAT = MODE == "cheat"
PORT = int(os.environ.get("FTP_PORT", "21"))

BANNER = b"220 ProFTPD 1.3.5 Server (NOCTIS mod_copy mock) [127.0.0.1]\r\n"
# Reject benign commands issued before authentication (real ProFTPd behaviour).
NEED_LOGIN = b"530 Please login with USER and PASS.\r\n"
CPFR_OK = b"350 File or directory exists, ready for destination name.\r\n"
CPTO_OK = b"250 Copy successful.\r\n"


def reply(cmd, user):
    """Return the canned response bytes for one control command."""
    upper = cmd.upper()

    # Naive faker: 350 to everything. The feed's control gate must reject this.
    if CHEAT:
        return b"350 ok\r\n"

    if upper.startswith("USER"):
        return b"331 Password required for " + (user or b"user") + b".\r\n"
    if upper.startswith("PASS"):
        # We never authenticate in detection; mock always declines the login.
        return b"530 Login incorrect.\r\n"
    if upper.startswith("SYST"):
        return b"215 UNIX Type: L8\r\n"
    if upper.startswith("FEAT"):
        return b"211 End\r\n"
    if upper.startswith("QUIT"):
        return b"221 Goodbye.\r\n"

    # mod_copy commands — the crux of CVE-2015-3306.
    if upper.startswith("SITE CPFR"):
        return CPFR_OK if VULN else NEED_LOGIN
    if upper.startswith("SITE CPTO"):
        return CPTO_OK if VULN else NEED_LOGIN

    # Benign control commands: always need login pre-auth (both vuln & patched).
    if upper.split(" ", 1)[0] in (
        "PWD", "CWD", "CDUP", "LIST", "NLST", "RETR", "STOR",
        "MKD", "RMD", "DELE", "SITE",
    ):
        return NEED_LOGIN
    return b"500 Unknown command.\r\n"


def handle(conn):
    conn.sendall(BANNER)
    f = conn.makefile("rb")
    user = None
    try:
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("utf-8", "replace").strip()
            if cmd.upper().startswith("USER"):
                user = (cmd.split(" ", 1)[1].strip() if " " in cmd else "").encode()
            resp = reply(cmd, user)
            conn.sendall(resp)
            if cmd.upper().startswith("QUIT"):
                break
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
