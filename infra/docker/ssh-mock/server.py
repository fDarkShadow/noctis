#!/usr/bin/env python3
"""Mock SSH server for the default-credentials check (paramiko).

vuln:    accepts a well-known default credential (root:toor, root:root,
         admin:admin) and runs `id`, returning root's id output.
patched: rejects all password auth.
"""
import os
import socket
import threading
import time

import paramiko

VULN = os.environ.get("SSH_MODE", "patched") == "vuln"
PORT = int(os.environ.get("SSH_PORT", "22"))
ALLOWED = {("root", "toor"), ("root", "root"), ("admin", "admin")}
HOST_KEY = paramiko.RSAKey.generate(2048)
ID_OUTPUT = b"uid=0(root) gid=0(root) groups=0(root)\n"


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if VULN and (username, password) in ALLOWED:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode("utf-8", "replace") if isinstance(command, bytes) else command
        out = ID_OUTPUT if "id" in cmd else b""
        try:
            channel.sendall(out)
            channel.send_exit_status(0)
        finally:
            channel.close()
        return True


def handle(conn):
    transport = paramiko.Transport(conn)
    transport.add_server_key(HOST_KEY)
    try:
        transport.start_server(server=Server())
        chan = transport.accept(20)
        if chan is not None:
            time.sleep(1)  # let the exec reply flush before teardown
    except Exception:
        pass
    finally:
        try:
            transport.close()
        except Exception:
            pass


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
