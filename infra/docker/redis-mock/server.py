#!/usr/bin/env python3
"""Minimal Redis mock for the unauthenticated-access check.

vuln:    answers PING/INFO without auth (INFO returns redis_version ...).
patched: requirepass set -> every command returns "-NOAUTH Authentication required.".
Speaks just enough of the inline RESP protocol for the check.
"""
import os
import socket
import threading

VULN = os.environ.get("REDIS_MODE", "patched") == "vuln"
PORT = int(os.environ.get("REDIS_PORT", "6379"))

INFO_BODY = (
    "# Server\r\n"
    "redis_version:7.0.12\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux\r\n"
    "tcp_port:6379\r\n"
)
NOAUTH = b"-NOAUTH Authentication required.\r\n"


def handle(conn):
    f = conn.makefile("rb")
    try:
        while True:
            line = f.readline()
            if not line:
                break
            cmd = line.decode("utf-8", "replace").strip()
            if not cmd:
                continue
            word = cmd.split()[0].upper()
            if not VULN:
                conn.sendall(NOAUTH)
                continue
            if word == "PING":
                conn.sendall(b"+PONG\r\n")
            elif word == "INFO":
                body = INFO_BODY.encode()
                conn.sendall(f"${len(body)}\r\n".encode() + body + b"\r\n")
            elif word == "QUIT":
                conn.sendall(b"+OK\r\n")
                break
            else:
                conn.sendall(b"+OK\r\n")
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
