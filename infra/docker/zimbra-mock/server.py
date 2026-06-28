#!/usr/bin/env python3
import os, socket, threading

VULN_MODE = os.environ.get("ZIMBRA_MODE", "patched") == "vuln"


def handle_client(conn):
    try:
        conn.sendall(b"220 zimbra.local ESMTP Zimbra\r\n")
        buf = b""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                line = line.strip()
                if not line:
                    continue
                cmd = line.upper()
                if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                    conn.sendall(b"250 OK\r\n")
                elif cmd.startswith(b"MAIL FROM"):
                    conn.sendall(b"250 OK\r\n")
                elif cmd.startswith(b"RCPT TO"):
                    if VULN_MODE and b"$(" in line:
                        conn.sendall(b"250 message delivered\r\n")
                    elif VULN_MODE:
                        conn.sendall(b"250 OK\r\n")
                    else:
                        conn.sendall(b"550 5.1.3 Invalid address\r\n")
                elif cmd.startswith(b"DATA"):
                    conn.sendall(b"354 End data with <CR LF>.<CR LF>\r\n")
                elif line == b".":
                    conn.sendall(b"250 OK\r\n")
                elif cmd.startswith(b"QUIT"):
                    conn.sendall(b"221 Bye\r\n")
                    return
                elif cmd.startswith(b"RSET") or cmd.startswith(b"NOOP"):
                    conn.sendall(b"250 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


def serve_smtp(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(32)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve_smtp(25)
