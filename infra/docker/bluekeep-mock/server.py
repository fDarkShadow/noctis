#!/usr/bin/env python3
import os, socket, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("BLUEKEEP_MODE", "patched") == "vuln"


def _handle_rdp_conn(conn):
    try:
        conn.settimeout(1.0)
        try:
            conn.recv(4096)
        except Exception:
            pass
        conn.settimeout(None)
        if VULN_MODE:
            conn.sendall(b"BlueKeep-Vulnerable\r\n")
        else:
            conn.sendall(b"NLA-Required\r\n")
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _rdp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 3389))
    srv.listen(10)
    while True:
        try:
            conn, _ = srv.accept()
            threading.Thread(target=_handle_rdp_conn, args=(conn,), daemon=True).start()
        except Exception:
            break


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def do_GET(self):
        body = b"RDP BlueKeep Mock"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    threading.Thread(target=_rdp_server, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
