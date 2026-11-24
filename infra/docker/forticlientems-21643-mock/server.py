#!/usr/bin/env python3
import os, ssl, threading, json, re, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("FORTICLIENTEMS_MODE", "patched") == "vuln"

INIT_RESP = json.dumps({"SITES_ENABLED": True, "version": "7.4.4", "status": "ok"})
ERROR_RESP = json.dumps({"error": "Database query failed", "status": "error"})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/api/v1/init_consts"):
            site_header = self.headers.get("Site", "")
            # Check if Site header contains pg_sleep injection
            m = re.search(r'pg_sleep\((\d+)\)', site_header, re.IGNORECASE)
            if m and VULN_MODE:
                sleep_secs = min(int(m.group(1)), 30)
                time.sleep(sleep_secs)
                self._send(500, ERROR_RESP)
            else:
                # Normal response — fingerprint endpoint (both vuln and patched)
                self._send(200, INIT_RESP)
        else:
            self._send(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        self._send(404, json.dumps({"error": "Not found"}))


if __name__ == "__main__":
    serve(Handler, HTTPServer)
