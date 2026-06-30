#!/usr/bin/env python3
import os, ssl, threading, json, re
from http.server import BaseHTTPRequestHandler, HTTPServer
try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
except ImportError:
    pass

VULN_MODE = os.environ.get("LIVEWIRE_MODE", "patched") == "vuln"

LIVEWIRE_VERSION = "3.6.3" if VULN_MODE else "3.6.4"

HOMEPAGE = ("""<!DOCTYPE html>
<html>
<head>
  <meta name="csrf-token" content="dummy-csrf-token">
  <title>Laravel Livewire App</title>
</head>
<body>
  <div
    wire:id="noctis-component"
    wire:snapshot="{&quot;data&quot;:{},&quot;memo&quot;:{&quot;id&quot;:&quot;noctis-component&quot;,&quot;name&quot;:&quot;counter&quot;}}"
    data-update-uri="/livewire/update"
    data-csrf="dummy-csrf-token"
  >
    <p>Count: <span wire:model="count">0</span></p>
  </div>
  <script src="/livewire/livewire.js?v=LIVEWIRE_VERSION_PLACEHOLDER"></script>
</body>
</html>
""").replace("LIVEWIRE_VERSION_PLACEHOLDER", LIVEWIRE_VERSION).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            self._send(200, HOMEPAGE, "text/html")
        else:
            self._send(404, "Not found")

    def do_POST(self):
        if self.path == "/livewire/update":
            body = self._read_body()
            if VULN_MODE:
                # Simulate vulnerable Livewire: execute commands from calls[].params
                m = re.search(r'curl\s+(https?://[^\s"\'\\]+)', body)
                if m:
                    oob_url = m.group(1)
                    threading.Thread(target=self._fetch, args=(oob_url,), daemon=True).start()
                self._send(200, json.dumps({
                    "components": [{"snapshot": "{}", "effects": {"html": "<p>0</p>", "dirty": []}}]
                }), "application/json")
            else:
                # Patched: reject payload — HMAC validation fails
                self._send(403, json.dumps({
                    "message": "This request is not secure. Snapshot HMAC validation failed."
                }), "application/json")
        else:
            self._send(404, "Not found")

    def _fetch(self, url):
        try:
            req = Request(url, headers={"User-Agent": "curl/7.88.1"})
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            urlopen(req, timeout=10, context=ctx)
        except Exception:
            pass


def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
