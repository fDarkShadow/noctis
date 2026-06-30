#!/usr/bin/env python3
import json, os, re, ssl, threading, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("ACTIVEMQ_MODE", "patched") == "vuln"

JOLOKIA_READ_RESP = json.dumps([{
    "request": {
        "type": "read",
        "mbean": "org.apache.activemq:type=Broker,brokerName=localhost",
        "attribute": "BrokerName"
    },
    "value": "localhost",
    "timestamp": 1700000000,
    "status": 200
}])

def _fetch_url(url):
    try:
        urllib.request.urlopen(url, timeout=10)
    except Exception:
        pass

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path.startswith("/api/jolokia"):
            if VULN_MODE:
                # If addNetworkConnector with xbean: URI, fetch it to trigger OOB callback
                m = re.search(r'xbean:(https?://[^\s"\'\\]+)', body)
                if m:
                    threading.Thread(target=_fetch_url, args=(m.group(1),), daemon=True).start()
                self._send(200, JOLOKIA_READ_RESP)
            else:
                self._send(403, json.dumps({"error": "403 Forbidden - Jolokia access denied"}))
        else:
            self._send(404, "Not found", ct="text/plain")

    def do_GET(self):
        self._send(200, "<html><body>Apache ActiveMQ Web Console</body></html>", ct="text/html")

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
