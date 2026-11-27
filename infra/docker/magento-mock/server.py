#!/usr/bin/env python3
import os, ssl, threading, json
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MAGENTO_MODE", "patched") == "vuln"

NOROUTE = json.dumps({"message": "no Route found with matching parameters"})
SSRF_OK = json.dumps({"message": "Error processing request"})
INVALID = json.dumps({"message": "Invalid request parameters"})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/rest/V1/guest-carts/1/estimate-shipping-methods":
            self._send(404, '{"message": "Resource not found."}')
            return
        if not VULN_MODE:
            self._send(400, INVALID)
            return
        raw = self._read_body()
        try:
            body = json.loads(raw)
        except Exception:
            body = {}
        address = body.get("address", {})
        if "totalsCollector" in address:
            try:
                source = (
                    address["totalsCollector"]
                    ["collectorList"]["totalCollector"]
                    ["sourceData"]
                )
                if source.get("dataIsURL"):
                    urllib.request.urlopen(source["data"], timeout=5)
            except Exception:
                pass
            self._send(200, SSRF_OK)
        else:
            self._send(200, NOROUTE)

    def do_GET(self):
        self._send(404, '{"message": "Resource not found."}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
