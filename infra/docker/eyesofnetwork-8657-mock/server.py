#!/usr/bin/env python3
"""Mock for CVE-2020-8657 — EyesOfNetwork eonapi hardcoded API key.

Models the /eonapi/getApiVersion read-only info endpoint, which requires a
valid apiKey. EyesOfNetwork wraps the API status in the JSON body (the HTTP
status stays 200), so rejection is signalled by "http_code": "401 ...".

Modes (EYESOFNETWORK8657_MODE):
  vuln    — the hardcoded apiKey is accepted; every other key is rejected.
  patched — the hardcoded apiKey has been removed; ALL keys are rejected.
  cheat   — adversarial control: ANY key is accepted (a permissive endpoint
            that does not really validate the key). The feed's bogus-key
            control must defeat this (expect 0 findings).
"""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from mocklib import serve

MODE = os.environ.get("EYESOFNETWORK8657_MODE", "patched")
HARDCODED_KEY = "1c85d47ff80b5ff2a4dd577e8e5f8e9d"

AUTH_OK = '{"http_code": "200 OK", "api_version": "5.3-11", "status": "authenticated"}'
AUTH_ERR = '{"http_code": "401 Unauthorized", "error": "Invalid API key"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _accepts(self, key):
        if MODE == "cheat":
            return True          # accepts ANY key — the permissive/cheating endpoint
        if MODE == "vuln":
            return key == HARDCODED_KEY
        return False             # patched: the hardcoded key is gone, reject all

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/eonapi/getApiVersion":
            qs = parse_qs(parsed.query)
            key = (qs.get("apiKey") or [""])[0]
            # Always HTTP 200; the API verdict lives in the JSON body.
            self._send(200, AUTH_OK if self._accepts(key) else AUTH_ERR)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
