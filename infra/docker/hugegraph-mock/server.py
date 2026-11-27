#!/usr/bin/env python3
import os, ssl, threading, json, re
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("HUGEGRAPH_MODE", "patched") == "vuln"

PROBE_RESULT = json.dumps({
    "result": {
        "data": {"@type": "g:List", "@value": [{"@type": "g:Int32", "@value": 2}]},
        "meta": {"@type": "g:Map", "@value": []}
    },
    "status": {"message": "", "code": 200}
})

OOB_RESULT = json.dumps({
    "result": {
        "data": {"@type": "g:List", "@value": []},
        "meta": {"@type": "g:Map", "@value": []}
    },
    "status": {"message": "", "code": 200}
})

UNAUTH = json.dumps({"exception": "unauthorized", "message": "Authentication required"})


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
        if self.path != "/gremlin":
            self._send(404, '{"exception":"not found"}')
            return
        if not VULN_MODE:
            self._send(401, UNAUTH)
            return
        raw = self._read_body()
        try:
            gremlin = json.loads(raw).get("gremlin", "")
        except Exception:
            gremlin = ""
        if "openStream" in gremlin:
            m = re.search(r'new URL\("(http://[^"]+)"\)', gremlin)
            if m:
                try:
                    urllib.request.urlopen(m.group(1), timeout=5)
                except Exception:
                    pass
            self._send(200, OOB_RESULT)
        else:
            self._send(200, PROBE_RESULT)

    def do_GET(self):
        self._send(404, '{"exception":"not found"}')


if __name__ == "__main__":
    serve(Handler, HTTPServer)
