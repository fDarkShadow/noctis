#!/usr/bin/env python3
"""Elasticsearch mock for the Groovy scripting sandbox-bypass detection check.

CVE-2015-1427: dynamic inline Groovy scripting in a _search request.

vuln:    POST /_search with a `script_fields` Groovy script evaluates the
         (arithmetic-only) script server-side and reflects the computed value
         in the response's script_fields — exactly as a vulnerable ES 1.3/1.4
         node with dynamic Groovy scripting enabled does.
patched: inline scripting disabled -> POST /_search returns an error
         ("scripts of type [inline], operation [search] and lang [groovy] are
         not enabled") and never evaluates or reflects the value.

Only addition is honoured; anything that is not "<int> + <int>" is rejected as
a compile error, so the mock never executes arbitrary code. The detection feed
only ever sends an arithmetic expression.

Serves HTTP:80 and HTTPS:443 (self-signed cert generated at build time).
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("ES_MODE", "patched") == "vuln"

# GET / cluster banner (an ES 1.4.2 node, which is in the affected range).
BANNER = json.dumps({
    "status": 200,
    "name": "noctis-node-1",
    "cluster_name": "noctis-cluster",
    "version": {
        "number": "1.4.2",
        "build_hash": "927caff6f05403e936c20bf4529f144f0c89fd8c",
        "lucene_version": "4.10.2",
    },
    "tagline": "You Know, for Search",
})

# Patched node: inline Groovy scripting disabled.
SCRIPT_DISABLED = json.dumps({
    "error": "SearchPhaseExecutionException[Failed to execute phase [query], "
             "all shards failed; ... ScriptException[scripts of type [inline], "
             "operation [search] and lang [groovy] are not enabled]]",
    "status": 400,
})

# Only a bare "<int> + <int>" arithmetic expression is honoured server-side.
ARITH_RE = re.compile(r"^\s*(-?\d+)\s*\+\s*(-?\d+)\s*$")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(200, BANNER)
        else:
            self._send(404, json.dumps({"status": 404}))

    def do_POST(self):
        if not self.path.startswith("/_search"):
            self._send(404, json.dumps({"status": 404}))
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""

        if not VULN_MODE:
            # Patched: inline scripting refused, nothing evaluated.
            self._send(400, SCRIPT_DISABLED)
            return

        # Vulnerable: evaluate the inline Groovy script_fields scripts.
        try:
            req = json.loads(raw.decode("utf-8") or "{}")
        except (ValueError, UnicodeDecodeError):
            self._send(400, json.dumps({"error": "parse_exception", "status": 400}))
            return

        fields = {}
        for name, spec in (req.get("script_fields") or {}).items():
            script = (spec or {}).get("script", "")
            m = ARITH_RE.match(str(script))
            if m:
                value = int(m.group(1)) + int(m.group(2))
                fields[name] = [value]
            else:
                # A real vulnerable node would run it; this mock only does
                # arithmetic, so refuse anything else.
                self._send(400, json.dumps({
                    "error": "ScriptException[failed to run inline script]",
                    "status": 400,
                }))
                return

        resp = {
            "took": 1,
            "timed_out": False,
            "hits": {
                "total": 1,
                "max_score": 1.0,
                "hits": [{
                    "_index": "noctis",
                    "_type": "doc",
                    "_id": "1",
                    "_score": 1.0,
                    "fields": fields,
                }],
            },
        }
        self._send(200, json.dumps(resp))


if __name__ == "__main__":
    serve(Handler, HTTPServer)
