#!/usr/bin/env python3
"""Mock VMware Spring Cloud Gateway Actuator — CVE-2022-22947 SpEL injection.

Models the Gateway Actuator route API used by the vulnerability:

    POST   /actuator/gateway/routes/<id>   add a route (JSON body with filters)
    POST   /actuator/gateway/refresh       (re)build routes — triggers evaluation
    GET    /actuator/gateway/routes/<id>   read the applied route back
    DELETE /actuator/gateway/routes/<id>   delete a route

Vuln mode: when a route's filter value contains a SpEL expression #{ A * B }
(benign integer multiplication), the `refresh` step *evaluates* the arithmetic
and the stored/applied route reflects the computed product. This mirrors the
real vulnerability's sink: SpEL in a filter value is evaluated server-side.
Only pure `<int> * <int>` arithmetic is evaluated here — the mock contains no
code-execution capability of any kind.

Patched mode: the Actuator refuses to evaluate the expression; the route is
stored with the filter value kept *literal* (#{ A * B } verbatim), so the
computed product never appears. (A real patched/locked-down deployment may also
simply 404 the Actuator; either way the arithmetic differential stays clean.)
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("SCG_MODE", "patched") == "vuln"

# Matches a benign SpEL integer-multiplication expression: #{ 12345 * 67890 }
ARITH_RE = re.compile(r"#\{\s*(\d+)\s*\*\s*(\d+)\s*\}")

# In-memory route store: id -> route definition dict (as applied).
ROUTES = {}


def _apply_filters(route, evaluate):
    """Return a copy of the route with filter values resolved.

    When `evaluate` is True, a #{A*B} filter value is replaced by the product
    A*B (SpEL evaluated). When False, the value is kept verbatim (literal)."""
    applied = json.loads(json.dumps(route))
    for flt in applied.get("filters", []):
        args = flt.get("args", {}) if isinstance(flt, dict) else {}
        val = args.get("value")
        if not isinstance(val, str):
            continue
        m = ARITH_RE.search(val)
        if m and evaluate:
            args["value"] = str(int(m.group(1)) * int(m.group(2)))
    return applied


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="application/json"):
        if not isinstance(body, (bytes, bytearray)):
            if not isinstance(body, str):
                body = json.dumps(body)
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route_id(self, path):
        # /actuator/gateway/routes/<id>
        prefix = "/actuator/gateway/routes/"
        if path.startswith(prefix):
            rid = path[len(prefix):].strip("/")
            return rid or None
        return None

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""

        if path == "/actuator/gateway/refresh":
            # (Re)build every route. Vuln mode evaluates SpEL arithmetic now.
            for rid, route in list(ROUTES.items()):
                ROUTES[rid] = _apply_filters(route, evaluate=VULN_MODE)
            self._send(200, "")
            return

        rid = self._route_id(path)
        if rid is not None:
            try:
                route = json.loads(raw or b"{}")
            except Exception:
                route = {}
            route.setdefault("id", rid)
            # Store the raw definition; evaluation happens on refresh.
            ROUTES[rid] = route
            self._send(201, "")
            return

        self._send(404, {"status": 404, "error": "Not Found"})

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/actuator/gateway/routes":
            self._send(200, list(ROUTES.values()))
            return
        rid = self._route_id(path)
        if rid is not None:
            route = ROUTES.get(rid)
            if route is None:
                self._send(404, {"status": 404, "error": "Not Found"})
                return
            self._send(200, route)
            return
        if path == "/":
            self._send(200, "Spring Cloud Gateway", "text/plain")
            return
        self._send(404, {"status": 404, "error": "Not Found"})

    def do_DELETE(self):
        path = self.path.split("?", 1)[0]
        rid = self._route_id(path)
        if rid is not None:
            ROUTES.pop(rid, None)
            self._send(200, "")
            return
        self._send(404, {"status": 404, "error": "Not Found"})


if __name__ == "__main__":
    serve(Handler, HTTPServer)
