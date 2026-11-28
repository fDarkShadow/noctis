#!/usr/bin/env python3
# Apache Airflow Experimental REST API auth-bypass mock — CVE-2020-13927.
#
# VULN mode: the Experimental API (/api/experimental/*) serves real-shaped JSON
#   with 200 WITHOUT any auth, and 404s unknown /api/experimental/* subpaths
#   (a real Airflow routes the API and returns 404 for unknown endpoints).
# PATCHED mode: /api/experimental/* requires auth → 403.
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("AIRFLOW_MODE", "patched") == "vuln"

# Real Airflow /api/experimental/latest_runs response shape.
LATEST_RUNS = {
    "items": [
        {
            "dag_id": "example_bash_operator",
            "dag_run_url": "/admin/airflow/graph?dag_id=example_bash_operator&execution_date=2020-07-01T00%3A00%3A00%2B00%3A00",
            "execution_date": "2020-07-01T00:00:00+00:00",
            "start_date": "2020-07-01T00:00:05.123456+00:00",
        },
        {
            "dag_id": "example_python_operator",
            "dag_run_url": "/admin/airflow/graph?dag_id=example_python_operator&execution_date=2020-07-01T00%3A00%3A00%2B00%3A00",
            "execution_date": "2020-07-01T00:00:00+00:00",
            "start_date": "2020-07-01T00:00:06.654321+00:00",
        },
    ]
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Everything under the Experimental API is auth-gated when patched.
        if self.path.startswith("/api/experimental/"):
            if not VULN_MODE:
                # Patched: default auth backend replaced — auth required.
                self._send(403, "Forbidden")
                return
            # Vulnerable: no auth enforced. Route known endpoints only; a real
            # Airflow 404s unknown subpaths of the Experimental API.
            if self.path == "/api/experimental/latest_runs":
                self._send(200, json.dumps(LATEST_RUNS), ct="application/json")
            elif self.path == "/api/experimental/test":
                self._send(200, json.dumps({"status": "OK"}), ct="application/json")
            else:
                self._send(404, json.dumps({"error": "Not Found"}), ct="application/json")
            return
        self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
