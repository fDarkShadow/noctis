#!/usr/bin/env python3
"""Mock Zoho ManageEngine ServiceDesk Plus — CVE-2021-37415.

Vuln mode: the REST API v3 list endpoint /api/v3/requests is reachable WITHOUT
authentication and returns the authentic ServiceDesk Plus v3 JSON envelope
(response_status.status_code 2000 + a list_info block + the records).

Patched mode: the same unauthenticated request is rejected with 401 and a login
redirect — the API data is never disclosed.

Both modes gate a still-protected endpoint (/api/v3/users): it returns 401 even in
vuln mode, proving the detection keys on the specific affected path, not a blanket
open API.
"""
import os
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from mocklib import serve

VULN_MODE = os.environ.get("MANAGEENGINE_MODE", "patched") == "vuln"

# Authentic ServiceDesk Plus REST API v3 response envelope for a /requests list.
REQUESTS_BODY = json.dumps({
    "response_status": {
        "status_code": 2000,
        "status": "success",
    },
    "list_info": {
        "has_more_rows": False,
        "start_index": 1,
        "sort_field": "created_time",
        "sort_order": "desc",
        "row_count": 1,
    },
    "requests": [
        {
            "id": "1",
            "subject": "Unable to connect to VPN",
            "status": {"name": "Open", "id": "1"},
            "requester": {"name": "John Doe", "id": "4"},
            "created_time": {"value": "1514764800000", "display_value": "Jan 1, 2018 12:00 AM"},
        }
    ],
})

LOGIN_REDIRECT = (
    "<html><head><meta http-equiv=\"refresh\" "
    "content=\"0;URL=/SetUpWizard.do?forwardTo=workstation\"></head>"
    "<body>You are not authorized. Please log in.</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        # Still-protected endpoint: 401 even in vuln mode (detection must not fire here).
        if path == "/api/v3/users":
            self._send(401, LOGIN_REDIRECT)
            return

        # Affected list endpoint.
        if path == "/api/v3/requests":
            if VULN_MODE:
                self._send(200, REQUESTS_BODY, "application/json")
            else:
                self._send(401, LOGIN_REDIRECT)
            return

        self._send(404, "Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            self.rfile.read(length)
        self._send(404, "Not found")


if __name__ == "__main__":
    serve(Handler, HTTPServer)
