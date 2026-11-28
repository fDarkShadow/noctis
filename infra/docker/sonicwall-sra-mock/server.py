#!/usr/bin/env python3
# Mock SonicWall SRA / SMA "Virtual Assist" supportLogin CGI for CVE-2019-7481.
#
# The real bug: customerTID is placed into a SQLite query with the %s formatter
# instead of %q, so it is NOT escaped. This mock reproduces that exactly:
#
#   vuln     -> builds  WHERE tid='<customerTID>'  with the raw value and
#               evaluates the resulting boolean. A tautology injected through
#               customerTID (0' OR '1'='1) makes the WHERE true and the server
#               returns a different page than an always-false condition
#               (0' OR '1'='2) or a benign value (no such tid) -> genuine
#               boolean-based blind SQL injection.
#   patched  -> escapes the quote (' -> '') so the value is a single string
#               literal that never matches: every input returns the same
#               "no customer" page, so there is no differential to detect.
#
# A benign (non-injection) customerTID returns the normal "no customer" page in
# BOTH modes, so the vuln mock only exhibits SQLi behaviour for an injected
# payload.
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("SRA_MODE", "patched") == "vuln"

# tid of the (only) stored row — attacker input never legitimately equals it.
ROW_TID = "__noctis_sentinel_tid__"

FOUND_PAGE = (
    "<html><head><title>Virtual Assist</title></head><body>"
    "<h1>SonicWALL Virtual Assist</h1>"
    "<div id='session'>Support session located. Technician queue ready.</div>"
    "<form action='/cgi-bin/supportSession' method='post'>"
    "<input type='hidden' name='tid' value='active'></form>"
    "</body></html>"
)

NOCUSTOMER_PAGE = (
    "<html><head><title>Virtual Assist</title></head><body>"
    "<h1>SonicWALL Virtual Assist</h1>"
    "<div id='login'>No support session found for the supplied TID. "
    "Please enter your technician ID.</div>"
    "<form action='/cgi-bin/supportLogin' method='get'>"
    "<input type='text' name='customerTID'></form>"
    "</body></html>"
)


def _eval_term(term):
    # term like  tid='x'  or  '1'='1'  — compare the two operands as the SQL
    # engine would, with surrounding single quotes stripped; the column `tid`
    # resolves to the stored row's sentinel value.
    if "=" not in term:
        return False
    lhs, rhs = term.split("=", 1)

    def val(tok):
        tok = tok.strip()
        if len(tok) >= 2 and tok.startswith("'") and tok.endswith("'"):
            return tok[1:-1]
        if tok == "tid":
            return ROW_TID
        return tok

    return val(lhs) == val(rhs)


def _eval_where(expr):
    # Minimal boolean evaluator over OR/AND of equality terms. OR has lower
    # precedence than AND, matching SQL.
    for or_part in expr.split(" OR "):
        if all(_eval_term(t) for t in or_part.split(" AND ")):
            return True
    return False


def _row_matched(customer_tid):
    if VULN_MODE:
        # Unsafe %s interpolation — the raw value becomes SQL structure.
        where = "tid='%s'" % customer_tid
        try:
            return _eval_where(where)
        except Exception:
            return False
    else:
        # Safe %q-equivalent: escape the quote, the value stays a literal.
        escaped = customer_tid.replace("'", "''")
        where = "tid='%s'" % escaped
        # A literal comparison can only be true if it equals the stored tid.
        return where == "tid='%s'" % ROW_TID


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "SonicWALL SSL-VPN Web Server")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        if parts.path == "/cgi-bin/supportLogin":
            qs = parse_qs(parts.query, keep_blank_values=True)
            customer_tid = qs.get("customerTID", [""])[0]
            if _row_matched(customer_tid):
                self._send(200, FOUND_PAGE)
            else:
                self._send(200, NOCUSTOMER_PAGE)
        else:
            self._send(404, "Not found")

    def do_POST(self):
        self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
