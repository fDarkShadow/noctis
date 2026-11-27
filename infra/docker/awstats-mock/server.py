#!/usr/bin/env python3
# AWStats mock for CVE-2017-1000501 (awstats.pl `config` directory traversal).
# vuln: AWStats < 7.7 opens the traversed path as its config file and emits
#       config-parser warnings echoing that path.
# patched: AWStats 7.7 strips path characters from `config`, so no traversed
#          file is opened and the path never appears in the output.
import os, re, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, parse_qs
from mocklib import serve

VULN_MODE = os.environ.get("AWSTATS_MODE", "patched") == "vuln"
SCRIPT_PATHS = ("/cgi-bin/awstats.pl",)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # Raw request path — no normalisation of ../ sequences.
        parts = urlsplit(self.path)
        if parts.path not in SCRIPT_PATHS:
            self._send(404, "Not found", "text/plain")
            return
        config = parse_qs(parts.query).get("config", [""])[0]
        if VULN_MODE and "/" in config:
            body = (
                '<html><head><meta name="generator" content="AWStats 7.6 (build 20161204)">'
                "</head><body>\n"
                f"Warning: Syntax error line 1 in file '{config}'. Config line is ignored.<br>\n"
                f"Warning: Syntax error line 2 in file '{config}'. Config line is ignored.<br>\n"
                f"Error: Setup ('{config}' file, web server or permissions) may be wrong.<br>\n"
                "Check config file, permissions and AWStats documentation (in 'docs' directory).\n"
                "</body></html>\n"
            )
            self._send(200, body)
            return
        safe = re.sub(r"[^-\w.@]", "", config)
        body = (
            '<html><head><meta name="generator" content="AWStats 7.7 (build 20180105)">'
            "</head><body>\n"
            f'Error: Couldn\'t open config file "awstats.{safe}.conf" nor "awstats.conf" '
            "after searching in path \"/etc/awstats,/usr/local/etc/awstats,/etc\": No such file or directory<br>\n"
            "Check config file, permissions and AWStats documentation (in 'docs' directory).\n"
            "</body></html>\n"
        )
        self._send(200, body)

    def do_POST(self): self.do_GET()


if __name__ == "__main__":
    serve(Handler, HTTPServer)
