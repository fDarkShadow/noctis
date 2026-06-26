"""Mock ownCloud Graph API server — CVE-2023-49103 vulnerable behaviour."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("OWNCLOUD_MODE", "vuln") == "vuln"

PHPINFO_PATH = "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php"

PHPINFO_BODY = b"""<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
</style>
</head><body>
<div class="center">
<table>
<tr class="h"><td>
<a href="http://www.php.net/"><img border="0" src="/php_logo.png" alt="PHP logo" /></a>
<h1 class="p">PHP Version 8.1.0</h1>
</td></tr>
</table><br />
<table>
<tr><td class="e">System</td><td class="v">Linux owncloud-server 5.15.0</td></tr>
<tr><td class="e">Build Date</td><td class="v">Jan 10 2022 12:00:00</td></tr>
</table>
<table>
<tr class="h"><th>Variable</th><th>Value</th></tr>
<tr><td class="e">OWNCLOUD_ADMIN_USERNAME</td><td class="v">admin</td></tr>
<tr><td class="e">OWNCLOUD_ADMIN_PASSWORD</td><td class="v">noctis_secret</td></tr>
<tr><td class="e">OWNCLOUD_DB_PASSWORD</td><td class="v">dbpassword123</td></tr>
<tr><td class="e">OWNCLOUD_MAIL_SMTP_PASSWORD</td><td class="v">smtppassword</td></tr>
</table>
</div></body></html>"""


class OwnCloudHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        # Strip query string for matching
        path = self.path.split("?")[0]

        if path == PHPINFO_PATH or path == PHPINFO_PATH + "/.css" or path == PHPINFO_PATH + "/.js":
            if VULN_MODE:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=UTF-8")
                self.send_header("Content-Length", str(len(PHPINFO_BODY)))
                self.end_headers()
                self.wfile.write(PHPINFO_BODY)
            else:
                body = b"Not Found"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        else:
            body = b"Not Found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def _make_https_server(handler, port):
    import ssl
    srv = HTTPServer(("0.0.0.0", port), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


if __name__ == "__main__":
    import threading
    mode = "vuln" if VULN_MODE else "patched"
    http_srv = HTTPServer(("0.0.0.0", 80), OwnCloudHandler)
    https_srv = _make_https_server(OwnCloudHandler, 443)
    print(f"ownCloud graphapi mock on :80/:443 (mode={mode})", flush=True)
    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()
