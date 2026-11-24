#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("EFRONT_MODE", "patched") == "vuln"

# The injected query, reflected (decoded) in the SQL error message.
INJECTED = "0 UNION select concat(login,0x2e,password),1,1,1,1 from users -- x"
# The concat(login,0x2e,password) UNION result — admin login + "." + password
# hash — the NASL extra_check "admin". Produced ONLY by the real injection.
ADMIN_ROW = "admin.5f4dcc3b5aa765d61d8327deb882cf99"

# eFront page title — served in both modes (realistic app fingerprint).
TITLE = "<title>eFront</title>"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/html"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        # Chat endpoint — the injectable chatrooms_ID parameter.
        if p.startswith("/ask_chat.php"):
            if VULN_MODE and "union" in p.lower() and "concat" in p.lower():
                # Vulnerable: the UNION dumps admin.<password> and echoes the query.
                self._send(200,
                    "<html><head>%s</head><body>"
                    "<b>Warning</b>: You have an error in your SQL syntax; "
                    "check the manual near '%s' at line 1"
                    "<div class='chat-user'>%s</div>"
                    "</body></html>" % (TITLE, INJECTED, ADMIN_ROW))
            else:
                # Patched (or benign request): normal eFront chat page, no dump.
                self._send(200,
                    "<html><head>%s</head><body><h1>Chat</h1>"
                    "<p>No chatroom available.</p></body></html>" % TITLE)
        else:
            self._send(404, "<html><body>404 Not Found</body></html>")

    def do_POST(self):
        self.do_GET()

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
