FROM docker.io/library/httpd:2.4

# Standard Apache without CGI configured — no path in the feed can execute bash
# Shellshock payloads injected via HTTP headers have no effect → true negative

EXPOSE 80
