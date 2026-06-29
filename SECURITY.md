# Security Policy

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| older   | no        |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities by email to **florian.schaal.16@gmail.com** with the subject line `[noctis] Security Report`.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected version(s) or commit

You can expect an acknowledgement within **48 hours** and a status update within **7 days**.

If a fix is needed, a patched release will be published and you will be credited in the changelog (unless you prefer to remain anonymous).

## Scope

This policy covers the noctis scanner engine and its bundled YAML feeds.
Test infrastructure (mock Docker images under `infra/`) is intentionally vulnerable by design and is out of scope.
