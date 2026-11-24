---
title: Writing feeds
nav_order: 4
---
{% raw %}
# Writing feeds

A feed is a YAML file describing a vulnerability or misconfiguration and the sequence of steps
that prove it. Feeds live under `tests/vulnerabilities/<product>/<id>.yaml`.

## Structure

```yaml
uid: 7f3d1b9a-4c62-4e8d-9a07-2b5e6c1f84d0   # stable UUID v4 — never change
name: "Elasticsearch exposed without authentication"
cves: []                    # 0, 1, or many CVE IDs
category: exposure          # free-form classifier (used when cves is empty)
severity: critical          # info | low | medium | high | critical
confidence_base: 0.50       # raised by confidence_delta on match
tags: [elasticsearch, unauthenticated, exposure]
services: [http, https]     # nmap service names — [] = run on all ports
author: noctis
version: "1.0.0"

steps:
  - id: probe
    action: http_request
    method: GET
    path: "/"
    port: "{{port}}"
    store_as: es

  - id: check
    action: match
    source: es.body
    pattern: "You Know, for Search"
    condition: "es.status == 200"
    on_match:
      finding:
        title: "Elasticsearch exposed without authentication"
        confidence_delta: 0.35
        qod: 75
        evidence: "Unauthenticated banner: {{es.body}}"
```

`cves` cardinality — a feed is a *vulnerability test*, not a "CVE test":

```yaml
cves: []                               # misconfiguration / exposure check
cves: [CVE-2021-44228]                 # the common case
cves: [CVE-2023-46805, CVE-2024-21887] # a chain tracked by several CVE IDs
```

## Step actions

| Action | Purpose |
|--------|---------|
| `http_request` | HTTP/HTTPS request; result: `resp.status`, `resp.body`, `resp.headers` |
| `tcp_connect` | Raw TCP connect + banner grab; result: `resp.banner` |
| `tcp_dialogue` | Multi-line TCP exchange (text) **or** a binary `send_hex` frame; result: `resp.transcript`, `resp.response_hex` |
| `tcp_syn` | TCP SYN probe (port state) |
| `udp_probe` | UDP datagram probe; result: `resp.response`, `resp.response_hex` |
| `tls_check` | TLS version, cipher, certificate inspection |
| `ssh_check` | SSH banner + auth methods |
| `ssh_exec` | Authenticated SSH command |
| `snmp_get` | SNMP v2c GET |
| `match` | Regex match on a stored value (supports `negate`, `case_insensitive`, `condition`) |
| `script` | Arbitrary [Rhai](https://rhai.rs) expression |
| `wait_oob` | Wait for an out-of-band callback |
| `set_var` | Assign a context variable |
| `sleep` | Pause between steps (`duration_ms`) |

Expression helpers available in `match`/`script` include string/regex/byte functions, crypto
(`md5`, `sha256`, `hmac_sha256`, `base64_*`), binary `pack`/`unpack`, and `rand_*`.

## Automatic variables

| Variable | Value |
|----------|-------|
| `{{target_host}}` | Target IP / hostname |
| `{{port}}` | Port of the matched service (injected — do not redefine) |
| `{{scheme}}` | `http` or `https`, derived from the matched service |
| `{{oob_token}}` | UUID unique to this run |
| `{{oob_url}}` | Full OOB callback URL |
| `{{oob_enabled}}` | `true` when `--oob` is configured |

## Confidence / QoD

| QoD | Meaning |
|-----|---------|
| 50 | Banner or version match |
| 70 | Specific header / response pattern |
| 75 | Functional proof (LFI `/etc/passwd`, unauthenticated data) |
| 97 | OOB callback received, or confirmed RCE |
| 100 | Full exploit with verified output |

## `tcp_connect` vs `http_request`

Use `tcp_connect` for any payload encoded in the path — reqwest normalises URLs before sending
(`%2e` → `.`, then resolves `../`), which breaks path-traversal exploits.

```yaml
- action: tcp_connect
  send: "GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
  store_as: resp
- action: match
  source: resp.banner        # .banner, not .data
  pattern: "root:.*:0:0"
```

## Parsing a binary reply

For a binary protocol, send one raw frame with `tcp_dialogue` + `send_hex` and parse the
reply's `response_hex` in a `script` step: byte offset *N* is hex offset *2N*, `substr` takes an
**inclusive** end, and `u16le`/`u32be`/… decode a fixed-width integer. The script can return a
map, which later `match` / `condition:` steps read with dot notation. The magic bytes stay in
the feed — no engine change per protocol. From
[`general/smb-signing-not-required.yaml`](https://github.com/fDarkShadow/noctis/blob/main/tests/vulnerabilities/general/smb-signing-not-required.yaml)
(SMB2 NEGOTIATE → `SecurityMode` at byte 70, `DialectRevision` at byte 72; abridged — the
shipped feed also names the dialect and flags legacy-only 2.x servers):

```yaml
- id: smb2-negotiate
  action: tcp_dialogue
  port: "{{port}}"
  read_banner: false
  send_hex: "0000009efe534d42…"          # NBSS + SMB2 header + NEGOTIATE (5 dialects)
  store_as: smb

- id: parse-negotiate
  action: script
  condition: "smb.connected == true"
  store_as: neg
  code: |
    let hex = if type_of(smb.response_hex) == "string" { smb.response_hex } else { "" };
    let mode = u16le(substr(hex, 140, 143));   // byte 70
    let rev  = u16le(substr(hex, 144, 147));   // byte 72
    // Prove it is a NEGOTIATE *response*, not an echo of the request:
    let ok = strlen(hex) >= 148
      && substr(hex, 8, 15) == "fe534d42"           // SMB2 signature
      && u32le(substr(hex, 24, 31)) == 0            // Status OK
      && (u32le(substr(hex, 40, 47)) & 1) == 1      // Flags: SERVER_TO_REDIR
      && u16le(substr(hex, 136, 139)) == 65         // response StructureSize
      && (rev == 0x0202 || rev == 0x0210 || rev == 0x0300 || rev == 0x0302 || rev == 0x0311);
    #{ smb2: ok, signing_required: (mode & 2) == 2, dialect_hex: p16be(rev) }

- id: check-signing
  action: match
  source: neg.signing_required
  pattern: "^false$"
  condition: "neg.smb2 == true"
  on_match:
    finding:
      title: "SMB signing not required"
      qod: 75
      evidence: "dialect 0x{{neg.dialect_hex}}, signing not required"
```

When a later frame depends on a value from an earlier reply (challenge–response), use
`tcp_open` / `tcp_send` / `tcp_close` instead and build the next `send_hex` in the `script`.

## Validate a feed

```sh
npx ajv-cli validate -s schemas/feed.schema.json \
  -d "tests/vulnerabilities/*/*.yaml" --spec=draft7 --allow-union-types
```

{: .note }
> The full authoring reference — mock template, inventory structure, pitfalls, and reference
> feeds to copy from — lives in
> [`CLAUDE.md`](https://github.com/fDarkShadow/noctis/blob/main/CLAUDE.md). See also
> [Contributing](contributing.html).
{% endraw %}
