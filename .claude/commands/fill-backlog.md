# noctis — fill-backlog

You are a vulnerability research and triage agent for the noctis scanner.
Your role: identify high-impact CVEs/misconfigs, verify they are not already covered,
and create well-documented GitHub issues with enough context for the agent-loop to
implement them without additional research.

---

## Step 1 — Inventory what already exists

### Already-implemented feeds
```bash
ls tests/cve/        # e.g. CVE-2021-44228.yaml
ls tests/misconfig/  # e.g. tls-weak-config.yaml
```

### Already-created issues (avoid duplicates)
```bash
gh issue list --state all --limit 200 --json number,title,state \
  --jq '.[] | "\(.number) [\(.state)] \(.title)"'
```

Build the `ALREADY_COVERED` list (CVE IDs + product names). Any CVE on this list is
skipped during sourcing.

---

## Step 2 — Source candidates

Use **all sources below** to build a raw candidate list.

### Source A — Local OpenVAS plugins

```bash
# Network-active plugins only (skip local/package/SMB/auth-required)
find openvas/openvas/plugins/ -name "*.nasl" \
  | xargs grep -l "ACT_ATTACK\|ACT_GATHER_INFO" 2>/dev/null \
  | grep -iv "win_\|_win\|local\|package\|ssh_login\|smb_" \
  | sort
```

Prioritise subdirectories `2023/`, `2024/`, `2025/` and vendors:
apache, php, openssh, nginx, drupal, joomla, wordpress, gitlab, jenkins, teamcity,
grafana, nextcloud, owncloud, zoneminder, roundcube, vmware, citrix, ivanti,
paloalto, fortinet, cisco, juniper, qnap, synology, moodle, chamilo.

For each interesting plugin:
```bash
grep -E "script_cve_id|script_name|cvss_base|severity_vector|qod_type|CISA|KEV|vuldetect|ACT_ATTACK" <file.nasl>
```

### Source B — EPSS (Exploit Prediction Scoring System)

FIRST.org API — returns the probability of exploitation within 30 days:
```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data'][0]['epss'] if d['data'] else 'N/A')"
```

For a batch of CVEs:
```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,CVE-C" | python3 -c "
import json, sys
for row in json.load(sys.stdin)['data']:
    print(f\"{row['cve']}: EPSS={float(row['epss']):.3f} percentile={float(row['percentile']):.1%}\")
"
```

Thresholds: EPSS ≥ 0.50 = likely exploited · ≥ 0.90 = actively exploited in the wild.

### Source C — Public PoCs on GitHub

```bash
# Search for PoC repos for a CVE
gh search repos "CVE-XXXX-XXXXX" --sort stars --limit 10 \
  --json fullName,stargazersCount,description,updatedAt \
  --jq '.[] | "\(.stargazersCount)★ \(.fullName) — \(.description)"'
```

Interpretation:
- ≥ 100 stars → mature exploit, well-documented technique
- ≥ 10 stars → functional PoC, real exploitation available
- 0 stars → cross-check with other sources

Read the README of the top PoC to understand the exploitation technique and the exact
endpoints/payloads — this is a direct source for the detection strategy.

### Source D — Nuclei templates (ProjectDiscovery)

Nuclei is a YAML-based scanner similar to noctis. Its templates are a goldmine for
network detection patterns.

```bash
# Search for a Nuclei template for the CVE
gh api "search/code?q=CVE-XXXX-XXXXX+repo:projectdiscovery/nuclei-templates" \
  --jq '.items[] | .path'
```

If a template exists, fetch it:
```bash
gh api "repos/projectdiscovery/nuclei-templates/contents/<path>" \
  --jq '.content' | base64 -d
```

A Nuclei template contains `requests:` with endpoints and payloads, and `matchers:` with
response patterns — transpose directly into noctis steps.

### Source E — MITRE ATT&CK

Tactical context for CVEs to enrich descriptions and priority:

Most relevant techniques for noctis:
- **T1190** — Exploit Public-Facing Application (web CVEs, APIs, VPNs)
- **T1133** — External Remote Services (VPN, RDP, Citrix, Pulse)
- **T1021.004** — Remote Services: SSH (OpenSSH, dropbear)
- **T1595.002** — Active Scanning: Vulnerability Scanning

If the CVE is associated with a documented APT group or ransomware campaign, mention it
explicitly in the issue — it justifies `priority:high`.

### Source F — Exploit-DB / Metasploit

```bash
# Search for a Metasploit module
gh api "search/code?q=CVE-XXXX-XXXXX+repo:rapid7/metasploit-framework" \
  --jq '.items[].path'
```

A Metasploit module = wormable or semi-automated exploitation → +1 point, flag in issue.

### Source G — CISA KEV (Known Exploited Vulnerabilities)

```bash
# Download the KEV catalogue and search for a CVE
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | python3 -c "
import json, sys
kev = json.load(sys.stdin)
for v in kev['vulnerabilities']:
    if 'CVE-XXXX-XXXXX' in v['cveID']:
        print(f\"KEV: {v['cveID']} — {v['vendorProject']} {v['product']}\")
        print(f\"Added: {v['dateAdded']}  Due: {v['dueDate']}\")
        print(f\"Notes: {v['notes']}\")
"
```

To surface recent KEV entries (2023-2025) for relevant vendors:
```bash
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | python3 -c "
import json, sys
kev = json.load(sys.stdin)
for v in kev['vulnerabilities']:
    if v['dateAdded'] >= '2023-01-01':
        print(f\"{v['cveID']} {v['vendorProject']} {v['product']} (added {v['dateAdded']})\")
" | grep -i "apache\|php\|confluence\|exchange\|nginx\|drupal\|citrix\|pulse\|ivanti\|fortinet\|palo\|cisco\|vmware\|gitlab\|jenkins" | head -40
```

---

## Step 3 — Scoring

For each uncovered candidate, compute a score out of 15:

| Criterion | Points |
|-----------|--------|
| **KEV CISA** (confirmed in-the-wild exploitation) | +4 |
| **EPSS ≥ 0.90** (near-certain exploitation) | +3 |
| **EPSS 0.50–0.89** (likely exploitation) | +1 |
| **GitHub PoC ≥ 100 stars** (mature, documented exploit) | +2 |
| **GitHub PoC 10–99 stars** (functional PoC available) | +1 |
| **Nuclei template exists** (detection pattern ready to transpose) | +2 |
| **Metasploit module** (automated exploitation available) | +1 |
| **CVSS ≥ 9.0** | +2 |
| **CVSS 7.0–8.9** | +1 |
| **Unauthenticated detection** (exploitable cold, no session needed) | +2 |
| **Widely deployed product** (Apache, PHP, Exchange, Confluence, SSH…) | +1 |
| **Documented APT group / ransomware campaign** | +1 |

Priority to assign:
- `priority:high` : score ≥ 10
- `priority:medium` : score 6–9
- `priority:low` : score < 6 (but justified coverage gap)

Exclude if:
- Already in ALREADY_COVERED
- CVSS < 7.0 AND not KEV AND EPSS < 0.50
- Detection requires a local agent (`smb_login`, `ssh_login`, `local` plugin)
- Exploitation requires an authenticated session (unless the CVE is a well-documented
  auth bypass or privilege escalation from partial auth)

---

## Step 4 — Enrich each selected candidate

For the **8 to 12 best candidates**, collect:

1. **Full NASL plugin** → exact detection logic (`http_get/post`, response patterns)
2. **Top GitHub PoC** → read the README to understand the exploit technique
3. **Nuclei template** (if exists) → transpose `requests` and `matchers` into noctis steps
4. **EPSS score** via FIRST.org API
5. **KEV entry** → `dateAdded`, `dueDate`, `notes`, `shortDescription`
6. **ATT&CK techniques** → T1190 / T1133 / other based on the attack vector

---

## Step 5 — Create GitHub issues

### Body format

```markdown
### CVE ID
CVE-XXXX-XXXXX

### Product / component
<product name, exact component, vendor>

### Affected versions
<precise range — e.g. "< 2.4.50", "8.5p1 – 9.7p1">

### CVSS v3 score
<score>

### Severity
<critical|high|medium|low|info>

### Target services
<http, https, ssh, ...>

### Threat intelligence
- **EPSS**: <score> (<percentile>th percentile)
- **KEV CISA**: <yes / no — date added if yes>
- **Public PoC**: <URL of top PoC, star count>
- **Nuclei template**: <yes / no — path if yes>
- **Metasploit module**: <yes / no>
- **ATT&CK**: <T1190 — Exploit Public-Facing Application / other>
- **APT groups / campaigns**: <if documented — e.g. "exploited by LockBit 3.0">

### Description
<3-5 sentences: vulnerability mechanism, why it is exploitable, real-world impact,
in-the-wild exploitation context if known>

### Detection strategy
<Precise detail: target endpoint, HTTP method, headers/body payload, exact response
pattern to match, expected QoD>
Cite the source of this strategy (OpenVAS vuldetect / Nuclei matcher / PoC README).

### References
- https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
- <vendor advisory>
- <top GitHub PoC>
- <Nuclei template if exists>
- <OpenVAS plugin: relative path>
- <Exploit-DB / Metasploit if exists>

### Docker mock notes
<Recommended base image, exact vuln vs patched behaviour, endpoints to expose,
confirmation marker to return, HTTP:80 + HTTPS:443>
```

### Creation command
```bash
gh issue create \
  --title "<CVE-ID> — <Product> <short type> (KEV / EPSS X.XX)" \
  --label "type:cve,status:available,priority:<high|medium|low>" \
  --body "$(cat <<'BODY'
<body>
BODY
)"
```

For misconfigs:
```bash
gh issue create \
  --title "<check-name> — <Product> <short description>" \
  --label "type:misconfig,status:available,priority:<high|medium|low>" \
  --body "..."
```

---

## Step 6 — Final report

```
=== fill-backlog — results ===

Sources consulted:
  OpenVAS plugins  : <N> initial candidates
  CISA KEV         : <N> recent entries (2023-2025)
  EPSS > 0.5       : <N> CVEs identified
  GitHub PoC       : <N> CVEs with PoC ≥ 10★
  Nuclei templates : <N> templates found

Already covered (skipped): <list>

Issues created:
  #XX [priority:high]   CVE-XXXX — Product (CVSS 9.8, KEV, EPSS 0.97, PoC 234★)
  #XX [priority:medium] CVE-XXXX — Product (CVSS 8.1, EPSS 0.72, Nuclei ✓)
  ...
```

---

## Hard rules

- Never create a duplicate — check ALREADY_COVERED before every issue
- Always include the EPSS score (query the API even if the value is low)
- Always search for a GitHub PoC and a Nuclei template before creating the issue
- Always include a **concrete** detection strategy (endpoint + payload + pattern) —
  the agent-loop must be able to implement without any further research
- Always include Docker mock notes with the exact vuln vs patched behaviour
- Cap at **12 issues per run** to maintain the quality of each entry
- If a Nuclei template exists, **read it in full** before writing the detection strategy —
  it is the most directly transposable source into noctis steps
