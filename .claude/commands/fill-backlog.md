# noctis — fill-backlog

Tu es un agent de recherche et de triage de vulnérabilités pour le scanner noctis.
Ton rôle : identifier des CVEs/misconfigs à fort impact, vérifier qu'elles ne sont pas déjà
couvertes, et créer des issues GitHub bien documentées avec suffisamment de contexte pour
que l'agent-loop puisse les implémenter sans recherche supplémentaire.

---

## Étape 1 — Inventaire de l'existant

### Feeds déjà implémentés
```bash
ls tests/cve/        # ex: CVE-2021-44228.yaml
ls tests/misconfig/  # ex: tls-weak-config.yaml
```

### Issues déjà créées (éviter les doublons)
```bash
gh issue list --state all --limit 200 --json number,title,state \
  --jq '.[] | "\(.number) [\(.state)] \(.title)"'
```

Construire la liste `ALREADY_COVERED` (CVE IDs + noms de produits). Toute CVE dans cette
liste sera ignorée lors du sourçage.

---

## Étape 2 — Sourcer des candidats

Utiliser **toutes les sources ci-dessous** pour constituer une liste brute de candidats.

### Source A — Plugins OpenVAS locaux

```bash
# Plugins réseau actifs uniquement
find openvas/openvas/plugins/ -name "*.nasl" \
  | xargs grep -l "ACT_ATTACK\|ACT_GATHER_INFO" 2>/dev/null \
  | grep -iv "win_\|_win\|local\|package\|ssh_login\|smb_" \
  | sort
```

Priorité aux dossiers `2023/`, `2024/`, `2025/` et aux vendors :
apache, php, openssh, nginx, drupal, joomla, wordpress, gitlab, jenkins, teamcity,
grafana, nextcloud, owncloud, zoneminder, roundcube, vmware, citrix, ivanti,
paloalto, fortinet, cisco, juniper, qnap, synology, moodle, chamilo.

Pour chaque plugin intéressant :
```bash
grep -E "script_cve_id|script_name|cvss_base|severity_vector|qod_type|CISA|KEV|vuldetect|ACT_ATTACK" <fichier.nasl>
```

### Source B — EPSS (Exploit Prediction Scoring System)

API FIRST.org — renvoie le score de probabilité d'exploitation dans les 30 jours :
```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data'][0]['epss'] if d['data'] else 'N/A')"
```

Pour un lot de CVEs :
```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,CVE-C" | python3 -c "
import json, sys
for row in json.load(sys.stdin)['data']:
    print(f\"{row['cve']}: EPSS={float(row['epss']):.3f} percentile={float(row['percentile']):.1%}\")
"
```

Seuils : EPSS ≥ 0.50 = exploitation probable · ≥ 0.90 = exploitation active confirmée.

### Source C — PoC publics GitHub

```bash
# Chercher des repos PoC pour une CVE
gh search repos "CVE-XXXX-XXXXX" --sort stars --limit 10 \
  --json fullName,stargazersCount,description,updatedAt \
  --jq '.[] | "\(.stargazersCount)★ \(.fullName) — \(.description)"'
```

Interpréter :
- ≥ 100 étoiles → PoC mature, exploitation documentée
- ≥ 10 étoiles → PoC fonctionnel, implémentation réelle disponible
- 0 étoile → à recouper avec d'autres sources

Lire le README du PoC principal pour comprendre la technique d'exploitation et les
endpoints/payloads utilisés — c'est une source directe pour la stratégie de détection.

### Source D — Templates Nuclei (ProjectDiscovery)

Nuclei est un scanner YAML similaire à noctis. Ses templates sont une mine pour les
patterns de détection réseau.

```bash
# Chercher un template Nuclei pour la CVE
gh search repos "CVE-XXXX-XXXXX" --owner projectdiscovery --limit 5

# Ou directement dans nuclei-templates via l'API GitHub
gh api "search/code?q=CVE-XXXX-XXXXX+repo:projectdiscovery/nuclei-templates" \
  --jq '.items[] | .path'
```

Si un template existe, le récupérer :
```bash
gh api "repos/projectdiscovery/nuclei-templates/contents/<path>" \
  --jq '.content' | base64 -d
```

Un template Nuclei contient `requests:` avec les endpoints, payloads, et `matchers:` avec
les patterns de réponse — transposer directement en steps noctis.

### Source E — MITRE ATT&CK

Contexte tactique des CVEs pour enrichir la description et la priorité :

Techniques réseau les plus fréquentes dans noctis :
- **T1190** — Exploit Public-Facing Application (CVEs web, API, VPN)
- **T1133** — External Remote Services (VPN, RDP, Citrix, Pulse)
- **T1021.004** — Remote Services: SSH (OpenSSH, dropbear)
- **T1595.002** — Active Scanning: Vulnerability Scanning

Groupes APT connus pour exploiter la CVE (à mentionner dans l'issue) :
```bash
# Chercher dans ATT&CK via l'API MITRE
curl -s "https://attack.mitre.org/api/groups/?cve=CVE-XXXX-XXXXX" 2>/dev/null || true
# Ou WebSearch : "CVE-XXXX-XXXXX site:attack.mitre.org"
```

Si la CVE est associée à un groupe APT ou une campagne ransomware documentée, le mentionner
explicitement dans l'issue — ça justifie `priority:high`.

### Source F — Exploit-DB / Metasploit

```bash
# Chercher sur Exploit-DB via l'API
curl -s "https://www.exploit-db.com/search?cve=XXXX-XXXXX&type=webapps" 2>/dev/null || \
  echo "use WebSearch: site:exploit-db.com CVE-XXXX-XXXXX"

# Chercher un module Metasploit
gh search repos "CVE-XXXX-XXXXX" --owner rapid7 --limit 5
# Ou : gh api "search/code?q=CVE-XXXX-XXXXX+repo:rapid7/metasploit-framework" --jq '.items[].path'
```

Un module Metasploit = exploitation wormable ou semi-automatisable → +2 points, signaler
dans l'issue.

### Source G — CISA KEV (Known Exploited Vulnerabilities)

```bash
# Télécharger le catalogue KEV CISA et chercher la CVE
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | python3 -c "
import json, sys
kev = json.load(sys.stdin)
for v in kev['vulnerabilities']:
    if 'CVE-XXXX-XXXXX' in v['cveID']:
        print(f\"KEV: {v['cveID']} — {v['vendorProject']} {v['product']}\")
        print(f\"Due date: {v['dueDate']}\")
        print(f\"Notes: {v['notes']}\")
" 2>/dev/null
```

Ou pour trouver toutes les CVEs KEV récentes (2023-2025) d'un vendor :
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

## Étape 3 — Scoring

Pour chaque candidat non couvert, calculer un score sur 15 points :

| Critère | Points |
|---------|--------|
| **KEV CISA** (exploitation in-the-wild confirmée) | +4 |
| **EPSS ≥ 0.90** (exploitation quasi-certaine) | +3 |
| **EPSS 0.50–0.89** (exploitation probable) | +1 |
| **PoC GitHub ≥ 100 étoiles** (exploit mature et documenté) | +2 |
| **PoC GitHub 10–99 étoiles** (exploit fonctionnel) | +1 |
| **Template Nuclei existant** (pattern de détection prêt) | +2 |
| **Module Metasploit** (exploitation automatisable) | +1 |
| **CVSS ≥ 9.0** | +2 |
| **CVSS 7.0–8.9** | +1 |
| **Détection sans auth** (unauthenticated, accessible à froid) | +2 |
| **Produit très répandu** (Apache, PHP, Exchange, Confluence, SSH…) | +1 |
| **APT/ransomware documenté** sur cette CVE | +1 |

Priorité à assigner :
- `priority:high` : score ≥ 10
- `priority:medium` : score 6–9
- `priority:low` : score < 6 (mais coverage gap justifié)

Exclure si :
- Déjà dans ALREADY_COVERED
- CVSS < 7.0 ET pas KEV ET pas EPSS > 0.50
- Détection impossible sans agent local (plugin `smb_login`, `ssh_login`, `local`)
- Exploitation nécessite une session authentifiée (sauf si la CVE est une escalade
  d'une auth partielle bien documentée)

---

## Étape 4 — Enrichissement de chaque candidat retenu

Pour les **8 à 12 meilleurs candidats**, collecter :

1. **Plugin NASL complet** → logique de détection exacte (`http_get/post`, patterns)
2. **PoC GitHub principal** → lire le README pour comprendre l'exploit
3. **Template Nuclei** (si existe) → transposer les `requests` et `matchers`
4. **EPSS score** via API FIRST.org
5. **KEV entry** → `dueDate`, `notes`, `shortDescription`
6. **ATT&CK techniques** → T1190 / T1133 / autre selon le vecteur

---

## Étape 5 — Créer les issues GitHub

### Format du body

```markdown
### CVE ID
CVE-XXXX-XXXXX

### Produit / composant
<nom du produit, composant exact, vendor>

### Versions affectées
<plage précise — ex: "< 2.4.50", "8.5p1 – 9.7p1">

### Score CVSS v3
<score>

### Sévérité
<critical|high|medium|low|info>

### Services ciblés
<http, https, ssh, ...>

### Threat intelligence
- **EPSS** : <score> (<percentile>e percentile)
- **KEV CISA** : <oui / non — date d'ajout si oui>
- **PoC public** : <URL du PoC principal, étoiles GitHub>
- **Template Nuclei** : <oui / non — chemin si oui>
- **Module Metasploit** : <oui / non>
- **ATT&CK** : <T1190 — Exploit Public-Facing Application / autre>
- **Groupes APT / campagnes** : <si documenté — ex: "exploitée par LockBit 3.0">

### Description
<3-5 phrases : mécanisme de la vulnérabilité, pourquoi elle est exploitable,
impact réel, contexte d'exploitation in-the-wild si connu>

### Stratégie de détection
<Détailler précisément : endpoint cible, méthode HTTP, headers/body du payload,
pattern exact dans la réponse, QoD attendu>
Mentionner la source de cette stratégie (OpenVAS vuldetect / Nuclei matcher / PoC).

### Références
- https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
- <advisory officiel du vendor>
- <PoC GitHub principal>
- <Nuclei template si existe>
- <Plugin OpenVAS : chemin relatif>
- <Exploit-DB / Metasploit si existe>

### Notes pour le mock Docker
<Base image recommandée, comportement exact vuln vs patché, endpoints à exposer,
marqueur de confirmation à retourner, HTTP:80 + HTTPS:443>
```

### Commande de création
```bash
gh issue create \
  --title "<CVE-ID> — <Produit> <type court> (KEV / EPSS X.XX)" \
  --label "type:cve,status:available,priority:<high|medium|low>" \
  --body "$(cat <<'BODY'
<body>
BODY
)"
```

---

## Étape 6 — Rapport final

```
=== fill-backlog — résultats ===

Sources consultées :
  OpenVAS plugins : <N> candidats initiaux
  KEV CISA        : <N> entrées récentes (2023-2025)
  EPSS > 0.5      : <N> CVEs identifiées
  GitHub PoC      : <N> CVEs avec PoC ≥ 10★
  Nuclei templates: <N> templates trouvés

Déjà couvertes (ignorées) : <liste>

Issues créées :
  #XX [priority:high]   CVE-XXXX — Produit (CVSS 9.8, KEV, EPSS 0.97, PoC 234★)
  #XX [priority:medium] CVE-XXXX — Produit (CVSS 8.1, EPSS 0.72, Nuclei ✓)
  ...
```

---

## Règles absolues

- Ne jamais créer de doublon — vérifier ALREADY_COVERED avant chaque issue
- Toujours inclure le score EPSS (interroger l'API même si la valeur est basse)
- Toujours chercher le PoC GitHub et le template Nuclei avant de créer l'issue
- Toujours inclure la stratégie de détection **concrète** (endpoint + payload + pattern) —
  l'agent-loop ne doit pas avoir à chercher
- Toujours inclure les notes Docker avec le comportement exact vuln vs patché
- Limiter à **12 issues par exécution** pour maintenir la qualité de chaque fiche
- Si un template Nuclei existe, **le lire entièrement** avant de rédiger la stratégie de
  détection — c'est la source la plus directement transposable en steps noctis
