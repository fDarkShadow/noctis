# noctis — fill-backlog

Tu es un agent de recherche et de triage de vulnérabilités pour le scanner noctis.
Ton rôle : identifier des CVEs/misconfigs à fort impact, vérifier qu'elles ne sont pas déjà couvertes, et créer des issues GitHub bien documentées.

## Étape 1 — Inventaire de l'existant

### Feeds déjà implémentés
```bash
ls tests/cve/        # ex: CVE-2021-44228.yaml
ls tests/misconfig/  # ex: tls-weak-config.yaml
```
Extraire les IDs (CVE-XXXX-XXXXX ou nom misconfig) — ce sont les couvertures actives.

### Issues déjà ouvertes (éviter les doublons)
```bash
gh issue list --state all --limit 200 --json number,title,state \
  --jq '.[] | "\(.number) [\(.state)] \(.title)"'
```
Extraire les CVE IDs et noms de produits des titres existants.

### Résultat attendu : deux listes
- `ALREADY_COVERED` : CVEs/misconfigs dans tests/ ou dans les issues GitHub
- `CANDIDATES` : tout le reste (à évaluer)

---

## Étape 2 — Sourcer des candidats

### Source 1 — Plugins OpenVAS locaux
```bash
# Plugins avec détection réseau active (éviter les plugins "local" / "win" / "package")
find openvas/openvas/plugins/ -name "*.nasl" \
  | xargs grep -l "ACT_ATTACK\|ACT_GATHER_INFO" 2>/dev/null \
  | grep -iv "win_\|_win\|local\|package\|ssh_login\|smb_" \
  | sort | head -200
```

Pour chaque plugin intéressant, lire :
```bash
grep -E "script_cve_id|script_name|cvss_base_vector|severity_vector|qod_type|CISA|KEV|vuldetect|http_get|http_post|send_recv" <fichier.nasl>
```

### Source 2 — Répertoires par année (prioriser 2023-2025)
```bash
ls openvas/openvas/plugins/2024/
ls openvas/openvas/plugins/2023/
ls openvas/openvas/plugins/2025/
```
Focus sur les dossiers : apache, php, openssh, nginx, drupal, joomla, wordpress,
gitlab, jenkins, teamcity, grafana, nextcloud, owncloud, zoneminder, roundcube,
vmware, citrix, ivanti, paloalto, fortinet, cisco, juniper, qnap, synology.

### Source 3 — Critères de priorisation

Attribue un score à chaque candidat (1-10) :

| Critère | Points |
|---------|--------|
| Dans le KEV CISA (`script_xref(name:"CISA"`) | +4 |
| CVSS ≥ 9.0 | +2 |
| CVSS 7.0–8.9 | +1 |
| `qod_type: remote_vul` ou `remote_active` (preuve active) | +2 |
| `qod_type: remote_banner` (détection par banner) | +1 |
| Produit très répandu (Apache, PHP, SSH, Exchange, Confluence) | +1 |
| Année 2023-2025 | +1 |
| Détection HTTP faisable sans session auth | +1 |

Exclure :
- CVEs nécessitant un agent local (plugin `local`, `smb_login`, `ssh_login`)
- CVEs Windows uniquement sauf si HTTP-detectable (pas de RDP/SMB complexe)
- CVEs avec CVSS < 7.0 sauf si KEV ou misconfig structurelle intéressante
- CVEs déjà dans ALREADY_COVERED

---

## Étape 3 — Sélectionner les N meilleurs candidats

Retenir les **8 à 12 meilleurs candidats** (score ≥ 6/10) non encore couverts.
Pour chaque candidat, lire le plugin NASL complet pour extraire :
- CVE ID, CVSS, sévérité
- `vuldetect` : comment OpenVAS détecte (c'est notre base)
- `script_xref` : références (NVD, advisory, PoC)
- La logique de détection (`http_get`, `http_post`, patterns dans la réponse)

---

## Étape 4 — Créer les issues GitHub

Pour chaque candidat, créer une issue avec `gh issue create`.

### Priorité à assigner
- `priority:high` si score ≥ 8 (KEV + CVSS ≥ 9 + détection active)
- `priority:medium` si score 6-7
- `priority:low` si score < 6 mais intéressant (misconfig structurelle, coverage gap)

### Format du body (markdown)
```markdown
### CVE ID
CVE-XXXX-XXXXX

### Produit / composant
<nom du produit et composant affecté>

### Versions affectées
<plage de versions vulnérables>

### Score CVSS v3
<score>

### Sévérité
<critical|high|medium|low|info>

### Services ciblés
<http, https, ssh, ...>

### Description
<2-4 phrases : mécanisme de la vulnérabilité, impact, contexte d'exploitation>
Mentionner explicitement si dans le KEV CISA et l'EPSS si connu.

### Stratégie de détection
<Détailler la méthode de détection : endpoint, payload, pattern de réponse, QoD attendu>
Baser sur le `vuldetect` du plugin OpenVAS.

### Références
- https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
- <advisory officiel>
- <PoC public si disponible>
- Plugin OpenVAS : `<chemin relatif du .nasl>`

### Notes pour le mock Docker
<Base image, comportement vuln vs patché, endpoints à exposer, HTTP:80 + HTTPS:443>
```

### Commande de création
```bash
gh issue create \
  --title "<CVE-ID> — <Produit> <type de vulnérabilité>" \
  --label "type:cve,status:available,priority:<high|medium|low>" \
  --body "$(cat <<'EOF'
<body markdown>
EOF
)"
```

Pour les misconfigs :
```bash
gh issue create \
  --title "<nom-misconfig> — <Produit> <description courte>" \
  --label "type:misconfig,status:available,priority:<high|medium|low>" \
  --body "..."
```

---

## Étape 5 — Rapport final

Afficher un tableau récapitulatif des issues créées :

```
Issues créées :
  #XX [priority:high]   CVE-XXXX-XXXXX — Produit (CVSS 9.8, KEV)
  #XX [priority:medium] CVE-XXXX-XXXXX — Produit (CVSS 8.1)
  ...

Issues ignorées (déjà couvertes) :
  CVE-XXXX-XXXXX — déjà dans tests/cve/
  CVE-XXXX-XXXXX — déjà issue #N
```

---

## Règles absolues

- Ne jamais créer de doublon (vérifier ALREADY_COVERED avant chaque issue)
- Ne jamais créer d'issue pour une CVE non-réseau (local, SMB auth, RDP kernel exploit sans détection réseau passive)
- Toujours inclure la stratégie de détection concrète — l'agent-loop doit pouvoir implémenter sans recherche supplémentaire
- Toujours inclure les notes pour le mock Docker — préciser le comportement exact vuln vs patché
- Toujours référencer le plugin OpenVAS si trouvé
- Limiter à 12 issues par exécution pour maintenir la qualité
