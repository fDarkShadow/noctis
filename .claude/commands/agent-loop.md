# noctis — agent loop

Tu es un agent d'implémentation autonome pour le scanner noctis.
Ton rôle : prendre un ticket GitHub, implémenter le feed + l'infra de test, ouvrir une PR.

## Cycle d'une itération

### 1. Trouver le prochain ticket disponible

```bash
gh issue list \
  --label "status:available" \
  --state open \
  --json number,title,labels,body \
  --jq 'sort_by(.labels | map(select(.name == "priority:high")) | length) | reverse | .[0]'
```

Si aucun ticket disponible : affiche "No available issues." et termine.

### 2. Revendiquer le ticket (verrou distribué)

```bash
ISSUE=<number>
gh issue edit $ISSUE \
  --add-label "status:in-progress" \
  --remove-label "status:available" \
  --assignee "@me"
```

### 3. Parser le contenu de l'issue

Extraire depuis le body (format GitHub Forms) :
- CVE ID ou nom du check
- Produit, versions affectées, sévérité, services
- Description, stratégie de détection, références, notes mock

### 4. Créer un worktree isolé

```bash
CVE=<cve-id>   # ex: CVE-2024-1234
BRANCH="feat/$CVE"
git worktree add "../noctis-$CVE" -b "$BRANCH"
cd "../noctis-$CVE"
```

### 5. Implémenter

Suivre scrupuleusement CLAUDE.md. Pour chaque CVE/misconfig :

**a) Feed YAML** — `tests/cve/<CVE>.yaml` ou `tests/misconfig/<name>.yaml`
  - Générer un UUID v4 valide (variant `[89ab]`)
  - `services:` toujours renseigné
  - `tcp_connect` pour tout payload encodé dans le path
  - Utiliser `resp.banner` (jamais `resp.data`)
  - Ne pas définir `port:` ou `scheme:` dans `vars:`

**b) Mock Docker** — `infra/docker/<name>/`
  - `Dockerfile.vuln` + `Dockerfile.patched`
  - Base Python `python:3.11-slim` si appliance propriétaire
  - HTTP:80 + HTTPS:443 (cert auto-signé via openssl)
  - Pattern `_make_https_server()` + `threading.Thread` pour les mocks Python
  - `SSLSessionCache none` + `Mutex file:` pour Apache (pas shmcb)
  - Debian Buster EOL : patcher sources.list → archive.debian.org

**c) Inventaire** — `infra/inventories/<CVE>/hosts.yml`
  - 4 hôtes : `_vuln`, `_vuln_https`, `_patched`, `_patched_https`
  - `container_port: 443` sur les hôtes https
  - Jamais de `target_port`

**d) Playbook** — `infra/playbooks/<CVE>.yml` (copier un existant)

**e) site.yml** — ajouter `import_playbook: playbooks/<CVE>.yml`

**f) Taskfile.yml** — ajouter le CVE à `vars.INVENTORIES`

**g) build_local_images.yml** — ajouter les tâches de build des nouvelles images

### 6. Builder les images

```bash
cd infra
task build
```

Si échec : diagnostiquer, corriger, recommencer. Ne pas passer à l'étape suivante.

### 7. Lancer les tests

```bash
task test CVE=<CVE>
```

Résultat attendu : 4 tests passants (vuln HTTP, vuln HTTPS, patched HTTP, patched HTTPS).

Si échec :
- Analyser la sortie Ansible
- Corriger le feed ou le mock
- Re-builder si nécessaire
- Relancer jusqu'à 3 tentatives
- Si toujours en échec après 3 tentatives : créer la PR avec label `needs-help` et documenter l'erreur dans le body

### 8. Valider le schéma

```bash
cd ..  # racine du repo
npx ajv-cli validate -s schemas/feed.schema.json \
  -d "tests/cve/<CVE>.yaml" --spec=draft7 --allow-union-types
```

Corriger toute erreur de validation avant de continuer.

### 9. Commiter et pousser

```bash
git add tests/ infra/ schemas/
git commit -m "feat(<CVE>): add detection feed and test infrastructure

- Feed YAML with <detection_method>
- Python/Docker mock (vuln + patched), HTTP + HTTPS
- Ansible inventory + playbook, 4 test cases

Closes #<ISSUE>"
git push origin "$BRANCH"
```

### 10. Ouvrir la PR

```bash
gh pr create \
  --title "feat(<CVE>): <product> — <short description>" \
  --body "$(cat <<'EOF'
## CVE / Check

**Issue:** #<ISSUE>
**CVE:** <CVE_ID>
**Product:** <product>
**CVSS:** <cvss>

## Implémentation

- Feed: `tests/cve/<CVE>.yaml`
- Mock: `infra/docker/<name>/` (HTTP:80 + HTTPS:443)
- Tests: 4 cas (vuln/patched × HTTP/HTTPS)

## Résultats des tests

```
<coller la sortie de task test>
```

## Checklist

- [ ] Feed YAML validé par ajv-cli
- [ ] UUID v4 valide
- [ ] 4 tests passants (TP×2 + TN×2)
- [ ] Schéma respecté (additionalProperties)
EOF
)"
```

### 11. Mettre à jour l'issue

```bash
gh issue edit $ISSUE \
  --add-label "status:review" \
  --remove-label "status:in-progress"
gh issue comment $ISSUE --body "PR ouverte : <pr_url>"
```

### 12. Nettoyer le worktree

```bash
cd /home/flo/workspace/iscan
git worktree remove "../noctis-$CVE" --force
```

## Règles absolues

- Ne jamais merger une PR
- Ne jamais hardcoder `target_port` dans un inventaire
- Ne jamais commiter sur `main` directement
- Si un test échoue et que tu ne sais pas pourquoi après 3 tentatives : ouvrir la PR avec le label `needs-help`
- Toujours générer un UUID v4 frais (ne pas réutiliser un UUID existant)
