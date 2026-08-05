## Tâche du plan d'action

**Code tâche :** P<n>.<m>  
**Lien vers PLAN_ACTION.md :** ligne XXX  
**Phase :** <n> — <Nom de la phase>

---

## Description

<!-- Résumé en 2-3 phrases : qu'est-ce qui change et pourquoi ? -->

---

## Changements principaux

<!-- Liste bullet des modifications majeures -->

- [ ] Nouveau collector `<nom>` pour <OS>
- [ ] Nouvelle règle de détection `<rule_id>`
- [ ] Nouvel endpoint API `<METHOD> /api/v1/<path>`
- [ ] Nouveau worker `<worker_name>`
- [ ] Modification interface `<Interface>` (BREAKING CHANGE ⚠)

---

## Tests

### Tests ajoutés

- [ ] Tests unitaires : `<fichier_test>`
- [ ] Tests d'intégration : `<fichier_test>`
- [ ] Tests E2E : `<scénario>`
- [ ] Couverture : **XX%** (minimum 80%)

### Plan de test manuel (si applicable)

```bash
# Commandes pour reproduire le test localement
```

**Résultat attendu :**
<!-- Décrire ce qui doit se passer -->

---

## Références architecture

**Sections lues :**
- [ ] `ARCHITECTURE.md` §<X>.<Y>
- [ ] Fichiers contrats (Annexe) : `<fichier>`

**Interfaces respectées :**
- [ ] `PlatformDriver` (Go)
- [ ] `Collector` (Go)
- [ ] `EventBus` (Python)
- [ ] `EventRepository` (Python)
- [ ] Autre : `<Interface>`

---

## Breaking changes

- [ ] **Non** — changements rétrocompatibles
- [ ] **Oui** — changements cassants (détailler ci-dessous)

<!-- Si Oui, décrire l'impact et la migration nécessaire -->

---

## Screenshots (UI uniquement)

<!-- Si changement UI, ajouter des screenshots avant/après -->

---

## Checklist avant review

### Code

- [ ] Lint passe (`golangci-lint` / `ruff` / `eslint`)
- [ ] Tests passent localement
- [ ] Build passe localement
- [ ] Aucun `TODO` / `FIXME` non justifié
- [ ] Logs structurés JSON avec `trace_id` si applicable
- [ ] Aucun secret en dur (clés API, mots de passe)

### Documentation

- [ ] Docstrings/comments sur fonctions publiques
- [ ] `CONTRIBUTING.md` respecté
- [ ] Commit messages formatés selon `P<n>.<m>: <description>`

### Sécurité

- [ ] Pas d'injection SQL / XSS / command injection
- [ ] Input validation sur tous les endpoints API
- [ ] Pas de fuite mémoire / goroutine leak (Go)

### Performance

- [ ] Agent : CPU < 4% sur workload standard
- [ ] Pas de boucle infinie / attente active
- [ ] Ressources nettoyées proprement (fermeture channels, connections)

---

## Reviewers suggérés

<!-- Mentionner 1-2 reviewers appropriés -->
- @virus-one (lead, architecture)
- @<senior-dev> (expertise <domaine>)

---

## Notes additionnelles

<!-- Tout contexte utile pour le reviewer -->
