# Plan de release OSEye v0.1.0-alpha.1

Date : 2026-08-12

## Objectifs

1. Nettoyer les docs (garder README, LICENSE, DESCRIPTION pour la release ; le reste est dev-only)
2. Mettre en place le packaging et le versioning semantique
3. Creer le site officiel open-source avec documentation complete

---

## Partie A — Nettoyage documentation

### Fichiers gardes a la racine

| Fichier | Role |
|---------|------|
| `README.md` | Page d'accueil du projet |
| `LICENSE` | Apache 2.0 |
| `docs/DESCRIPTION.md` | Description fonctionnelle |
| `SECURITY.md` | Politique de signalement vulnerabilites |
| `CHANGELOG.md` | Historique des versions (a creer) |

### Fichiers deplaces dans `docs/internal/`

- `docs/ARCHITECTURE.md`
- `docs/AUDIT_2026-08-12.md`
- `docs/DEVELOPMENT_PLAN.md`
- `docs/DEVELOPMENT_PLAN_AGENT.md`
- `docs/DEVELOPMENT_PLAN_PHASE2.md`
- `docs/PLAN_ACTION.md`
- `docs/PROGRESS.md`
- `docs/ROADMAP_REMAINING.md`
- `docs/UI_PROGRESS.md`
- `docs/dataflow_redesign_task.md`
- `docs/CONDUCT.md`
- `CONTRIBUTING.md`

Ces fichiers restent dans le repo pour les developpeurs mais sont exclus des artifacts de release.

---

## Partie B — Packaging et versioning

### B1 : Source de verite version

Fichier `VERSION` a la racine : `0.1.0-alpha.1`

### B2 : Embedding version dans les binaires Go

- `agent/cmd/oseye-agent/main.go` : `var version = "dev"` injecte via `-ldflags`
- `agent/cmd/oseye-config/main.go` : idem, commande `version`

### B3 : Synchronisation versions

Script `scripts/sync-versions.sh` : propage VERSION dans `pyproject.toml` et `package.json`

### B4 : Makefile

- `VERSION ?= $(shell cat VERSION)`
- `-trimpath` dans ldflags (reproductibilite)
- Target `checksums:` (SHA256SUMS)
- `package-agent` depend de `oseye-agent` + `oseye-config`

### B5 : Dockerfile agent

- Base images avec digest (pas de tag mutable)
- `ARG VERSION` injecte dans ldflags
- 2 binaires copies (`oseye-agent`, `oseye-config`)
- Labels OCI standards
- `-trimpath` pour builds reproductibles

### B6 : Scripts package (prerm/postrm)

- `prerm` : arret et desactivation du service avant desinstallation
- `postrm` : daemon-reload, backup buffer si non-vide avant purge, cleanup

### B7 : Workflow release GitHub Actions

`.github/workflows/release.yml` declenche par tag `v*` :
1. Validate (lint + tests)
2. Build (cross-compile linux/amd64, linux/arm64)
3. Package (.deb/.rpm via nfpm + signature GPG)
4. Docker (build + push GHCR + signature cosign)
5. Release GitHub (SHA256SUMS + tous les artifacts)

### B8 : CHANGELOG

Premiere entree : `[0.1.0-alpha.1] — 2026-08-12`

### B9 : Tag

```bash
git tag -a v0.1.0-alpha.1 -m "OSEye v0.1.0-alpha.1 — experimental release"
```

### Principes CIA appliques

| Principe | Mesure |
|----------|--------|
| **Confidentialite** | Permissions 0600 sur config, secrets masques dans CLI |
| **Integrite** | SHA256SUMS, signature GPG (.deb/.rpm), cosign (Docker), -trimpath, digests base images |
| **Disponibilite** | Graceful drain avant arret, backup buffer avant purge |

---

## Partie C — Site officiel

### Stack : Astro Starlight

- SSG rapide, MDX, sidebar auto, dark/light mode, search integree
- Standard open-source (utilise par Tailwind, Astro, etc.)

### Structure

```
site/
├── astro.config.mjs
├── package.json
├── public/
│   └── screenshots/
├── src/content/docs/
│   ├── index.mdx                    (landing page)
│   ├── getting-started/
│   │   ├── installation.mdx         (.deb, .rpm, Docker, source)
│   │   ├── configuration.mdx        (oseye-config, env vars)
│   │   └── quickstart.mdx           (premier lancement)
│   ├── deployment/
│   │   ├── single-node.mdx
│   │   ├── distributed.mdx
│   │   ├── docker.mdx
│   │   └── kubernetes.mdx
│   ├── guides/
│   │   ├── agent-enrollment.mdx
│   │   ├── detection-rules.mdx
│   │   ├── dashboard.mdx
│   │   ├── response-actions.mdx
│   │   └── plugins.mdx
│   ├── reference/
│   │   ├── api.mdx
│   │   ├── config-agent.mdx
│   │   ├── config-server.mdx
│   │   └── architecture.mdx
│   └── security/
│       ├── mtls.mdx
│       ├── rbac.mdx
│       └── integrity.mdx
└── tsconfig.json
```

### Pages principales

- **Landing** : hero + features (9 collecteurs, ML, detection, response) + quickstart 3 etapes
- **Installation** : tabs par methode, verification GPG/SHA256
- **Configuration** : guide oseye-config, tableau env vars, profils de surveillance
- **Deployment** : single-node, distribue, Docker compose, Kubernetes
- **Guides** : enrollment, regles detection, dashboard tour, actions reponse, plugins
- **Reference** : API REST, config agent/serveur, architecture

### Deploiement

- GitHub Pages via `.github/workflows/docs.yml`
- Build declenche sur push `main` dans `site/**`

---

## Ordre d'execution

1. Nettoyage docs (`git mv` fichiers internes)
2. Packaging/versioning (B1-B8)
3. Site officiel (Astro Starlight)
4. Tag `v0.1.0-alpha.1`

## Verification

- `make version` → `0.1.0-alpha.1`
- `make package-agent` → .deb + .rpm dans dist/
- `./dist/oseye-agent --version` → `oseye-agent 0.1.0-alpha.1`
- `cd site && npm run build` → site statique OK
- `go test ./...` passe
