# OSEye — Guide de déploiement serveur

Ce guide couvre le déploiement du serveur OSEye en deux modes : **développement local** et **production**.

---

## Deux modes de déploiement

| | Développement | Production |
|---|---|---|
| Protocole | HTTP | HTTPS (TLS 1.2/1.3) |
| Configuration | Variables d'env en clair | `server.env` + `secrets.env` |
| Certificats | Auto-signés (dev) | PKI générée par `oseye-server init` |
| SSL UI | Non | nginx en reverse proxy |
| gRPC | Sans mTLS (`INSECURE_DEV=true`) | mTLS obligatoire |
| Réseau Docker | Un seul réseau | Réseaux isolés (backend/frontend) |
| Commandes | 1 (`docker compose up -d`) | 3 (`init` + `setup` + `compose up`) |

---

## Mode développement

### Prérequis

- Docker 24+ installé et démarré
- Images buildées localement : `make package-server`

### Lancement

```bash
docker compose -f infra/docker/docker-compose.dev.yml up -d
```

### Accès

| Service | URL |
|---|---|
| UI | http://localhost:5174 |
| API | http://localhost:5174/api/v1/ (via proxy) |
| gRPC | localhost:50051 (sans TLS) |

### Identifiants par défaut

```
admin    / admin123
analyst  / analyst123
```

### Arrêt

```bash
docker compose -f infra/docker/docker-compose.dev.yml down
# Supprimer les volumes :
docker compose -f infra/docker/docker-compose.dev.yml down -v
```

---

## Mode production

### Étape 1 : Initialiser la PKI

Génère la CA racine, les certificats serveur (avec SANs), les JWT keys et la clé enrollment Ed25519 dans `/etc/oseye/certs/` :

```bash
docker run --rm \
  -v /etc/oseye:/etc/oseye \
  oseye-server:latest \
  oseye-server init
```

> **CA key à protéger** : `/etc/oseye/certs/ca.key` signe tous les certificats agents. Ne jamais l'exposer.

### Étape 2 : Wizard de configuration

Lance le wizard interactif qui génère automatiquement `/etc/oseye/server.env` (mode 640) et `/etc/oseye/secrets.env` (mode 600) :

```bash
docker run --rm -it \
  -v /etc/oseye:/etc/oseye \
  oseye-server:latest \
  oseye-server setup
```

Le wizard demande :
- Hostname et IP du serveur
- Ports API (8000) et gRPC (50051)
- Backend base de données (SQLite ou PostgreSQL)
- URL Redis
- Mots de passe admin et analyst
- APIs de Threat Intelligence (optionnel)
- Niveau de log et OpenTelemetry

À la fin, il affiche un **token d'enrollment** valable 24h.

### Étape 3 : Lancer la stack

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d
```

Le compose lit automatiquement `/etc/oseye/server.env` et `/etc/oseye/secrets.env` via `env_file:`. Aucune variable à passer manuellement.

### Vérification

```bash
# Santé des containers
docker compose -f infra/docker/docker-compose.prod.yml ps

# Santé API
curl https://<HOSTNAME>/api/v1/health
# → {"status": "ok"}
```

### Étape 4 : Enroller un agent

Sur chaque machine à surveiller :

```bash
# Installer le package
sudo dpkg -i oseye-agent_amd64.deb      # Debian/Ubuntu
sudo rpm -i oseye-agent_amd64.rpm       # RHEL/Rocky

# Enroller avec le token affiché par setup
sudo oseye-config enroll \
  --server <HOSTNAME>:50051 \
  --token <TOKEN>

sudo systemctl enable --now oseye-agent
```

Pour créer un nouveau token si l'ancien a expiré :

```bash
docker exec oseye-server oseye-server enrollment token create
```

---

## Mise à jour

```bash
# Télécharger la nouvelle image
docker pull oseye-server:X.Y.Z

# Mettre à jour le tag dans docker-compose.prod.yml, puis :
docker compose -f infra/docker/docker-compose.prod.yml up -d oseye-server
```

Les volumes PostgreSQL et les certificats sont persistants — aucune perte de données.

---

## Logs et monitoring

```bash
# Logs serveur
docker logs oseye-server -f

# Santé des services
docker compose -f infra/docker/docker-compose.prod.yml ps

# Events reçus des agents
docker logs oseye-server | grep batch_ingested
```

Voir [TROUBLESHOOTING.md](TROUBLESHOOTING.md) pour les erreurs courantes.
