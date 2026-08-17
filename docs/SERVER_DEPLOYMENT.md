# OSEye — Guide de déploiement serveur

Ce guide couvre le déploiement du serveur OSEye en deux modes : **développement local** et **production**.

---

## Deux modes de déploiement

| | Développement | Production |
|---|---|---|
| Protocole | HTTP | HTTPS (TLS 1.2/1.3) |
| Secrets | En clair dans le compose | Docker secrets (fichiers) |
| Certificats | Auto-signés (dev) | PKI interne ou Let's Encrypt |
| SSL UI | Non | nginx en reverse proxy |
| gRPC | Sans mTLS (`INSECURE_DEV=true`) | mTLS obligatoire |
| Réseau Docker | Un seul réseau | Réseaux isolés (backend/frontend) |
| Commande | `docker compose -f infra/docker/docker-compose.dev.yml up -d` | Voir Étape 4 ci-dessous |

---

## Mode développement

### Prérequis

- Docker 24+ installé et démarré
- Images buildées localement : `make docker-build`

### Lancement

```bash
docker compose -f infra/docker/docker-compose.dev.yml up -d
```

### Accès

| Service | URL |
|---|---|
| UI | http://localhost:5174 |
| API | http://localhost:5174/api/v1/ (via proxy) |
| API directe | http://localhost:8000/api/v1/ |
| gRPC | localhost:50051 (sans TLS) |

### Identifiants par défaut

```
admin    / admin123
analyst  / analyst123
```

### Arrêt

```bash
docker compose -f infra/docker/docker-compose.dev.yml down
# Supprimer aussi les volumes (base de données) :
docker compose -f infra/docker/docker-compose.dev.yml down -v
```

---

## Mode production

### Architecture

```
Internet
    │
    ▼
nginx (port 80 → 301, port 443 SSL)
    ├── /api/*  → oseye-server:8000
    ├── /ws/*   → oseye-server:8000 (WebSocket)
    └── /*      → oseye-ui:5173
                      └── /api/* → oseye-server:8000 (proxy interne)

oseye-server:8000  ──→  postgres:5432  (réseau oseye-backend)
                   ──→  redis:6379     (réseau oseye-backend)
oseye-server:50051 ──→  Agents (gRPC mTLS, exposé sur l'hôte)
```

### Étape 1 : Préparer les secrets

Créer les fichiers de secrets sur l'hôte (ne jamais committer ces fichiers) :

```bash
mkdir -p /etc/oseye/secrets
chmod 700 /etc/oseye/secrets

# Clé principale (32+ caractères)
openssl rand -hex 16 > /etc/oseye/secrets/secret_key.txt

# Clé HMAC checkpoint (64 hex chars = 32 bytes)
openssl rand -hex 32 > /etc/oseye/secrets/hmac_key.txt

# Mots de passe
openssl rand -base64 24 > /etc/oseye/secrets/admin_password.txt
openssl rand -base64 24 > /etc/oseye/secrets/analyst_password.txt
openssl rand -base64 24 > /etc/oseye/secrets/db_password.txt
openssl rand -base64 24 > /etc/oseye/secrets/redis_password.txt

# Permissions restrictives
chmod 600 /etc/oseye/secrets/*.txt
```

### Étape 2 : Initialiser les certificats et tokens

```bash
# Crée /etc/oseye/certs/ avec CA, certificats serveur, JWT keys, clé enrollment
docker run --rm \
  -v /etc/oseye:/etc/oseye \
  oseye-server:0.2.0-alpha.1 \
  oseye-server init
```

Fichiers générés :
```
/etc/oseye/certs/
├── ca.crt                  # CA racine (distribuer aux agents)
├── ca.key                  # Clé CA (protéger, ne jamais exposer)
├── server.crt              # Certificat serveur (avec SANs)
├── server.key
├── jwt_private.pem         # Signature JWT (RS256)
├── jwt_public.pem
├── enrollment_ed25519.pub  # Vérification tokens enrollment
└── enrollment_ed25519.key
```

> **Si vous avez votre propre PKI**, copiez manuellement vos certificats dans `/etc/oseye/certs/` en respectant ces noms.

### Étape 3 : Configurer votre domaine

Adapter `infra/docker/docker-compose.prod.yml` :

```yaml
OSEYE_API_CORS_ORIGINS: '["https://oseye.votre-domaine.com"]'
```

Et `infra/docker/nginx.prod.conf` :

```nginx
server_name oseye.votre-domaine.com;
```

Si vous utilisez Let's Encrypt :

```bash
certbot certonly --standalone -d oseye.votre-domaine.com
cp /etc/letsencrypt/live/oseye.votre-domaine.com/fullchain.pem /etc/oseye/certs/server.crt
cp /etc/letsencrypt/live/oseye.votre-domaine.com/privkey.pem   /etc/oseye/certs/server.key
```

### Étape 4 : Lancer la stack

```bash
docker compose -f infra/docker/docker-compose.prod.yml up -d
```

Vérifier que tout est sain :

```bash
docker compose -f infra/docker/docker-compose.prod.yml ps
```

Tous les services doivent être `healthy` ou `running`.

### Étape 5 : Vérifier l'API

```bash
curl https://oseye.votre-domaine.com/api/v1/health
# → {"status": "ok"}
```

### Étape 6 : Créer un token d'enrollment pour les agents

```bash
# Lister les tokens existants
docker exec oseye-server oseye-server enrollment token list

# Créer un nouveau token (expire dans 24h)
docker exec oseye-server oseye-server enrollment token create
```

Distribuer ce token aux agents via `oseye-config enroll`.

### Étape 7 : Enroller un agent

Sur la machine à surveiller (après installation du package `.deb` ou `.rpm`) :

```bash
sudo oseye-config enroll \
  --server oseye.votre-domaine.com:50051 \
  --token <TOKEN>

sudo systemctl start oseye-agent
sudo systemctl enable oseye-agent
```

---

## Variables d'environnement clés

Voir [SERVER_CLI.md](SERVER_CLI.md) pour la liste complète. Les plus importantes :

| Variable | Requis | Description |
|---|---|---|
| `OSEYE_DB_URL` | Oui | URL PostgreSQL (asyncpg) |
| `OSEYE_REDIS_URL` | Oui | URL Redis |
| `OSEYE_SECRET_KEY` | Oui | Clé HMAC sessions (32+ chars) |
| `OSEYE_CHECKPOINT_HMAC_KEY` | Oui | Clé HMAC ML (64 hex chars) |
| `OSEYE_ADMIN_PASSWORD` | Oui | Mot de passe admin UI |
| `OSEYE_API_CORS_ORIGINS` | Oui | Origines autorisées (JSON array) |
| `OSEYE_GRPC_TLS_CERT` | En prod | Certificat serveur gRPC |
| `OSEYE_GRPC_TLS_KEY` | En prod | Clé privée serveur gRPC |
| `OSEYE_JWT_PRIVATE_KEY_PATH` | Oui | Clé privée RS256 pour JWT |
| `OSEYE_JWT_PUBLIC_KEY_PATH` | Oui | Clé publique RS256 pour JWT |
| `OSEYE_ENROLLMENT_CA_CERT_FILE` | Oui | CA pour signer les certs agents |
| `OSEYE_ENROLLMENT_CA_KEY_FILE` | Oui | Clé CA (écriture protégée) |

---

## Mise à jour

```bash
# Télécharger la nouvelle image
docker pull oseye-server:X.Y.Z

# Mettre à jour le tag dans docker-compose.prod.yml, puis :
docker compose -f infra/docker/docker-compose.prod.yml up -d oseye-server
```

La base de données et les certificats sont dans des volumes persistants — aucune perte de données.

---

## Logs et monitoring

```bash
# Logs serveur
docker logs oseye-server -f

# Logs nginx
docker logs oseye-nginx -f

# Santé de tous les services
docker compose -f infra/docker/docker-compose.prod.yml ps
```

Voir [TROUBLESHOOTING.md](TROUBLESHOOTING.md) pour les erreurs courantes.
