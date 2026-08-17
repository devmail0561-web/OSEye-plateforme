# OSEye — Guide de déploiement production

Ce guide décrit le déploiement complet d'OSEye en environnement de production.

---

## Architecture de déploiement

```
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer (optional)                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Reverse Proxy (nginx/traefik)             │
│                    Port 443 (HTTPS)                          │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│    OSEye Server           │   │    OSEye UI               │
│    Port 8000 (HTTP)       │   │    Port 5173 (HTTP)       │
│    Port 50051 (gRPC/TLS)  │   │                           │
└───────────────────────────┘   └───────────────────────────┘
              │
              ├─────────────┬─────────────┐
              ▼             ▼             ▼
┌─────────────────┐ ┌─────────────┐ ┌─────────────┐
│   PostgreSQL    │ │    Redis    │ │  Agents     │
│   Port 5432     │ │  Port 6379  │ │  (mTLS)     │
└─────────────────┘ └─────────────┘ └─────────────┘
```

---

## Prérequis

### Matériel

**Serveur (minimum) :**
- CPU : 4 cores
- RAM : 8 GB
- Disque : 100 GB SSD (logs, événements, ML models)
- Réseau : 1 Gbps

**Agent (par machine surveillée) :**
- CPU : < 4% (configurable via `OSEYE_MAX_CPU_PCT`)
- RAM : < 256 MB (configurable via `OSEYE_MAX_MEM_MB`)
- Disque : 1 GB (buffer offline)

### Logiciels

- Docker 24+ et Docker Compose 2.20+
- PostgreSQL 16
- Redis 7
- Linux kernel 5.10+ (pour eBPF)

---

## Étape 1 : Génération des secrets et certificats

### 1.1 Secrets applicatifs

```bash
# Créer un répertoire pour les secrets
mkdir -p ~/oseye-secrets
cd ~/oseye-secrets

# Secret principal (32+ caractères)
openssl rand -hex 16 > secret_key.txt
echo "OSEYE_SECRET_KEY=$(cat secret_key.txt)"

# HMAC checkpoint (64 caractères hex)
openssl rand -hex 32 > checkpoint_hmac.txt
echo "OSEYE_CHECKPOINT_HMAC_KEY=$(cat checkpoint_hmac.txt)"

# Mots de passe admin
openssl rand -base64 24 > admin_password.txt
echo "OSEYE_ADMIN_PASSWORD=$(cat admin_password.txt)"

openssl rand -base64 24 > analyst_password.txt
echo "OSEYE_ANALYST_PASSWORD=$(cat analyst_password.txt)"
```

### 1.2 Certificats TLS (CA interne)

```bash
mkdir -p ~/oseye-certs
cd ~/oseye-certs

# 1. CA root
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout ca.key -out ca.crt -days 3650 \
  -subj "/C=FR/O=OSEye/CN=OSEye Root CA"

# 2. Certificat serveur
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/C=FR/O=OSEye/CN=oseye-server"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(echo "subjectAltName=DNS:oseye-server,DNS:localhost,IP:127.0.0.1")

# 3. Clés JWT (RSA 2048)
openssl genrsa -out jwt_private.pem 2048
openssl rsa -in jwt_private.pem -pubout -out jwt_public.pem

# 4. Clé Ed25519 pour enrollment
openssl genpkey -algorithm ed25519 -out enrollment_ed25519
openssl pkey -in enrollment_ed25519 -pubout -out enrollment_ed25519.pub

# Permissions
chmod 600 ca.key server.key jwt_private.pem enrollment_ed25519
chmod 644 ca.crt server.crt jwt_public.pem enrollment_ed25519.pub
```

---

## Étape 2 : Déploiement du serveur

### 2.1 Docker Compose (recommandé)

Créer `docker-compose.prod.yml` :

```yaml
name: oseye-production

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: oseye
      POSTGRES_USER: oseye
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    secrets:
      - db_password
    networks:
      - oseye-backend
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --save 60 1 --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    networks:
      - oseye-backend
    restart: unless-stopped

  oseye-server:
    image: oseye-server:0.2.0-alpha.1
    environment:
      OSEYE_DB_BACKEND: postgresql
      OSEYE_DB_URL: postgresql+asyncpg://oseye:${DB_PASSWORD}@postgres:5432/oseye
      OSEYE_BUS_BACKEND: redis
      OSEYE_REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      OSEYE_API_HOST: 0.0.0.0
      OSEYE_API_PORT: 8000
      OSEYE_API_CORS_ORIGINS: '["https://oseye.example.com"]'
      OSEYE_GRPC_PORT: 50051
      OSEYE_GRPC_INSECURE_DEV: "false"
      OSEYE_GRPC_TLS_CERT: /etc/oseye/certs/server.crt
      OSEYE_GRPC_TLS_KEY: /etc/oseye/certs/server.key
      OSEYE_SECRET_KEY_FILE: /run/secrets/secret_key
      OSEYE_CHECKPOINT_HMAC_KEY_FILE: /run/secrets/checkpoint_hmac
      OSEYE_ADMIN_PASSWORD_FILE: /run/secrets/admin_password
      OSEYE_ANALYST_PASSWORD_FILE: /run/secrets/analyst_password
      OSEYE_JWT_PRIVATE_KEY_PATH: /etc/oseye/certs/jwt_private.pem
      OSEYE_JWT_PUBLIC_KEY_PATH: /etc/oseye/certs/jwt_public.pem
      OSEYE_JWT_ACCESS_TOKEN_EXPIRE_MINUTES: 60
      OSEYE_ED25519_PUBLIC_KEY: /etc/oseye/certs/enrollment_ed25519.pub
      OSEYE_ENROLLMENT_CA_CERT_FILE: /etc/oseye/certs/ca.crt
      OSEYE_ENROLLMENT_CA_KEY_FILE: /etc/oseye/certs/ca.key
      OSEYE_LOG_LEVEL: info
      OSEYE_PLUGINS_DIR: /var/lib/oseye/plugins
      OSEYE_DATA_DIR: /var/lib/oseye/data
    volumes:
      - ~/oseye-certs:/etc/oseye/certs:ro
      - oseye-data:/var/lib/oseye
    secrets:
      - secret_key
      - checkpoint_hmac
      - admin_password
      - analyst_password
    depends_on:
      - postgres
      - redis
    networks:
      - oseye-backend
      - oseye-frontend
    restart: unless-stopped

  oseye-ui:
    image: oseye-ui:0.2.0-alpha.1
    environment:
      VITE_API_URL: https://oseye.example.com
      VITE_WS_URL: wss://oseye.example.com
    networks:
      - oseye-frontend
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ~/oseye-certs:/etc/nginx/certs:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      - oseye-server
      - oseye-ui
    networks:
      - oseye-frontend
    restart: unless-stopped

networks:
  oseye-backend:
    driver: bridge
  oseye-frontend:
    driver: bridge

volumes:
  postgres-data:
  redis-data:
  oseye-data:

secrets:
  db_password:
    file: ~/oseye-secrets/db_password.txt
  secret_key:
    file: ~/oseye-secrets/secret_key.txt
  checkpoint_hmac:
    file: ~/oseye-secrets/checkpoint_hmac.txt
  admin_password:
    file: ~/oseye-secrets/admin_password.txt
  analyst_password:
    file: ~/oseye-secrets/analyst_password.txt
```

### 2.2 Configuration nginx

Créer `nginx.conf` :

```nginx
# HTTP → HTTPS redirect
server {
    listen 80;
    server_name oseye.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    server_name oseye.example.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    client_max_body_size 100M;

    # API
    location /api {
        proxy_pass http://oseye-server:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }

    # WebSocket
    location /ws {
        proxy_pass http://oseye-server:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }

    # UI
    location / {
        proxy_pass http://oseye-ui:5173;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 2.3 Lancement

```bash
# Définir variables d'environnement
export DB_PASSWORD=$(cat ~/oseye-secrets/db_password.txt)
export REDIS_PASSWORD=$(openssl rand -hex 16)

# Démarrer la stack
docker-compose -f docker-compose.prod.yml up -d

# Vérifier les logs
docker-compose -f docker-compose.prod.yml logs -f oseye-server

# Tester l'API
curl -k https://localhost/api/v1/health
```

---

## Étape 3 : Génération du token d'enrollment

```bash
# Se connecter au container serveur
docker exec -it oseye-server bash

# Créer un token d'enrollment (valide 24h)
oseye-server enrollment token create

# Exemple de sortie :
# Token créé : 4d223dfc3b2347cfd3b833b69f83f7fa9ab9478678842707187d5fdfe05fa6dd
# Valide jusqu'à : 2026-08-18T13:00:00Z
```

**Important :** Copier ce token, il sera utilisé pour enrollement des agents.

---

## Étape 4 : Déploiement des agents

### 4.1 Installation du package

Le package **`oseye-agent`** contient deux binaires :
- `/usr/bin/oseye-agent` — daemon de collecte (service systemd)
- `/usr/bin/oseye-config` — CLI d'administration (enrollment, configuration)

Sur chaque machine à surveiller :

```bash
# Debian/Ubuntu
wget https://releases.oseye.io/oseye-agent_0.2.0~alpha.1_amd64.deb
sudo dpkg -i oseye-agent_0.2.0~alpha.1_amd64.deb

# RedHat/CentOS
wget https://releases.oseye.io/oseye-agent-0.2.0~alpha.1.x86_64.rpm
sudo rpm -i oseye-agent-0.2.0~alpha.1.x86_64.rpm
```

**Vérification :**
```bash
which oseye-agent oseye-config
# /usr/bin/oseye-agent
# /usr/bin/oseye-config

oseye-config --version
# oseye-config 0.2.0-alpha.1
```

### 4.2 Enrollment

⚠️ **Important** : L'enrollment se fait avec `oseye-config`, **pas** `oseye-agent`.

```bash
sudo oseye-config enroll \
  --server oseye.example.com:443 \
  --token 4d223dfc3b2347cfd3b833b69f83f7fa9ab9478678842707185d5fdfe05fa6dd \
  --grpc-port 50051
```

**Ce que fait l'enrollment :**
1. Télécharge le certificat CA via HTTPS (TOFU)
2. Génère une paire de clés RSA-2048
3. Crée une CSR et la soumet au serveur pour signature
4. Reçoit le certificat agent signé par la CA
5. Écrit `/etc/oseye/agent.env` avec la configuration
6. Active et démarre `oseye-agent.service`

### 4.3 Vérification

```bash
# Status service (le daemon oseye-agent)
sudo systemctl status oseye-agent

# Logs temps réel
sudo journalctl -u oseye-agent -f

# Afficher la configuration avec oseye-config
sudo oseye-config show

# Valider la configuration
sudo oseye-config validate

# Vérifier que les certificats existent
sudo oseye-config check-files
# Ou manuellement :
ls -lh /etc/oseye/certs/
# ca.crt, agent.crt, agent.key doivent exister
```

### 4.4 Gestion de la configuration

Après l'enrollment, vous pouvez ajuster la configuration avec `oseye-config` :

```bash
# Modifier la limite CPU (défaut: 4%)
sudo oseye-config set OSEYE_MAX_CPU_PCT=2.0

# Modifier la limite mémoire (défaut: 256 MB)
sudo oseye-config set OSEYE_MAX_MEM_MB=128

# Ajouter des chemins surveillés par fanotify
sudo oseye-config set OSEYE_FANOTIFY_PATHS=/etc/passwd,/etc/shadow,/root/.ssh,/home/admin/.ssh

# Lire une valeur
sudo oseye-config get OSEYE_GRPC_ADDR

# Redémarrer l'agent pour appliquer les changements
sudo systemctl restart oseye-agent
```

---

## Étape 5 : Accès à l'interface web

1. Ouvrir https://oseye.example.com
2. Se connecter avec les identifiants admin
3. Vérifier que les agents apparaissent dans **Agents** → liste

---

## Pièges courants à éviter

### ❌ Secrets trop courts

**Problème :** `OSEYE_SECRET_KEY` ou `OSEYE_CHECKPOINT_HMAC_KEY` trop courts.

```bash
# ❌ Trop court (29 chars)
OSEYE_SECRET_KEY=test-secret-min32b-local-only

# ✅ Minimum 32 caractères
OSEYE_SECRET_KEY=$(openssl rand -hex 16)  # 32 chars hex
OSEYE_CHECKPOINT_HMAC_KEY=$(openssl rand -hex 32)  # 64 chars hex
```

**Erreur typique :**
```
RuntimeError: OSEYE_SECRET_KEY is too short (29 chars). Minimum 32 characters required.
RuntimeError: OSEYE_CHECKPOINT_HMAC_KEY must be a hex string
```

### ❌ Certificat sans SANs

**Problème :** Le certificat serveur n'a pas de Subject Alternative Names.

```bash
# ❌ Sans SANs
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt

# ✅ Avec SANs (obligatoire pour Go 1.15+)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -out server.crt \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:oseye-server,IP:127.0.0.1")
```

**Erreur typique :**
```
x509: certificate relies on legacy Common Name field, use SANs instead
```

### ❌ Permissions certificats agent

**Problème :** L'agent ne peut pas lire ses certificats après enrollment.

✅ **Depuis v0.2.0-alpha.1** : Ce problème est **résolu automatiquement**. 

`oseye-config enroll` change maintenant automatiquement l'ownership des certificats vers `oseye:oseye` après leur création.

**Si vous utilisez une version antérieure** :
```bash
# Corriger manuellement après enrollment
sudo chown -R oseye:oseye /etc/oseye/certs/
sudo chmod 640 /etc/oseye/certs/agent.key
sudo chmod 644 /etc/oseye/certs/{agent.crt,ca.crt}
```

**Erreur typique (versions < 0.2.0-alpha.1) :**
```
"grpc client init failed — running in buffer-only mode"
"err":"open /etc/oseye/certs/agent.key: permission denied"
```

### ❌ Token d'enrollment expiré

**Problème :** Tokens créés par `oseye-server init` expirent après 24h.

```bash
# ❌ Token > 24h
oseye-config enroll --token <OLD_TOKEN>
# → "Invalid or expired enrollment token"

# ✅ Créer un nouveau token
docker exec oseye-server python -c "
from oseye.enrollment_store import EnrollmentStore
import asyncio
# Créer nouveau token (TODO: ajouter CLI oseye-server enrollment token create)
"
```

**Solution temporaire :** Relancer `oseye-server init` génère un nouveau token.

### ❌ gRPC context.is_active()

**Problème :** Code serveur utilise `context.is_active()` qui n'existe pas dans grpcio.

```python
# ❌ Incorrect (AttributeError)
while context.is_active() is not False:
    ...

# ✅ Correct
while not context.cancelled():
    ...
```

**Ce bug est corrigé dans la version actuelle.**

### ❌ UI : "Identifiants invalides" alors que les credentials sont corrects

**Problème :** L'UI tourne sur un port différent de l'API (ex: UI sur `5174`, API sur `443`). Le navigateur bloque la requête CORS car l'origine `http://localhost:5174` n'est pas dans la liste `OSEYE_API_CORS_ORIGINS` du serveur.

**Symptôme dans la console navigateur (F12) :**
```
Blocage d'une requête multiorigine (Cross-Origin Request) :
la politique « Same Origin » ne permet pas de consulter la ressource distante
sur https://localhost/api/v1/auth/token. Raison : échec de la requête CORS.
```

**Solution :** Démarrer le serveur avec l'origine de l'UI dans `OSEYE_API_CORS_ORIGINS` :
```bash
-e 'OSEYE_API_CORS_ORIGINS=["http://localhost:5174","https://oseye.example.com"]'
```

### ❌ Events non reçus — "send batch failed" sans erreur visible

**Problème :** Le serveur tourne sans le répertoire `/etc/oseye/agent_keys`. Avec `require_agent_keys=True` (ancien défaut), toutes les requêtes `IngestEvents` sont rejetées silencieusement avec `UNAUTHENTICATED`. L'agent voit des timeouts.

**Symptôme serveur :**
```
agent_key_not_registered cn=<agent>
```
Aucun log `batch_ingested`.

**Solution (v0.2.0-alpha.1+) :** Ce comportement est corrigé — `require_agent_keys` est activé uniquement quand des fichiers `.pub` sont présents dans `agent_keys_dir`. Pour les versions antérieures, supprimer le répertoire `agent_keys` vide ou y placer les clés publiques des agents.

### ❌ UI : `VITE_API_URL` non pris en compte

**Problème :** L'image Docker UI est buildée sans passer la variable `VITE_API_URL` comme `ARG` au build. Vite intègre les variables d'environnement au moment du build (pas au runtime), donc `VITE_API_URL` passé en `-e` sur `docker run` est ignoré.

**Solution :** Passer `--build-arg` au moment du build :
```bash
docker build -t oseye-ui:0.2.0-alpha.1 \
  --build-arg VITE_API_URL=https://localhost:443 \
  -f ui/Dockerfile ui/
```

Le `Dockerfile` de l'UI expose bien ce paramètre depuis `v0.2.0-alpha.1` :
```dockerfile
ARG VITE_API_URL=https://localhost:443
ENV VITE_API_URL=$VITE_API_URL
```

---

## Monitoring et maintenance

### Logs serveur

```bash
# Logs API/gRPC
docker logs oseye-server -f

# Logs PostgreSQL
docker logs oseye-postgres -f

# Logs Redis
docker logs oseye-redis -f
```

### Logs agent

```bash
# Logs systemd
sudo journalctl -u oseye-agent -f

# Logs debug (ajouter OSEYE_LOG_LEVEL=debug dans /etc/oseye/agent.env)
sudo systemctl restart oseye-agent
```

### Métriques

L'API expose des métriques Prometheus sur `/metrics` :

```bash
curl https://oseye.example.com/metrics
```

### Sauvegarde

**PostgreSQL :**
```bash
docker exec oseye-postgres pg_dump -U oseye oseye > oseye_backup_$(date +%Y%m%d).sql
```

**Redis :**
```bash
docker exec oseye-redis redis-cli SAVE
docker cp oseye-redis:/data/dump.rdb oseye_redis_$(date +%Y%m%d).rdb
```

**Certificats et secrets :**
```bash
tar czf oseye_secrets_$(date +%Y%m%d).tar.gz ~/oseye-certs ~/oseye-secrets
```

---

## Sécurité

### Checklist sécurité

- [ ] Tous les secrets générés aléatoirement (pas de valeurs par défaut)
- [ ] Certificats TLS avec dates d'expiration < 1 an
- [ ] Rotation des tokens d'enrollment (24-48h max)
- [ ] Firewall : seuls les ports 443 (HTTPS) et 50051 (gRPC) exposés
- [ ] PostgreSQL/Redis non exposés publiquement
- [ ] Logs centralisés (syslog, ELK, Loki)
- [ ] Monitoring actif (Prometheus, Grafana)
- [ ] Sauvegardes automatiques quotidiennes
- [ ] Plan de reprise d'activité (DRP) testé

### Rotation des secrets

**Token enrollment (toutes les 24h) :**
```bash
docker exec oseye-server oseye-server enrollment token revoke <OLD_TOKEN>
docker exec oseye-server oseye-server enrollment token create
```

**Certificats (tous les 90 jours) :**
```bash
cd ~/oseye-certs
# Regénérer server.crt (voir Étape 1.2)
docker-compose restart oseye-server nginx
```

---

## Mise à l'échelle

### Serveur horizontal (multi-instances)

OSEye supporte le scale-out via Redis :

```yaml
services:
  oseye-server:
    image: oseye-server:0.2.0-alpha.1
    deploy:
      replicas: 3  # 3 instances
    # ... même config
```

Load balancer (nginx upstream) :

```nginx
upstream oseye_backend {
    least_conn;
    server oseye-server-1:8000;
    server oseye-server-2:8000;
    server oseye-server-3:8000;
}

server {
    location /api {
        proxy_pass http://oseye_backend;
    }
}
```

### PostgreSQL clustering

Utiliser **PostgreSQL HA** (Patroni, Stolon, ou pgpool-II) pour haute disponibilité.

### Redis clustering

Utiliser **Redis Sentinel** ou **Redis Cluster** pour réplication.

---

## Dépannage

Voir [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) pour les problèmes courants.

---

## Support

- Documentation : https://github.com/devmail0561-web/OSEye-plateforme/tree/main/docs
- Issues : https://github.com/devmail0561-web/OSEye-plateforme/issues
- Discussions : https://github.com/devmail0561-web/OSEye-plateforme/discussions
