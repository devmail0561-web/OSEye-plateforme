# OSEye Server — Guide CLI

Le serveur OSEye dispose d'une CLI pour l'initialisation, la configuration et la gestion.

---

## 📦 Installation

### Docker (recommandé pour production)
```bash
docker pull oseye-server:0.2.0-alpha.1
```

### Installation native
```bash
# Depuis les sources (développement)
cd server
uv pip install -e .

# Via package Python (production)
pip install oseye-server

# Vérifier
oseye-server version
```

---

## 🔧 Commandes disponibles

```
oseye-server init                              Initialiser PKI et répertoires système
oseye-server setup                             Assistant interactif de configuration
oseye-server start                             Démarrer le serveur (API + gRPC + workers)
oseye-server stop      [--timeout N]           Arrêter le serveur (gracieux)
oseye-server restart   [--timeout N]           Redémarrer le serveur
oseye-server status                            État du serveur + health API
oseye-server user create <user> --role <role>  Créer un utilisateur
oseye-server user passwd <user>                Changer le mot de passe
oseye-server user delete <user>                Supprimer un utilisateur
oseye-server user list                         Lister les utilisateurs
oseye-server enrollment token create           Créer un token d'enrollment
oseye-server enrollment token list             Lister les tokens actifs
oseye-server enrollment token revoke <ID>      Révoquer un token
oseye-server validate                          Valider la configuration actuelle
oseye-server update                            Mettre à jour vers la dernière version
oseye-server uninstall                         Désinstaller serveur et/ou agents
oseye-server version                           Afficher la version
```

---

## 🚀 `oseye-server init` — Initialisation

**Rôle :** Crée les répertoires système, génère la PKI (CA, certificats, clés JWT/Ed25519) et un premier token d'enrollment.

**Usage :**
```bash
sudo oseye-server init [OPTIONS]

Options:
  --certs-dir PATH     Répertoire certificats (défaut: /etc/oseye/certs)
  --token-dir PATH     Répertoire tokens (défaut: /etc/oseye/enrollment_tokens)
  --hostname HOST      Hostname du serveur (auto-détecté par défaut)
  --ip IP              IP du serveur (auto-détectée par défaut)
  --force              Régénérer la PKI même si elle existe
```

**Exemple :**
```bash
sudo oseye-server init
# Génère :
# - /etc/oseye/certs/ca.{crt,key}
# - /etc/oseye/certs/server.{crt,key}
# - /etc/oseye/certs/jwt_{private,public}.pem
# - /etc/oseye/certs/enrollment_ed25519{,.pub}
# - Token d'enrollment dans /etc/oseye/enrollment_tokens/
```

**Sortie :**
```
OSEye Server — Initialize

  Hostname : server.example.com
  IP       : 192.168.1.10

✓ Created /etc/oseye/certs
✓ Created /var/lib/oseye
✓ CA generated (4096-bit, 10 years)
✓ Server certificate generated (4096-bit, 825 days)
✓ JWT RS256 key pair generated (4096-bit)
✓ Enrollment token generated

┌──────────────────────────────────────────────────────────────┐
│              Initialization complete                          │
├──────────────────────────────────────────────────────────────┤
│  Certs : /etc/oseye/certs/                                   │
│  Host  : server.example.com                                  │
│                                                               │
│  Enrollment token (valid 24 h):                              │
│  4d223dfc3b2347cfd3b833b69f83f7fa9ab9478678842707185d5...    │
│                                                               │
│  To enroll an agent:                                         │
│    oseye-config enroll --server <host>:443 --token <TOKEN>  │
│                                                               │
│  Next: oseye-server setup                                    │
└──────────────────────────────────────────────────────────────┘
```

---

## ⚙️ `oseye-server setup` — Assistant de configuration

**Rôle :** Wizard interactif qui génère `/etc/oseye/server.env` et `/etc/oseye/secrets.env`.

**Usage :**
```bash
sudo oseye-server setup
```

**Étapes :**
1. **Réseau** : hostname, ports API/gRPC, CORS
2. **PKI** : génère certificats si absents
3. **Database** : SQLite (dev) ou PostgreSQL (prod)
4. **Redis** : URL event bus
5. **Credentials** : mots de passe admin/analyst + secret keys
6. **Threat Intelligence** : AbuseIPDB, VirusTotal, MISP (optionnel)
7. **Observability** : logs + OpenTelemetry (optionnel)
8. **Surveillance** : profil agent (low/medium/high)
9. **Résumé** : validation finale

**Fichiers générés :**
```bash
/etc/oseye/server.env      # Config publique
/etc/oseye/secrets.env     # Secrets (mots de passe, tokens)
```

**Démarrage après setup :**
```bash
# Charger la config
source /etc/oseye/server.env
source /etc/oseye/secrets.env

# Démarrer
oseye-server start
```

---

## 🏃 `oseye-server start` — Démarrage

**Rôle :** Lance le serveur (API REST + gRPC + workers).

**Usage :**
```bash
oseye-server start [OPTIONS]

Options:
  --validate-only    Valide la config sans démarrer
```

**Exemple (installation native) :**
```bash
# Charger la config
export $(cat /etc/oseye/server.env | xargs)
export $(cat /etc/oseye/secrets.env | xargs)

# Démarrer
oseye-server start
```

**Exemple (Docker) :**
```bash
# Le serveur se lance via uvicorn dans le Dockerfile
# On passe la config via -e ou --env-file
docker run -d \
  -p 8000:8000 \
  -p 50051:50051 \
  --env-file /etc/oseye/server.env \
  --env-file /etc/oseye/secrets.env \
  oseye-server:0.2.0-alpha.1
```

---

## ✅ `oseye-server validate` — Validation

**Rôle :** Vérifie la configuration et les dépendances (DB, Redis, certificats).

**Usage :**
```bash
oseye-server validate
```

**Vérifications :**
- Variables d'environnement requises
- Format des URLs (DB, Redis)
- Longueur des secrets (>= 32 chars)
- Existence des certificats TLS
- Connexion PostgreSQL/Redis

**Sortie :**
```
✓ Database connection OK
✓ Redis connection OK
✓ TLS certificates present
✓ JWT keys valid
⚠ OSEYE_ADMIN_PASSWORD uses weak default
✗ OSEYE_SECRET_KEY too short (29 chars, need 32+)

Configuration invalid — 1 error, 1 warning
```

---

## 🔄 `oseye-server update` — Mise à jour

**Rôle :** Télécharge et installe la dernière version depuis GitHub releases.

**Usage :**
```bash
sudo oseye-server update [OPTIONS]

Options:
  --check-only    Vérifier la version disponible sans installer
  --yes           Installer sans confirmation
  --pre           Inclure les pre-releases (alpha, beta)
```

**Exemple :**
```bash
# Vérifier si mise à jour disponible
sudo oseye-server update --check-only
# Current: 0.2.0-alpha.1
# Latest:  0.3.0
# Update available

# Installer
sudo oseye-server update
```

---

## 🗑️ `oseye-server uninstall` — Désinstallation

**Rôle :** Supprime serveur, agents ou les deux (avec option purge).

**Usage :**
```bash
sudo oseye-server uninstall [OPTIONS]

Options:
  --server      Désinstaller le serveur uniquement
  --agent       Désinstaller les agents uniquement
  --purge       Supprimer aussi les données (/var/lib/oseye, /etc/oseye)
  --yes         Pas de confirmation
  --dry-run     Afficher ce qui serait supprimé
```

**Exemple :**
```bash
# Dry-run pour voir ce qui serait supprimé
sudo oseye-server uninstall --server --purge --dry-run

# Désinstallation réelle
sudo oseye-server uninstall --server --purge --yes
```

---

## 🔑 Variables d'environnement serveur

### Obligatoires

| Variable | Type | Description |
|----------|------|-------------|
| `OSEYE_DB_BACKEND` | `sqlite` ou `postgresql` | Backend de stockage |
| `OSEYE_DB_URL` | URL | Connexion database |
| `OSEYE_BUS_BACKEND` | `redis` | Event bus |
| `OSEYE_REDIS_URL` | URL | Connexion Redis |
| `OSEYE_SECRET_KEY` | string (32+ chars) | Clé pour tokens/sessions |
| `OSEYE_CHECKPOINT_HMAC_KEY` | hex (64 chars) | HMAC pour ML checkpoints |
| `OSEYE_ADMIN_PASSWORD` | string | Mot de passe admin |
| `OSEYE_ANALYST_PASSWORD` | string | Mot de passe analyst |

### API REST

| Variable | Défaut | Description |
|----------|--------|-------------|
| `OSEYE_API_HOST` | `0.0.0.0` | Interface d'écoute |
| `OSEYE_API_PORT` | `8000` | Port API |
| `OSEYE_API_CORS_ORIGINS` | `["*"]` | Origins CORS (JSON array) |

### gRPC (agents)

| Variable | Défaut | Description |
|----------|--------|-------------|
| `OSEYE_GRPC_PORT` | `50051` | Port gRPC |
| `OSEYE_GRPC_INSECURE_DEV` | `false` | Mode HTTP (dev uniquement) |
| `OSEYE_GRPC_TLS_CERT` | `/etc/oseye/certs/server.crt` | Certificat TLS |
| `OSEYE_GRPC_TLS_KEY` | `/etc/oseye/certs/server.key` | Clé privée TLS |

### JWT

| Variable | Défaut | Description |
|----------|--------|-------------|
| `OSEYE_JWT_PRIVATE_KEY_PATH` | `/etc/oseye/certs/jwt_private.pem` | Clé RSA privée |
| `OSEYE_JWT_PUBLIC_KEY_PATH` | `/etc/oseye/certs/jwt_public.pem` | Clé RSA publique |
| `OSEYE_JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Durée validité token |

### Enrollment

| Variable | Défaut | Description |
|----------|--------|-------------|
| `OSEYE_ENROLLMENT_CA_CERT_FILE` | `/etc/oseye/certs/ca.crt` | CA pour signing |
| `OSEYE_ENROLLMENT_CA_KEY_FILE` | `/etc/oseye/certs/ca.key` | Clé CA |
| `OSEYE_ED25519_PUBLIC_KEY` | `/etc/oseye/certs/enrollment_ed25519.pub` | Vérif signatures |

### Threat Intelligence (optionnel)

| Variable | Description |
|----------|-------------|
| `OSEYE_ABUSEIPDB_API_KEY` | Clé AbuseIPDB |
| `OSEYE_VIRUSTOTAL_API_KEY` | Clé VirusTotal |
| `OSEYE_MISP_URL` | URL instance MISP |
| `OSEYE_MISP_API_KEY` | Clé API MISP |

### Observability

| Variable | Défaut | Description |
|----------|--------|-------------|
| `OSEYE_LOG_LEVEL` | `INFO` | DEBUG, INFO, WARNING, ERROR |
| `OSEYE_OTEL_ENDPOINT` | `` | OTLP gRPC endpoint (ex: localhost:4317) |

---

## 📂 Structure des répertoires

```
/etc/oseye/
├── certs/
│   ├── ca.crt                      # CA root (public)
│   ├── ca.key                      # CA root (privée)
│   ├── server.crt                  # Certificat serveur
│   ├── server.key                  # Clé privée serveur
│   ├── jwt_private.pem             # JWT RS256 privée
│   ├── jwt_public.pem              # JWT RS256 publique
│   ├── enrollment_ed25519          # Ed25519 privée (signing)
│   └── enrollment_ed25519.pub      # Ed25519 publique (verify)
├── enrollment_tokens/
│   └── <token_hex>                 # Tokens valides (timestamp)
├── server.env                      # Config publique
└── secrets.env                     # Secrets (chmod 600)

/var/lib/oseye/
├── data/                           # Storage ML models
├── plugins/                        # Plugins Python
└── ml_checkpoint.pkl               # ML engine checkpoint
```

---

## 🎯 Exemples de déploiement

### Déploiement Docker (production)

```bash
# 1. Générer secrets
mkdir -p ~/oseye-secrets
openssl rand -hex 16 > ~/oseye-secrets/secret_key.txt
openssl rand -hex 32 > ~/oseye-secrets/checkpoint_hmac.txt
openssl rand -base64 24 > ~/oseye-secrets/admin_password.txt

# 2. Générer PKI
sudo oseye-server init

# 3. Lancer via Docker Compose
docker-compose -f docker-compose.prod.yml up -d

# 4. Créer token d'enrollment
docker exec oseye-server oseye-server enrollment token create
```

### Installation native (développement)

```bash
# 1. Init
sudo oseye-server init

# 2. Setup interactif
sudo oseye-server setup

# 3. Démarrer
source /etc/oseye/server.env
source /etc/oseye/secrets.env
oseye-server start
```

---

## ❓ FAQ

### Comment gérer les tokens d'enrollment ?

Actuellement, `oseye-server init` génère un token initial. Pour en créer d'autres :

**Via Python (dans container ou environnement) :**
```python
from oseye.enrollment_store import EnrollmentStore
store = EnrollmentStore(repo)
token = await store.create_token(valid_hours=24)
print(token)
```

**Via CLI (à venir) :**
```bash
# Roadmap
oseye-server enrollment token create [--valid-hours 24]
oseye-server enrollment token list
oseye-server enrollment token revoke <TOKEN>
```

### Puis-je utiliser SQLite en production ?

❌ **Non recommandé** — SQLite ne supporte pas :
- Connexions concurrentes multiples
- Scale-out (multi-instances serveur)
- Performance à partir de ~100 agents

Utilisez **PostgreSQL** pour production.

### Comment activer HTTPS sur l'API REST ?

L'API REST (Uvicorn/FastAPI) n'écoute qu'en HTTP. En production :

**Option 1 (recommandée) :** Reverse proxy avec TLS
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/oseye/certs/server.crt;
    ssl_certificate_key /etc/oseye/certs/server.key;
    
    location / {
        proxy_pass http://oseye-server:8000;
    }
}
```

**Option 2 :** Tunneling TLS (stunnel, socat)

Les certificats TLS sont utilisés pour :
- ✅ gRPC (agents → serveur)
- ✅ Enrollment (CA signing)
- ❌ API REST (nécessite reverse proxy)

### Le serveur peut-il tourner sans root ?

✅ **Oui** (recommandé en production) :

```dockerfile
# Dockerfile
RUN useradd -m -u 1000 oseye
USER oseye
CMD ["uvicorn", "oseye.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Permissions nécessaires :**
- Lecture : `/etc/oseye/certs/` (certificats)
- Écriture : `/var/lib/oseye/` (ML checkpoints, plugins)

Les commandes `init` et `setup` nécessitent root (écriture dans `/etc`).

---

## `oseye-server stop` / `restart` / `status`

### stop

Arrêt gracieux du serveur (SIGTERM).

```bash
oseye-server stop [--timeout 30]
```

- Sous **systemd** : délègue à `systemctl stop oseye-server`
- En **container Docker** : envoie SIGTERM à PID 1 (Docker restart policy gère le redémarrage)

### restart

```bash
oseye-server restart [--timeout 30]
```

### status

Affiche l'état systemd + vérifie la santé de l'API locale.

```bash
oseye-server status

# Exemple de sortie :
# ● oseye-server.service - OSEye Server
#    Active: active (running)
# API health : ok  (status=ok)
```

---

## `oseye-server user` — Gestion des utilisateurs

Les utilisateurs sont stockés dans `/etc/oseye/users.json` (bcrypt, mode 640).

**Un redémarrage du serveur est nécessaire après toute modification.**

### Rôles disponibles

| Rôle | Accès |
|---|---|
| `admin` | Lecture + écriture + gestion (admin + analyst) |
| `analyst` | Lecture seule |

### Commandes

```bash
# Créer un utilisateur (mot de passe demandé interactivement)
sudo oseye-server user create alice --role analyst

# Créer avec mot de passe en argument (scripts CI)
sudo oseye-server user create alice --role analyst --password "MonMotDePasse!"

# Modifier le mot de passe
sudo oseye-server user passwd alice

# Lister les utilisateurs
oseye-server user list

# Supprimer
sudo oseye-server user delete alice
```

### Contraintes mot de passe

- **Minimum :** 8 caractères
- **Maximum :** 72 bytes (limite bcrypt)
- La limite est affichée à chaque saisie interactive

### Fallback env vars

Si `/etc/oseye/users.json` n'existe pas, le serveur utilise :
```bash
OSEYE_ADMIN_PASSWORD=...
OSEYE_ANALYST_PASSWORD=...
```

---

## `oseye-server enrollment token` — Tokens d'enrollment

Gère les tokens permettant aux agents de s'enroller auprès du serveur.  
**Le serveur n'a pas besoin de tourner.** La CLI se connecte directement à la DB.

Lit `OSEYE_DB_URL` depuis : variable d'environnement → `/etc/oseye/secrets.env` → `/etc/oseye/server.env`.

### Créer un token

```bash
# Valide 24h (défaut)
sudo oseye-server enrollment token create

# Valide 48h
sudo oseye-server enrollment token create --valid-hours 48

# Sortie :
# Enrollment token created:
#   Token   : 4d223dfc3b2347cf...  ← donner ceci à l'agent
#   ID      : abc-123-...
#   Expires : 2026-08-18 17:00 UTC (24h)
#
# To enroll an agent:
#   oseye-config enroll --server <HOST>:50051 --token 4d223dfc3b2347cf...
```

### Lister les tokens actifs

```bash
oseye-server enrollment token list

# ID                                      Created by    Expires
# ------------------------------------------------------------------------
# abc-123-...                             cli           2026-08-18 17:00 UTC
```

### Révoquer un token

```bash
sudo oseye-server enrollment token revoke abc-123-...
# ✓ Token abc-123-... revoked.
```

---

## 📚 Voir aussi

- [DEPLOYMENT.md](./DEPLOYMENT.md) — Guide de déploiement complet
- [AGENT_CLI.md](./AGENT_CLI.md) — Guide CLI agent
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) — Problèmes courants
