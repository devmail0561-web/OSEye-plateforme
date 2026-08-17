# OSEye — Guide de dépannage

Ce document liste les problèmes courants rencontrés lors du déploiement en production et leurs solutions.

---

## Déploiement Production

### 1. Service systemd ne démarre pas

**Symptômes :**
```
oseye-agent.service: Failed to load environment files: No such file or directory
oseye-agent.service: Failed with result 'resources'
```

**Cause :**
Le fichier `/etc/oseye/agent.env` n'existe pas. Le service systemd attend ce fichier (défini dans `EnvironmentFile=`).

**Solution :**
Lancer l'enrollment avant de démarrer le service. ⚠️ **Utilisez `oseye-config`, pas `oseye-agent`** :
```bash
sudo oseye-config enroll \
  --server <SERVER_HOST>:<PORT> \
  --token <ENROLLMENT_TOKEN> \
  --grpc-port 50051
```

L'enrollment crée automatiquement le fichier `/etc/oseye/agent.env` et active le service.

**Note :** Le package `oseye-agent` contient deux binaires :
- `oseye-agent` — daemon de collecte (géré par systemd)
- `oseye-config` — CLI d'administration pour enrollment et configuration

---

### 2. Enrollment échoue : HTTPS vs HTTP

**Symptômes :**
```
fetch CA cert: http: server gave HTTP response to HTTPS client
```

**Cause :**
`oseye-config enroll` force HTTPS (ligne 68 dans `agent/cmd/oseye-config/enroll.go`) mais le serveur tourne en mode `OSEYE_INSECURE=true` (HTTP uniquement).

**Solution :**
En production, **toujours activer TLS sur le serveur** :
```bash
# Variables d'environnement requises
OSEYE_TLS_CERT=/etc/oseye/certs/server.crt
OSEYE_TLS_KEY=/etc/oseye/certs/server.key
OSEYE_GRPC_TLS_CERT=/etc/oseye/certs/server.crt
OSEYE_GRPC_TLS_KEY=/etc/oseye/certs/server.key
OSEYE_GRPC_INSECURE_DEV=false
```

**Alternative (développement uniquement) :**
Ajouter un reverse proxy nginx avec TLS devant un serveur HTTP :
```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;
    
    location / {
        proxy_pass http://oseye-server:8000;
    }
}
```

---

### 3. Serveur Docker : erreur réseau

**Symptômes :**
```
docker: network oseye-test not found
```

**Cause :**
Le container est lancé avec `--network oseye-test` mais le réseau n'existe pas ou a un nom différent (ex: `oseye-test_oseye-test` créé par docker-compose).

**Solution :**
Lister les réseaux existants :
```bash
docker network ls | grep oseye
```

Utiliser le nom exact :
```bash
docker run --network oseye-test_oseye-test ...
# ou
docker run --network oseye-net ...
```

---

### 4. Serveur : échec connexion PostgreSQL

**Symptômes :**
```
asyncpg.exceptions.InvalidPasswordError: password authentication failed for user "oseye"
```

**Cause :**
Mot de passe incorrect dans `OSEYE_DB_URL`.

**Solution :**
Vérifier le mot de passe défini lors de la création du container PostgreSQL :
```bash
docker inspect oseye-postgres | grep POSTGRES_PASSWORD
```

Corriger `OSEYE_DB_URL` :
```bash
OSEYE_DB_URL=postgresql+asyncpg://oseye:CORRECT_PASSWORD@postgres:5432/oseye
```

---

### 5. Serveur : HMAC key invalide

**Symptômes :**
```
RuntimeError: OSEYE_CHECKPOINT_HMAC_KEY must be a hex string (e.g. openssl rand -hex 32)
```

**Cause :**
La clé `OSEYE_CHECKPOINT_HMAC_KEY` n'est pas au format hexadécimal ou est trop courte.

**Solution :**
Générer une clé hexadécimale valide (64 caractères hex = 32 octets) :
```bash
openssl rand -hex 32
# Exemple: 9539d1a0b9dba5f3f27120ca88da0d35fc40e22a7bc793029806ed2c60d74971
```

Définir la variable :
```bash
OSEYE_CHECKPOINT_HMAC_KEY=9539d1a0b9dba5f3f27120ca88da0d35fc40e22a7bc793029806ed2c60d74971
```

---

### 6. Serveur : HTTPS ne fonctionne pas sur port 8000

**Symptômes :**
```
curl: (35) OpenSSL: error:0A00010B:SSL routines::wrong version number
```

**Cause :**
Uvicorn (serveur FastAPI) écoute en HTTP pur par défaut, pas HTTPS. Les variables `OSEYE_TLS_CERT` et `OSEYE_TLS_KEY` ne sont **pas** utilisées par Uvicorn pour activer HTTPS sur l'API REST.

**Solution 1 (recommandée) :**
Utiliser un reverse proxy (nginx, traefik, caddy) avec TLS :
```bash
docker run -d \
  --name oseye-nginx \
  -p 443:443 \
  -v /path/to/certs:/etc/nginx/certs:ro \
  -v /path/to/nginx.conf:/etc/nginx/conf.d/default.conf:ro \
  nginx:alpine
```

**Solution 2 (développement) :**
Accepter HTTP en développement et utiliser `--server localhost:8000` sans HTTPS.

**Note importante :**
Les certificats TLS sont utilisés pour :
- ✅ gRPC (agent → serveur) via `OSEYE_GRPC_TLS_CERT/KEY`
- ✅ Enrollment (CA signing) via `OSEYE_ENROLLMENT_CA_CERT/KEY`
- ❌ API REST Uvicorn (nécessite reverse proxy)

---

### 7. Enrollment : HTTP 500 — SECRET_KEY trop courte

**Symptômes :**
```
RuntimeError: OSEYE_SECRET_KEY is too short (29 chars). Minimum 32 characters required.
fetch CA cert: HTTP 500 — Internal Server Error
```

**Cause :**
La clé `OSEYE_SECRET_KEY` fait moins de 32 caractères. Elle est utilisée pour :
- Vérifier les tokens d'enrollment (HMAC)
- Signer les sessions API
- Générer les API keys

**Solution :**
Générer une clé d'au moins 32 caractères :
```bash
# Option 1: hex (32 caractères)
openssl rand -hex 16
# Exemple: b067a56cdd711e290932259814c8086f

# Option 2: base64 (43 caractères)
openssl rand -base64 32
# Exemple: 8vZ9mK3pQ7hR2wN6xL4aB5cT1dF8gH9j

# Option 3: alphanumérique (32+ caractères)
head -c 32 /dev/urandom | base64 | tr -d '+/=' | head -c 32
```

Définir la variable :
```bash
OSEYE_SECRET_KEY=b067a56cdd711e290932259814c8086f
```

**Important :**
- Ne **jamais** utiliser les clés d'exemple (`test-secret-*`, `admin123`, etc.) en production
- Générer des clés uniques pour chaque déploiement
- Stocker les clés de façon sécurisée (secrets manager, vault, variables d'environnement chiffrées)

---

## Variables d'environnement critiques

| Variable | Format | Longueur minimum | Exemple |
|----------|--------|------------------|---------|
| `OSEYE_SECRET_KEY` | hex/base64/alphanum | 32 caractères | `openssl rand -hex 16` |
| `OSEYE_CHECKPOINT_HMAC_KEY` | hexadécimal | 64 caractères hex (32 octets) | `openssl rand -hex 32` |
| `OSEYE_ADMIN_PASSWORD` | texte | 12+ caractères | `openssl rand -base64 16` |
| `OSEYE_ANALYST_PASSWORD` | texte | 12+ caractères | `openssl rand -base64 16` |

---

## Checklist déploiement production

### Serveur

- [ ] PostgreSQL démarré et accessible
- [ ] Redis démarré et accessible
- [ ] Certificats TLS générés (`ca.crt`, `ca.key`, `server.crt`, `server.key`)
- [ ] Clés JWT générées (`jwt_private.pem`, `jwt_public.pem`)
- [ ] Clé Ed25519 enrollment générée (`enrollment_ed25519`, `enrollment_ed25519.pub`)
- [ ] `OSEYE_SECRET_KEY` >= 32 caractères
- [ ] `OSEYE_CHECKPOINT_HMAC_KEY` = 64 hex chars
- [ ] Mots de passe admin/analyst changés (pas de valeurs par défaut)
- [ ] `OSEYE_DB_URL` pointe vers PostgreSQL avec bon mot de passe
- [ ] `OSEYE_REDIS_URL` pointe vers Redis
- [ ] `OSEYE_GRPC_INSECURE_DEV=false`
- [ ] `OSEYE_GRPC_TLS_CERT` et `OSEYE_GRPC_TLS_KEY` définis
- [ ] Reverse proxy TLS devant l'API REST (nginx/traefik/caddy)
- [ ] Token d'enrollment généré : `oseye-server enrollment token create`

### Agent

- [ ] Package installé : `dpkg -i oseye-agent_*.deb` ou `rpm -i oseye-agent_*.rpm`
- [ ] Enrollment lancé : `oseye-config enroll --server <HOST>:<PORT> --token <TOKEN>`
- [ ] Fichier `/etc/oseye/agent.env` créé
- [ ] Certificats créés : `/etc/oseye/certs/{agent.crt,agent.key,ca.crt}`
- [ ] Service activé : `systemctl status oseye-agent`
- [ ] Logs agent sans erreur : `journalctl -u oseye-agent -f`
- [ ] Agent visible dans l'UI : http://<SERVER>/agents

---

## Logs utiles

```bash
# Serveur Docker
docker logs oseye-server -f

# Agent systemd
journalctl -u oseye-agent -f

# PostgreSQL
docker logs oseye-postgres

# Redis
docker logs oseye-redis

# Nginx
docker logs oseye-nginx
```

---

## Contacts

Pour signaler un bug ou demander de l'aide :
- GitHub Issues : https://github.com/devmail0561-web/OSEye-plateforme/issues
- Documentation : docs/
