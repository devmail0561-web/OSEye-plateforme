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

### 8. Agent : permission denied sur les certificats

**Symptômes :**
```
"grpc client init failed — running in buffer-only mode"
"err":"open /etc/oseye/certs/agent.key: permission denied"
```

**Cause :**
L'agent tourne sous l'utilisateur `oseye` mais les certificats créés par `oseye-config enroll` (lancé en root) ont des permissions restrictives par défaut.

**Solution :**
✅ **Depuis v0.2.0-alpha.1** : `oseye-config enroll` fixe automatiquement les permissions (chown vers `oseye:oseye`).

Si vous utilisez une version antérieure, corriger manuellement :
```bash
sudo chown -R oseye:oseye /etc/oseye/certs/
sudo chmod 640 /etc/oseye/certs/agent.key
sudo chmod 644 /etc/oseye/certs/agent.crt
sudo chmod 644 /etc/oseye/certs/ca.crt
sudo systemctl restart oseye-agent
```

**Vérification :**
```bash
sudo journalctl -u oseye-agent -f
# Doit afficher "collectors started" sans erreur "permission denied"

ls -la /etc/oseye/certs/
# Doit afficher owner=oseye group=oseye
```

---

### 9. Serveur : gRPC streams échouent avec AttributeError

**Symptômes :**
```
rpc error: code = Unknown desc = Unexpected <class 'AttributeError'>: 
'grpc._cython.cygrpc._SyncServicerContext' object has no attribute 'is_active'
```

Logs agent :
```
"policy stream error, reconnecting"
"commands stream error, reconnecting"
```

**Cause :**
`context.is_active()` n'existe pas dans grpcio. La méthode correcte est `context.cancelled()`.

**Solution :**
Modifier `server/oseye/ingest/grpc_service.py` :
```python
# ❌ Incorrect
while context.is_active() is not False:
if context.is_active() is False:

# ✅ Correct
while not context.cancelled():
if context.cancelled():
```

Rebuild et redéployer :
```bash
docker build -t oseye-server:0.3.0-alpha.2 -f server/Dockerfile .
docker restart oseye-server
```

**Vérification :**
```bash
docker logs oseye-server | grep -E "policy_stream_opened|commands_stream_opened"
# Doit afficher les streams ouverts sans erreurs répétées
```

---

### 10. Enrollment : certificat sans SANs

**Symptômes :**
```
sign CSR: tls: failed to verify certificate: x509: certificate relies on 
legacy Common Name field, use SANs instead
```

**Cause :**
Le certificat serveur n'a pas de Subject Alternative Names (SANs). Go 1.15+ refuse ces certificats.

**Solution :**
Régénérer le certificat serveur avec SANs :
```bash
cd ~/oseye-certs

# 1. Créer nouvelle CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr \
  -subj "/C=FR/O=OSEye/CN=localhost"

# 2. Signer avec SANs
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(echo "subjectAltName=DNS:localhost,DNS:oseye-server,IP:127.0.0.1")

# 3. Vérifier
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"
# Doit afficher : DNS:localhost, DNS:oseye-server, IP Address:127.0.0.1

# 4. Redémarrer
docker restart oseye-server oseye-nginx
```

**Note :**
Pour production, ajouter tous les hostnames/IPs utilisés :
```
subjectAltName=DNS:oseye.example.com,DNS:prod.oseye.local,IP:10.0.0.50
```

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

### 11. Events non reçus par le serveur — "send batch failed"

**Symptômes :**
```
{"msg":"send batch failed — events buffered","err":"max retries exceeded: 15 attempts","count":204}
{"msg":"send batch failed — events buffered","err":"context deadline exceeded","count":10}
```
Côté serveur :
```
agent_key_not_registered cn=<agent>
```
Aucun log `batch_ingested` dans les logs serveur.

**Cause :**
`require_agent_keys=True` était hardcodé dans le servicer gRPC, mais le répertoire `/etc/oseye/agent_keys` n'existe pas. Résultat : `agent_public_key=None` → `context.abort(UNAUTHENTICATED)` sur chaque appel IngestEvents → timeout côté agent.

**Ce bug est corrigé depuis v0.2.0-alpha.1.** Le serveur active désormais `require_agent_keys=True` uniquement si des fichiers `.pub` sont présents dans `agent_keys_dir`.

**Vérification :**
```bash
# Les events doivent apparaître dans les logs serveur
docker logs oseye-server | grep batch_ingested
# → batch_ingested accepted=N cn=<agent> rejected=0

# Si toujours absent, vérifier le statut de require_agent_keys
docker logs oseye-server | grep "agent_key\|enforcement"
```

---

### 12. gRPC streams policy/commands échouent — AttributeError

**Symptômes :**
```
{"msg":"commands stream error, reconnecting","err":"rpc error: code = Unknown desc = Unexpected
<class 'AttributeError'>: 'grpc._cython.cygrpc._SyncServicerContext' object has no attribute 'cancelled'"}
```

**Cause :**
`_SyncServicerContext` de grpcio n'expose ni `is_active()` ni `cancelled()`. La seule API disponible pour détecter la déconnexion client est `add_callback()`.

**Ce bug est corrigé depuis v0.2.0-alpha.1.** Les méthodes `ReceivePolicy` et `StreamCommands` utilisent maintenant `threading.Event` + `context.add_callback(_cancelled.set)`.

---

### 13. Worker serveur ne traite plus les events (crash silencieux)

**Symptômes :** Les alertes ou décisions s'arrêtent de se générer. Le serveur répond aux requêtes API mais plus rien ne se passe côté détection.

**Cause :** Un worker asyncio (rule_worker, ml_worker, etc.) a crashé sur une exception non attrapée.

**Diagnostic :**
```bash
# Rechercher les crashes de workers dans les logs
docker logs oseye-server 2>&1 | grep "worker_task_crashed"
# ou
journalctl -u oseye-server | grep "worker_task_crashed"
```

**Solution :** Redémarrer le serveur (`oseye-server restart`). Investiguer l'exception loggée pour corriger la cause racine.

**Note :** Depuis v0.2.0, chaque crash de worker est loggué avec le nom du worker et la stack trace complète (niveau ERROR).

---

### 14. `oseye-server plugin upload` échoue : "Invalid plugin name" ou "signature required"

**Causes possibles :**

1. **Nom invalide** : le fichier .py a un nom qui n'est pas un identifiant Python valide, est un mot-clé, commence par `_`, ou correspond à un module réservé (os, sys, subprocess…). Renommer le fichier.

2. **Signature manquante** : `OSEYE_PLUGIN_REQUIRE_SIGNATURE=true` (défaut). Fournir un fichier `.sig` :
   ```bash
   oseye-server plugin upload my_plugin.py --sig my_plugin.sig
   ```
   Pour développement uniquement :
   ```bash
   OSEYE_PLUGIN_REQUIRE_SIGNATURE=false oseye-server plugin upload my_plugin.py --no-verify
   ```

3. **Clé non enregistrée** : le fichier `.sig` est présent mais aucune clé publique Ed25519 dans `/etc/oseye/plugin_keys/`. Ajouter la clé `.pem` dans ce répertoire.

---

---

### 15. Tous les endpoints `/rules/db/*` retournent HTTP 503

**Symptômes :**
```
POST /api/v1/rules/db → 503 Service Unavailable
{"detail": "Rule repository not available"}
```

**Cause :**
`app.state.rule_repo` n'était pas assigné dans le lifespan du serveur dans les versions antérieures
à 2026-08-19.

**Solution :**
Mettre à jour le serveur. Le bug est corrigé — `SQLRuleRepository` est maintenant correctement
instancié et assigné à `app.state.rule_repo` au démarrage.

```bash
docker restart oseye-server
```

**Vérification :**
```bash
curl -k -H "Authorization: Bearer <TOKEN>" https://localhost:443/api/v1/rules/db
# Doit retourner 200 avec liste JSON (vide si aucune règle en DB)
```

---

### 16. Agent offline sans raison connue

**Symptômes :**
L'agent passe offline dans l'UI sans message d'erreur. `systemctl status oseye-agent` montre
`inactive (dead)` sans cause explicite.

**Diagnostic :**
```bash
# Voir la raison de déconnexion depuis l'API (depuis v0.3.0)
curl -k -H "Authorization: Bearer <TOKEN>" \
  https://localhost:443/api/v1/agents/<HOSTNAME>
# → champ "disconnect_reason": "CANCELLED" | "UNAVAILABLE" | "EOF" | ...

# Logs agent avec code gRPC status
journalctl -u oseye-agent -f | grep "grpc_code"
```

**Codes gRPC courants :**

| Code | Cause probable |
|---|---|
| `CANCELLED` | Arrêt propre (SIGTERM/SIGINT) |
| `UNAVAILABLE` | Serveur inaccessible ou réseau coupé |
| `DEADLINE_EXCEEDED` | Timeout — réseau instable ou charge serveur |
| `UNAUTHENTICATED` | Certificat expiré ou révoqué |
| `EOF` | Connexion fermée proprement côté serveur |

**Test de connectivité :**
```bash
# Depuis l'UI : bouton "Ping" sur la page Agents
# Depuis le CLI :
oseye-server agents ping <HOSTNAME> --timeout 5
# → "ok (latency: 42ms)" ou "TIMEOUT"
```

---

### 17. Workers ne traitent qu'une fraction des événements

**Symptômes :**
Des alertes sont générées sporadiquement. Le RuleWorker loggue beaucoup moins d'events que le
StorageWriter. Certains events sont stockés en DB mais n'ont jamais déclenché d'évaluation.

**Cause :**
Dans les versions antérieures à 2026-08-19, tous les workers partageaient le même consumer group
Redis `"oseye"`. Redis distribuait les messages en round-robin → chaque event n'était traité que
par UN seul worker sur N.

**Solution :**
Mettre à jour le serveur. Le bug est corrigé — chaque worker a maintenant son propre consumer group
(`oseye-storage`, `oseye-rules`, `oseye-ml`, `oseye-ti`, etc.).

**Vérification :**
```bash
# Vérifier les consumer groups créés sur le stream events:normalized
docker exec oseye-redis redis-cli XINFO GROUPS events:normalized
# Doit afficher plusieurs groupes distincts (oseye-storage, oseye-rules, oseye-ml...)
```

---

### 18. Faux positifs massifs sur processus système (`systemd`, `sshd`, `cron`…)

**Symptômes :**
Des centaines d'alertes par heure sur des processus légitimes. L'agent génère des alertes sur
ses propres connexions gRPC vers le serveur.

**Cause :**
Les profils de surveillance n'avaient pas de section `baseline_apps` — les baselines arrivaient
vides à l'agent. De plus, `ignore_processes` n'incluait pas les binaires OSEye eux-mêmes.

**Solution :**
Mettre à jour le serveur (corrigé depuis 2026-08-19). Tous les profils incluent maintenant :
- `baseline_apps` : liste des processus légitimes par rôle (systemd, sshd, nginx, etc.)
- `ignore_processes: [oseye-agent, oseye-config]`
- `ignore_paths_prefix: [/etc/oseye/, /var/lib/oseye/]`

**Si les faux positifs persistent après mise à jour :**
```bash
# Forcer la re-synchronisation du profil vers l'agent
oseye-server policy push <HOSTNAME>
# ou redémarrer l'agent pour déclencher la re-sync au reconnect
sudo systemctl restart oseye-agent
```

---

### 19. Alertes `surveillance` redeviennent `anomaly` après redémarrage du serveur

**Symptômes :**
Des alertes créées avec `rule_type: surveillance` apparaissent comme `anomaly` après un redémarrage.
Les règles fonctionnent correctement avant le redémarrage mais pas après rechargement depuis la DB.

**Cause :**
Dans les versions antérieures à 2026-08-19, `AlertRow` n'avait pas de colonne `rule_type`. Les
alertes rechargées depuis la DB héritaient silencieusement du défaut Pydantic `"anomaly"`.

**Solution :**
Mettre à jour le serveur. La colonne `rule_type` est maintenant présente dans `AlertRow` et
correctement persistée/rechargée. Un redémarrage du serveur suffit après mise à jour.

**Vérification :**
```bash
# Vérifier que la colonne existe dans la DB SQLite/PostgreSQL
# SQLite :
sqlite3 /var/lib/oseye/oseye.db "SELECT rule_type FROM alerts LIMIT 5;"
# PostgreSQL :
docker exec oseye-postgres psql -U oseye -c "SELECT rule_type FROM alerts LIMIT 5;"
```

---

### 20. EventMerger — événements `openat` auditd non dédupliqués avec eBPF

**Comportement attendu :**
Les événements `openat` captés simultanément par eBPF et auditd ne sont pas fusionnés.
Deux événements distincts apparaissent pour la même ouverture de fichier.

**Explication :**
C'est une limitation connue du parser auditd actuel : le champ `filename` (fichier accédé)
n'est pas extrait des records `PATH` associés au SYSCALL auditd. Sans ce champ, le fingerprint
de fusion ne peut pas être calculé. Les événements auditd `openat` passent en mode `passthrough`
(non fusionnés).

**Impact :** Léger bruit supplémentaire uniquement si auditd et eBPF sont actifs simultanément.
eBPF étant prioritaire, auditd est redondant dans ce cas.

**Contournement :** Désactiver le collecteur auditd si eBPF est disponible et fonctionnel :
```bash
# Dans agent.env ou la configuration agent
OSEYE_COLLECTOR_AUDITD_ENABLED=false
```

---

## Contacts

Pour signaler un bug ou demander de l'aide :
- GitHub Issues : https://github.com/devmail0561-web/OSEye-plateforme/issues
- Documentation : docs/
