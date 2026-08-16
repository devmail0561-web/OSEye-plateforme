# Politique de sécurité — OSEye

## Versions supportées

| Version | Support sécurité |
|---------|-----------------|
| `main` (dev) | Oui |
| Releases stables | Oui (dernière mineure uniquement) |

## Signalement d'une vulnérabilité

**Ne pas ouvrir une issue publique GitHub pour signaler une faille de sécurité.**

### Processus de divulgation responsable

1. **Envoyer un rapport privé** via GitHub Security Advisories :  
   `https://github.com/your-org/oseye/security/advisories/new`  
   ou par email à : `security@oseye.io` (clé PGP disponible sur la page GitHub)

2. **Inclure dans le rapport :**
   - Description de la vulnérabilité
   - Composant affecté (agent, server, API, UI)
   - Étapes de reproduction
   - Impact estimé (confidentialité, intégrité, disponibilité)
   - Suggestion de correction si disponible

3. **Délais de réponse :**
   - Accusé de réception : **72 heures**
   - Évaluation initiale : **7 jours**
   - Correction et patch : **30 jours** (critiques), **90 jours** (modérées)

4. **Divulgation coordonnée :**  
   Nous vous informons avant la publication du correctif. Un CVE sera demandé si applicable.  
   Le chercheur sera crédité dans les notes de version (sauf souhait d'anonymat).

## Périmètre de sécurité

### Dans le périmètre

- Injection de commandes via les règles YAML/TOML
- Contournement d'authentification (JWT, mTLS, RBAC)
- Fuite de données sensibles via l'API REST ou WebSocket
- Élévation de privilèges dans l'agent (eBPF, sandbox plugin)
- Falsification du journal immutable des décisions
- Compromission de la chaîne de hachage des events

### Hors périmètre

- Attaques DoS sans impact sur la confidentialité/intégrité
- Attaques nécessitant un accès physique à la machine
- Vulnérabilités dans les dépendances tierces (à signaler à leurs mainteneurs)
- Issues de configuration dans les déploiements utilisateurs

## Architecture de sécurité

Les mécanismes de sécurité implémentés dans OSEye sont décrits dans :  
[`docs/ARCHITECTURE.md` — Section 5 : Architecture de sécurité](docs/ARCHITECTURE.md)

Points clés :
- **PKI interne** — mTLS strict entre agent et server (refus démarrage si certs absents)
- **CA key passphrase** — `OSEYE_TLS_CA_KEY_PASSWORD` active le chiffrement AES de la clé CA sur disque
- **JWT RS256** — authentification API ; rôles décodés à chaque chargement, jamais en localStorage
- **JWT blocklist** — tokens révoqués persistés dans `OSEYE_DATA_DIR/revoked_tokens.json` (0600, créé atomiquement)
- **RBAC 2 niveaux opérationnels** — analyst / admin ; admin hérite de analyst
- **API Keys** — stockées uniquement sous forme HMAC-SHA256 (`OSEYE_SECRET_KEY`, requis ≥ 32 chars)
- **Hash chain BLAKE3 + signature Ed25519** — intégrité des events ; clé de signature Ed25519 séparée de la clé mTLS (RSA)
- **Vérification batch serveur** — `AgentServiceServicer` charge les clés publiques `.pub` au démarrage et vérifie chaque batch
- **Journal immutable** — décisions protégées par hash chain BLAKE3 signé
- **Révocation d'agent** — immédiate via `DELETE /api/v1/agents/{cn}`, persistée en base, rechargée au redémarrage
- **Plugin sandbox** — subprocess isolé avec cgroups v2
- **TLS 1.3 uniquement** sur gRPC (`GRPC_SSL_CIPHER_SUITES` restreint aux suites TLS 1.3)
- **Full-jitter backoff** — reconnexions agent distribuées uniformément (anti thundering herd)

## Sécurité post-installation

### `oseye-server init` — génération PKI et répertoires

`oseye-server init` (Python, `server/oseye/cli/cmd_init.py`) applique `os.umask(0o077)` avant tout appel openssl — les clés privées sont créées directement en mode **0600**, sans fenêtre TOCTOU. Le token d'enrollment est créé via `os.open()` avec `O_CREAT` et le mode cible dès la première ouverture.

Le résumé final n'affiche **jamais** le mot de passe admin en clair.

```bash
sudo oseye-server init [--hostname HOST] [--ip IP] [--force]
```

### `oseye-server setup` — wizard de configuration

`oseye-server setup` (Python, `server/oseye/cli/cmd_setup.py`) :

- **Fichiers créés atomiquement** — `write_secure()` utilise `os.open()` avec le mode cible dès le premier `open()`. Pas de TOCTOU entre création et `chmod`.
- **Mot de passe DB isolé** — pour PostgreSQL, `OSEYE_DB_URL` (avec mot de passe percent-encodé) est écrit **uniquement** dans `secrets.env` (mode 600).
- **Validation hostname** — rejet si `/` ou espace avant injection dans `-subj` OpenSSL.
- **Validation IP** — `ipaddress.ip_address()` avant injection dans la SAN.
- **Anti-injection newline** — toutes les valeurs saisies sont nettoyées de `\n\r`.

```bash
sudo oseye-server setup
```

### `oseye-config enroll` — enrollment agent

`oseye-config enroll` (Go, `agent/cmd/oseye-config/enroll.go`) :

- **Crypto natif** — génération RSA-2048 et CSR via `crypto/rsa` + `crypto/x509`, sans dépendance à openssl.
- **TOFU sécurisé** — `InsecureSkipVerify` uniquement pour la requête initiale de fetch CA ; toutes les requêtes suivantes utilisent le pool CA.
- **Écriture atomique** — `os.OpenFile(O_CREAT|O_TRUNC, 0600)` sans étape chmod séparée.
- **IPv6 et scheme** — `net.SplitHostPort` + strip du scheme `https://` si fourni par l'opérateur.

```bash
sudo oseye-config enroll --server HOST:PORT --token TOKEN
```

### Modèle de permissions des répertoires

| Répertoire | Mode | Justification |
|------------|------|---------------|
| `/etc/oseye/certs` | 700 | Clés privées TLS et JWT |
| `/etc/oseye/enrollment_tokens` | 700 | Tokens à usage unique |
| `/etc/oseye/agent_keys` | 700 | Clés publiques Ed25519 agents |
| `/etc/oseye/plugin_keys` | 700 | Clés de vérification plugins |
| `/etc/oseye/plugins` | 750 | Code plugin — lisible par le groupe `oseye` |
| `/var/lib/oseye` | 750 | Checkpoint ML, buffer — lisible par le groupe `oseye` |
| `/var/run/oseye` | 755 | Socket IPC plugin — accessible au service |

### Séparation server.env / secrets.env

| Fichier | Mode | Contenu |
|---------|------|---------|
| `/etc/oseye/server.env` | 640 | Configuration non-sensible (ports, profils, DB backend…) |
| `/etc/oseye/secrets.env` | 600 | `OSEYE_SECRET_KEY`, passwords, API keys, `OSEYE_DB_URL` PostgreSQL |

Ne jamais committer `secrets.env`. En production, utiliser un secrets manager (Vault, AWS Secrets Manager) et injecter via `EnvironmentFile=` systemd ou Docker secrets.

## Remerciements

Nous remercions les chercheurs en sécurité qui contribuent à améliorer OSEye via une divulgation responsable.
