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
- **PKI interne** — mTLS entre agent et server, certificats par agent
- **JWT RS256** — authentification API, refresh token HttpOnly
- **RBAC 4 niveaux** — reader, analyst, senior_analyst, admin
- **Hash chain BLAKE3 + signature Ed25519** — intégrité des events
- **Journal immutable** — décisions protégées par hash chain signé
- **Plugin sandbox** — subprocess isolé avec cgroups v2

## Remerciements

Nous remercions les chercheurs en sécurité qui contribuent à améliorer OSEye via une divulgation responsable.
