# OSEye — Package développement

## Installation rapide

```bash
# Cloner le repo
git clone https://github.com/devmail0561-web/OSEye-plateforme.git
cd OSEye-plateforme

# Installer l'environnement complet
bash scripts/dev-install.sh

# Démarrer les services (Redis + PostgreSQL)
make dev-up

# Lancer le serveur
make run-server

# Lancer l'UI (dans un autre terminal)
make ui-dev
```

## Ce qui est installé

| Composant | Version | Description |
|---|---|---|
| Go | 1.25 | Compiler pour l'agent |
| Python | 3.12 | Runtime serveur |
| Node.js | 20 | Build UI React |
| venv Python | — | Dépendances serveur isolées |
| npm | — | Dépendances UI |

## Commandes disponibles

| Commande | Description |
|---|---|
| `make dev-up` | Démarrer Redis + PostgreSQL |
| `make run-server` | Lancer le serveur (SQLite dev) |
| `make run-agent` | Lancer l'agent |
| `make ui-dev` | UI React (Vite hot reload) |
| `make test` | Tous les tests |
| `make lint` | Lint + vet |
| `make package-all` | Produire les packages prod |
