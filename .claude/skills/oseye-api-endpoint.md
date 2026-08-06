# Skill : OSEye — Ajouter un endpoint API REST

## Quand utiliser ce skill
Invoquer avec `/oseye-api-endpoint` quand l'utilisateur demande d'ajouter ou modifier un endpoint dans l'API REST FastAPI d'OSEye.

---

## Ce que tu dois faire

Tu crées un endpoint FastAPI conforme aux patterns de `docs/ARCHITECTURE.md` §7 et §5.3.

### Étape 1 — Identifier l'endpoint

Si non fourni :
- **Méthode** : GET | POST | PATCH | PUT | DELETE
- **Path** : ex `/api/v1/alerts/{alert_id}/acknowledge`
- **Rôle minimum requis** : reader | analyst | senior_analyst | admin
- **Corps de requête / réponse** : modèles Pydantic impliqués

### Étape 2 — Vérifier que le router existe

Les routers sont dans `server/oseye/api/routers/`. Si le router n'existe pas, le créer et l'enregistrer dans `server/oseye/api/app.py` :

```python
# api/app.py
from oseye.api.routers import <module>
app.include_router(<module>.router, prefix="/api/v1")
```

### Étape 3 — Écrire l'endpoint

**Template complet :**

```python
# server/oseye/api/routers/<domain>.py
from fastapi import APIRouter, Depends, HTTPException, status
from oseye.api.auth.rbac import require_role
from oseye.core.schema import <Model>, <ResponseModel>
from oseye.storage.interface import <Repository>

router = APIRouter(prefix="/<domain>", tags=["<Domain>"])


@router.get(
    "/{item_id}",
    response_model=<ResponseModel>,
    summary="<Description courte>",
)
async def get_item(
    item_id: UUID,
    repo: <Repository> = Depends(get_repo),
    current_user=Depends(require_role("reader")),  # rôle minimum
) -> <ResponseModel>:
    item = await repo.get(item_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return item


@router.post(
    "/{item_id}/action",
    response_model=<ResponseModel>,
    status_code=status.HTTP_200_OK,
)
async def do_action(
    item_id: UUID,
    body: <RequestBody>,
    repo: <Repository> = Depends(get_repo),
    current_user=Depends(require_role("senior_analyst")),
) -> <ResponseModel>:
    item = await repo.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Not found")
    # logique métier
    updated = await repo.update(item_id, ...)
    return updated
```

### Étape 4 — Middleware audit log

Le middleware `audit/middleware.py` trace automatiquement chaque requête. Aucun code supplémentaire nécessaire — vérifier que le middleware est bien enregistré dans `app.py` :

```python
from oseye.audit.middleware import AuditMiddleware
app.add_middleware(AuditMiddleware)
```

### Étape 5 — RBAC — niveaux d'accès

| Dépendance | Rôle minimum | Usage typique |
|-----------|-------------|---------------|
| `require_role("reader")` | reader | GET — lecture |
| `require_role("analyst")` | analyst | PATCH status/notes |
| `require_role("senior_analyst")` | senior_analyst | Créer règles, approuver décisions |
| `require_role("admin")` | admin | Suppressions, plugins, agents |

### Étape 6 — Schémas de pagination

Pour les endpoints de liste :

```python
from oseye.core.schema import Page, Pagination

@router.get("/", response_model=Page[<Model>])
async def list_items(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    # filtres spécifiques...
    repo: <Repository> = Depends(get_repo),
    current_user=Depends(require_role("reader")),
) -> Page[<Model>]:
    filters = <Filter>(...)
    return await repo.query(filters, Pagination(limit=limit, offset=offset))
```

### Étape 7 — WebSocket (si temps réel requis)

Si l'endpoint doit envoyer des mises à jour live, broadcaster via `WebSocketManager` :

```python
from oseye.api.ws.manager import ws_manager

# Après création/modification :
await ws_manager.broadcast("<channel>", item.model_dump_json())
```

Channels disponibles : `events`, `alerts`, `decisions`, `dashboard`.

### Étape 8 — Tests

Créer `server/tests/unit/api/test_<domain>.py` :

```python
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_get_item_not_found(client: AsyncClient, auth_headers):
    resp = await client.get("/api/v1/<domain>/nonexistent-uuid", headers=auth_headers)
    assert resp.status_code == 404

@pytest.mark.asyncio
async def test_action_requires_role(client: AsyncClient, reader_headers):
    resp = await client.post("/api/v1/<domain>/uuid/action", headers=reader_headers)
    assert resp.status_code == 403
```

### Étape 9 — Mettre à jour le catalogue API

Vérifier que l'endpoint est documenté dans `docs/ARCHITECTURE.md` §7. Si non, l'ajouter dans la section correspondante.

---

## Contraintes à respecter

- **Jamais** de logique métier directement dans le router — déléguer au repository ou à un service
- Les endpoints retournant des listes **doivent** être paginés (`Page[T]`)
- Toute modification de données doit être tracée (custody log pour les cases, journal pour les decisions)
- Les endpoints de suppression (`DELETE`) sont réservés au rôle `admin` et ne suppriment jamais les décisions ou le custody log
- Toujours `get_settings()` (décorée `@lru_cache`) — jamais `Settings()` direct dans un handler (instanciation répétée à chaque requête)
- Les dataclasses internes (`_Filter`, `_Pagination`) doivent être définies au niveau module, pas à l'intérieur des handlers ou des fonctions
- `_connections` dans `WebSocketManager` est un `set`, pas une `list` — ne pas itérer avec index
- Référence : `docs/ARCHITECTURE.md` §7, §5.3, §5.6
