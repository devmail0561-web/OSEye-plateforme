# OSEye UI — Phase 9 : État d'avancement

**Date :** 2026-08-10  
**Branche :** `main`  
**Plan complet :** `/home/virus-one/.claude/plans/plannifies-le-developpement-staged-abelson.md`

---

## Modules terminés ✅

### M32a — Scaffold projet
- `ui/package.json` ✅
- `ui/vite.config.ts` ✅
- `ui/tsconfig.json` + `tsconfig.app.json` + `tsconfig.node.json` ✅
- `ui/tailwind.config.ts` ✅
- `ui/postcss.config.ts` ✅
- `ui/eslint.config.js` ✅
- `ui/index.html` ✅
- `ui/src/main.tsx` ✅
- `ui/src/index.css` ✅
- `ui/src/test/setup.ts` ✅
- `ui/src/App.test.tsx` ✅

### M32q — nginx.conf + Makefile
- `ui/nginx.conf` ✅
- `ui/Dockerfile` (ajout `COPY nginx.conf`) ✅
- `Makefile` (cibles `ui-dev`, `ui-build`, `ui-test`, `ui-lint`, `test-ui`) ✅

### M32b — Types TypeScript + Client API
- `ui/src/types/index.ts` ✅ (tous les types : UniversalEvent, Alert, Decision, ForensicCase, Rule, Incident, SurveillanceProfile, PluginInfo, AggregatedTIReport, AgentSnapshot, enums…)
- `ui/src/api/client.ts` ✅ (client Axios + intercepteur 401-refresh + authApi, eventsApi, alertsApi, decisionsApi, casesApi, rulesApi, incidentsApi, tiApi, pluginsApi, policiesApi, healthApi)

### M32c — Auth Store + Login
- `ui/src/stores/authStore.ts` ✅ (Zustand + localStorage + decode JWT exp)
- `ui/src/pages/Login.tsx` ✅

### M32d — Route Guard + Shell Layout
- `ui/src/components/ProtectedRoute.tsx` ✅
- `ui/src/components/layout/AppShell.tsx` ✅
- `ui/src/components/layout/Sidebar.tsx` ✅
- `ui/src/components/layout/Header.tsx` ✅
- `ui/src/App.tsx` ✅ (router complet avec lazy loading)

### M32e — Dashboard
- `ui/src/stores/alertStore.ts` ✅
- `ui/src/stores/eventStore.ts` ✅
- `ui/src/pages/Dashboard.tsx` ✅ (LineChart events/s, PieChart sévérité, KPI open alerts)

### M32m — WebSocket Hooks
- `ui/src/stores/wsStore.ts` ✅
- `ui/src/hooks/useWebSocket.ts` ✅ (reconnect exponentiel, JWT premier frame)
- `ui/src/hooks/useAlertsWebSocket.ts` ✅
- `ui/src/hooks/useTheme.ts` ✅
- `ui/src/hooks/useCountdown.ts` ✅
- `ui/src/hooks/useD3.ts` ✅

### Composants partagés
- `ui/src/components/SeverityBadge.tsx` ✅
- `ui/src/components/RelativeTime.tsx` ✅
- `ui/src/components/CaseTimeline.tsx` ✅
- `ui/src/components/CodeEditor.tsx` ✅ (CodeMirror 6, YAML, dark/light)

### Pages partielles
- `ui/src/pages/Events.tsx` ✅ (table + filtres URL-synced + pagination — **interrompue en cours de session**)

---

## Modules terminés (suite) ✅

### M32g — Alerts
- `ui/src/pages/Alerts.tsx` ✅ (table filtres status/severity/hostname, pagination URL-synced)
- `ui/src/components/AlertRow.tsx` ✅ (déjà créé, ack/FP optimiste)

### M32h — Decisions
- `ui/src/pages/Decisions.tsx` ✅ (cartes pending avec approve/reject/note, score bars, countdown, table historique)

### M32i — Cases
- `ui/src/pages/Cases.tsx` ✅ (liste + modal création)
- `ui/src/pages/CaseDetail.tsx` ✅ (5 onglets : Aperçu, Preuves, Notes, Custody, Timeline + exports JSON/HTML/PDF)

### M32j — Incidents
- `ui/src/pages/Incidents.tsx` ✅ (liste + filtres hostname/status)
- `ui/src/pages/IncidentDetail.tsx` ✅ (KPIs, MITRE tactics, timeline, alertes liées)

### M32k — Rules
- `ui/src/pages/Rules.tsx` ✅ (liste, expand avec CodeEditor YAML + validate, reload)

### M32l — NetworkGraph
- `ui/src/pages/NetworkGraph.tsx` ✅ (D3 force-directed, hôtes/IPs, drag+zoom, 250 derniers events réseau)

---

## Modules à implémenter ❌

### Tests unitaires ✅ (85 tests, 17 suites — tous verts)
| Fichier | Ce qu'il teste |
|---------|---------------|
| `ui/src/stores/authStore.test.ts` | login/logout/setToken |
| `ui/src/pages/Login.test.tsx` | form submit, redirect, erreur 401 |
| `ui/src/components/ProtectedRoute.test.tsx` | redirect si non auth |
| `ui/src/pages/Dashboard.test.tsx` | KPI tile, mock alertsApi.stats |
| `ui/src/pages/Events.test.tsx` | rendu lignes, filtres, pagination |
| `ui/src/pages/Alerts.test.tsx` | ack/FP optimiste |
| `ui/src/hooks/useCountdown.test.ts` | expired true/false |
| `ui/src/pages/Decisions.test.tsx` | cartes approbation |
| `ui/src/pages/Cases.test.tsx` + `CaseDetail.test.tsx` | CRUD, onglets, export |
| `ui/src/pages/Incidents.test.tsx` + `IncidentDetail.test.tsx` | liste, timeline |
| `ui/src/pages/Rules.test.tsx` | liste, validate |
| `ui/src/pages/NetworkGraph.test.tsx` | SVG rendu |
| `ui/src/hooks/useWebSocket.test.ts` | reconnect, backoff |
| `ui/src/hooks/useTheme.test.ts` | toggle dark class |
| `ui/src/api/client.test.ts` | injection token, retry 401 |

### E2E Playwright (M32p)
- `ui/playwright.config.ts`
- `ui/e2e/mocks/handlers.ts`
- `ui/e2e/golden-path-dashboard.spec.ts`
- `ui/e2e/golden-path-case.spec.ts`
- `ui/e2e/golden-path-decision.spec.ts`

### Dark mode polish (M32o)
- `useTheme` hook créé mais variantes `dark:` non appliquées systématiquement sur toutes les pages

---

## Ordre de reprise recommandé

```
1. ✅ Alerts.tsx + AlertRow.tsx          (M32g)
2. ✅ Decisions.tsx                      (M32h)
3. ✅ Cases.tsx + CaseDetail.tsx         (M32i)
4. ✅ Incidents.tsx + IncidentDetail.tsx (M32j)
5. ✅ Rules.tsx                          (M32k)
6. ✅ NetworkGraph.tsx                   (M32l)
7. ✅ Tests unitaires (85 tests, 17 suites)
8. ✅ Dark mode polish (M32o)
9. E2E Playwright (M32p)                ← NEXT
```

---

## Commandes de vérification

```bash
cd ui
npm install           # installer les dépendances
npm run lint          # doit passer à 0 warnings
npm test -- --coverage  # vitest, génère ui/coverage/lcov.info
npm run build         # tsc + vite build → dist/
```

## Points de vigilance (rappel)

| Risque | Mitigation |
|--------|-----------|
| Pas de `PATCH /rules/{id}` | Toggle disabled + tooltip "Géré via CLI" |
| JWT comme premier frame WS | `ws.send(token)` dans `onopen` |
| D3 + React StrictMode | `useEffect` cleanup `simulation.stop()` |
| `timestamp_ns` int64 | Diviser par `1_000_000` pour obtenir ms |
