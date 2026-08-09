# Tâche : Refonte dataflow.html — layout hub & spoke

## Fichier cible
`/home/virus-one/Documents/OSEye_project/docs/dataflow.html`

## Problème actuel
Layout linéaire gauche→droite qui force le scroll. Ne montre pas que le serveur admin est central et les endpoints sont des machines distantes.

## Ce qu'il faut faire : réécriture complète du SVG

### Layout cible
```
          [ Linux Endpoint ]
                 |  mTLS/gRPC
[ macOS ] ------[ SERVEUR ADMIN ]------ [ Windows ]
                 |  mTLS/gRPC
          [ Futur / Other ]
```

### 1. SVG + wrapper
- `viewBox="0 0 1400 860"`
- `svg#flow` : `width: 100%; height: calc(100vh - 120px)` (pas de min-width, pas de scroll)
- Supprimer `.canvas-wrapper { overflow-x: auto }`

### 2. Serveur Admin — zone centrale
- Rect centré : `x=490 y=60 w=420 h=740`
- Label : "SERVEUR ADMIN — central"
- Contenu interne (de haut en bas, compact) :
  - **Ingest** : gRPC Server · Validator · Normalizer
  - **Event Bus** : memory/Redis/Kafka
  - **Engines** : Rule Engine · ML · Correlation · Threat Intel
  - **Decision & Alerts** : Decision Engine · Alert Manager
  - **Workers** : Storage Writer · Worker Runner
  - **Storage** : SQLite/Postgres/ClickHouse + Router + Repos
  - **API/UI** : FastAPI · WebSocket · Auth · Dashboard UI
- Texte réduit : `node-title 11px`, `node-sub 9px`, `section-label 9px`
- Conserver les pills de statut (Phase ✓ / En cours / Prévu)

### 3. Endpoints (4 blocs autour)

**Linux** — gauche, centré verticalement (`x=30 y=220 w=200 h=380`)
- Couleur : `#4f8ef7`
- Contenu : eBPF · auditd · fanotify · inotify · procfs · netlink · journald · udev · syslog → Collector Manager → Buffer/Signer → gRPC Batcher
- Statut : opérationnel ✓

**Windows** — haut droite (`x=970 y=80 w=200 h=160`)
- Couleur : `#38bdf8`
- Contenu : ETW / Sysmon → gRPC Batcher
- Pill : Phase 3+

**macOS** — bas droite (`x=970 y=560 w=200 h=160`)
- Couleur : `#3ecf8e`
- Contenu : EndpointSecurity → gRPC Batcher
- Pill : Phase 3+

**Futur (IoT/Other)** — bas gauche (`x=30 y=680 w=200 h=80`)
- Couleur : `#555`, bordure dashed
- Contenu : "Agent générique"
- Pill : Phase 10+

### 4. Connexions hub & spoke
Chaque endpoint → bord du rect serveur admin, avec :
- Trait épais (`stroke-width: 2`) dans la couleur de l'endpoint
- `stroke-dasharray: 6,3` pour Windows, macOS, Futur
- Label centré sur le trait : `mTLS · Protobuf v3`
- Marker arrowhead en bout

### 5. Sources externes (Threat Intel)
Petit bloc en bas du SVG centré sous le serveur admin :
- AbuseIPDB · VirusTotal · MISP · TAXII Feed
- Flèche montante vers le serveur

### 6. Stat tiles
Réduire à 1 ligne horizontale compacte sous le header :
`3 plateformes | <500ms détection | 100k+ events/s | <2% CPU | 80%+ tests`

### 7. Légende
Garder la légende mais compacte, 1 seule ligne.

## Tooltips à conserver
Tous les `data-id` existants + ajouter : `win-etw`, `win-batcher`, `mac-es`, `mac-batcher`

## Vérification
Ouvrir `file:///home/virus-one/Documents/OSEye_project/docs/dataflow.html` — tout doit tenir dans un écran 1920×1080 sans scroll.
