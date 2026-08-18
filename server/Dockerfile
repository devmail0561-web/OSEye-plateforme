# Pin to a digest in production to prevent silent upstream changes:
# FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

# ── Stage 1 : build UI ───────────────────────────────────────────────────────
FROM node:20-slim AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci --prefer-offline
COPY ui/ ./
RUN npm run build

# ── Stage 2 : server ─────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY --chown=root:root server/pyproject.toml .
COPY --chown=root:root server/oseye/ oseye/
COPY --chown=root:root server/gen/ gen/

RUN uv pip install --system --no-cache -e .

# Bundle UI — l'image Docker active le mode management API par défaut.
# Pour désactiver l'UI, passer OSEYE_UI_DIR= (vide) ou
# OSEYE_MANAGEMENT_API_ENABLED=false.
COPY --from=ui-builder /ui/dist /app/ui-dist
ENV OSEYE_UI_DIR=/app/ui-dist

# Non-root service user
RUN groupadd -r oseye && useradd -r -g oseye -s /sbin/nologin oseye

COPY server/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER oseye

EXPOSE 8000 50051

ENTRYPOINT ["/entrypoint.sh"]
CMD ["oseye-server", "start"]
