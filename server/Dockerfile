# Pin to a digest in production to prevent silent upstream changes:
# FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

# Pin to a digest in production to prevent silent upstream changes:
# FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY --chown=root:root pyproject.toml .
COPY --chown=root:root oseye/ oseye/
COPY --chown=root:root gen/ gen/

RUN uv pip install --system --no-cache -e .

# Non-root service user. The /etc/oseye volume files written by
# 'oseye-server init/setup' must be owned or group-accessible by this user.
RUN groupadd -r oseye-srv && useradd -r -g oseye-srv -s /sbin/nologin oseye-srv

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER oseye-srv

EXPOSE 8000 50051

# Default: agent-only mode (health + enrollment only).
# Set OSEYE_MANAGEMENT_API_ENABLED=true to expose the full management API.
# Set OSEYE_UI_DIR=/path/to/dist to also serve the UI from this container.
ENTRYPOINT ["/entrypoint.sh"]
CMD ["oseye-server", "start"]
