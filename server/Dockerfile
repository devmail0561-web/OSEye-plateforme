# Pin to a digest in production to prevent silent upstream changes:
# FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

# SDK (optionnel — non requis si oseye-sdk est installé via PyPI)
# Install server
COPY --chown=root:root server/pyproject.toml .
COPY --chown=root:root server/oseye/ oseye/
COPY --chown=root:root server/gen/ gen/

RUN uv pip install --system --no-cache -e .

# Non-root service user. The /etc/oseye volume files written by
# 'oseye-server init/setup' must be owned or group-accessible by this user.
# Recommended host setup: chown root:oseye /etc/oseye && chmod 750 /etc/oseye
RUN groupadd -r oseye && useradd -r -g oseye -s /sbin/nologin oseye

COPY server/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER oseye

EXPOSE 8000 50051

# oseye-server is installed as a script entry point by pyproject.toml [project.scripts]
ENTRYPOINT ["/entrypoint.sh"]
CMD ["oseye-server", "start"]
