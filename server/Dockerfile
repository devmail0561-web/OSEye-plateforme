# Pin to a digest in production to prevent silent upstream changes:
# FROM python:3.12-slim@sha256:<digest>
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache -e .

COPY oseye/ oseye/
COPY workers/ workers/
COPY gen/ gen/

# Non-root service user. The /etc/oseye volume files written by
# 'oseye-server init/setup' must be owned or group-accessible by this user.
# Recommended host setup: chown root:oseye /etc/oseye && chmod 750 /etc/oseye
RUN groupadd -r oseye && useradd -r -g oseye -s /sbin/nologin oseye

USER oseye

EXPOSE 8000 50051

# oseye-server is installed as a script entry point by pyproject.toml [project.scripts]
CMD ["oseye-server", "start"]
