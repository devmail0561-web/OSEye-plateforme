FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml .
RUN uv pip install --system --no-cache -e .

COPY oseye/ oseye/
COPY workers/ workers/
COPY gen/ gen/

EXPOSE 8000 50051

# oseye-server is installed as a script entry point by pyproject.toml [project.scripts]
CMD ["oseye-server", "start"]
