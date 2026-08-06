FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir hatchling

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY oseye/ oseye/
COPY workers/ workers/
COPY gen/ gen/

EXPOSE 8000 50051

CMD ["uvicorn", "oseye.main:app", "--host", "0.0.0.0", "--port", "8000"]
