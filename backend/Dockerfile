# WebVerity backend — production image
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /src/backend/requirements.txt
RUN pip install --no-cache-dir -r /src/backend/requirements.txt

# Copy the repo root so the `backend.app.*` import path resolves
COPY backend /src/backend
COPY pyproject.toml /src/pyproject.toml
COPY README.md /src/README.md

# Runtime data directory for the SQLite database (mountable volume / persistent disk)
ENV WEBVERITY_DATA_DIR=/data \
    PORT=8000
RUN mkdir -p /data

# Start from /src so `backend.app.main:app` imports correctly.
# The /src launcher resolves WEBVERITY_DATA_DIR at runtime.
CMD ["python", "/src/backend/run_server.py"]
