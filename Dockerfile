# Image for the ThreatWeave FastAPI service.
FROM python:3.11-slim

# Avoid .pyc files and force unbuffered stdout/stderr for readable container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first so the layer is cached across code changes.
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "threatweave.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
