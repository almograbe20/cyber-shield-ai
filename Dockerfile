# Cyber Shield AI — container image (isolation + easy deployment)
FROM python:3.11-slim

# Don't write .pyc files; unbuffered logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY backend ./backend
COPY frontend ./frontend

# Run as a non-root user (defense in depth — the scanner runs isolated)
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

# In production, set these via your orchestrator:
#   ANTHROPIC_API_KEY=...            (enables real Claude analysis)
#   CYBERSHIELD_ALLOW_LOCALHOST=0    (block loopback scanning in production)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
