# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies into a separate layer for cache efficiency
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.12-slim

LABEL maintainer="Firas Ghr" \
      description="Zero-Day Prevention System — behaviour-based EDR tool" \
      version="1.0.0"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Create the logs directory
RUN mkdir -p logs

# Expose the Flask dashboard port
EXPOSE 5001

# Run as non-root for security
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

# Default command — start all monitors and the dashboard
CMD ["python", "main.py"]
