# ===========================================================================
# SecScan — bitta image: React frontend (build) + FastAPI backend.
# Konteyner host Docker soketi orqali skaner konteynerlarini ishga tushiradi
# (Docker-out-of-Docker), shuning uchun ichida docker CLI bor.
# ===========================================================================

# 1-bosqich: frontendni build qilish
FROM node:18-alpine AS frontend
WORKDIR /fe
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# 2-bosqich: backend + docker CLI
FROM python:3.11-slim

# docker CLI (statik binary) — mounted soket orqali host daemon'ga buyruq beradi
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-24.0.7.tgz -o /tmp/d.tgz \
    && tar -xzf /tmp/d.tgz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm /tmp/d.tgz \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY secscan/ ./secscan/
COPY run.py ./
# Build qilingan frontend (web.py uni /app/frontend/dist da kutadi)
COPY --from=frontend /fe/dist ./frontend/dist

EXPOSE 8000
CMD ["python", "-m", "secscan", "serve", "--host", "0.0.0.0", "--port", "8000"]
