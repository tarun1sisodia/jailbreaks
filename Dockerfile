# Build the browser application once; the API serves the resulting static files.
FROM node:22-alpine AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV WEBPROBE_REPORTS_DIR=/app/reports

WORKDIR /app

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/webprobe/ /app/webprobe/
COPY backend/webprobe.py backend/server.py /app/
COPY backend/config/ /app/config/
COPY --from=frontend /build/frontend/dist /app/frontend/dist

RUN mkdir -p /app/reports && \
    useradd -m -u 1000 webprobe && \
    chown -R webprobe:webprobe /app

USER webprobe
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=3)" || exit 1

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
