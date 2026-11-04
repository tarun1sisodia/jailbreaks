FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8080
ENV WEBPROBE_REPORTS_DIR=/app/reports

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY webprobe/ /app/webprobe/
COPY webprobe.py /app/
COPY server.py /app/
COPY config/ /app/config/

# Create reports directory and non-privileged application user
RUN mkdir -p /app/reports && \
    useradd -m -u 1000 webprobe && \
    chown -R webprobe:webprobe /app

USER webprobe

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=3)" || exit 1

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
