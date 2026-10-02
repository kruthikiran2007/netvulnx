# NetVulnX — production image (Milestone 17).
#
# Build:  docker build -t netvulnx .
# Run:    docker run -p 127.0.0.1:5000:5000 \
#           -e NETVULNX_SECRET_KEY="<long random>" \
#           -v netvulnx-data:/data netvulnx
#
# The database lives on /data (a volume) so scans, users and the audit
# log survive container restarts and image rebuilds.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    NETVULNX_HOST=0.0.0.0 \
    NETVULNX_DB_PATH=/data/netvulnx.db

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (alembic migrations included — the app self-migrates).
COPY app/ ./app/
COPY scanner/ ./scanner/
COPY rules/ ./rules/
COPY migrations/ ./migrations/
COPY config.py run.py ./

# Run as a non-root user; /data must stay writable.
RUN useradd --create-home --uid 10001 netvulnx \
    && mkdir -p /data && chown netvulnx:netvulnx /data
USER netvulnx

EXPOSE 5000

# waitress serves the app; the scheduler thread starts inside run.py.
CMD ["python", "run.py"]
