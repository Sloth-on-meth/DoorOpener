FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_DEBUG=False

# Install minimal tools for user/group management and privilege drop
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu passwd ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and entrypoint
COPY . .
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 6532

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Use gunicorn with environment variable for port; entrypoint will drop privileges.
# NOTE: must stay at --workers 1. Rate-limiting/brute-force counters live in
# process memory (see app.py), so multiple workers would each keep their own
# counters and an attacker would get N times the allowed attempts. Concurrency
# is provided via threads instead.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${DOOROPENER_PORT:-6532} app:app --workers 1 --threads 4 --timeout 60"]
