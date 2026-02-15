ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install Python and pip
RUN apk add --no-cache python3 py3-pip

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages \
    -r requirements.txt gunicorn

# Copy application code
COPY app.py config.py security.py ha_client.py users_store.py ./
COPY templates/ ./templates/
COPY static/ ./static/

# Copy HA add-on run script
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
