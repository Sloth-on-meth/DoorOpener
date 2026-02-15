ARG BUILD_FROM
FROM ${BUILD_FROM}

# The pre-built GHCR image already contains the app.
# This Dockerfile only adds the HA add-on run script.
COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
