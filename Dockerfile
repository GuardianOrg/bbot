FROM python:3.11-slim

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PIP_NO_CACHE_DIR=off
ENV PATH="/root/.bbot/tools:${PATH}"

WORKDIR /usr/src/bbot

RUN apt-get update && apt-get install -y \
    openssl \
    gcc \
    g++ \
    git \
    make \
    pkg-config \
    zlib1g-dev \
    chromium \
    unzip \
    curl \
    wget \
    vim \
    nano \
    sudo \
    tini

COPY . .

RUN pip install .

# Preinstall domain-config-dns-audit so BBOT module setup can always find the binary in PATH.
RUN git clone --depth 1 https://github.com/carlospolop/domain-config-dns-audit /opt/domain-config-dns-audit \
    && python3 -m venv /opt/domain-config-dns-audit/.venv \
    && /opt/domain-config-dns-audit/.venv/bin/pip install -r /opt/domain-config-dns-audit/dns-audit/requirements.txt \
    && mkdir -p /root/.bbot/tools \
    && printf '%s\n' '#!/usr/bin/env bash' \
        'exec "/opt/domain-config-dns-audit/.venv/bin/python" "/opt/domain-config-dns-audit/dns-audit/dns_audit.py" "$@"' \
        > /root/.bbot/tools/domain-config-dns-audit \
    && chmod +x /root/.bbot/tools/domain-config-dns-audit

RUN bbot -n deps-warmup -p /usr/src/bbot/my_bbot/all-but-intense-http.yml --allow-deadly -y -t example.com --force-deps --force --dry-run || true

# Web App Dependencies
COPY web_app/requirements.txt /tmp/webapp_requirements.txt
RUN pip install -r /tmp/webapp_requirements.txt

WORKDIR /usr/src/bbot

# Expose Web Interface Port
EXPOSE 8765

# Start Web App
CMD ["python3", "web_app/app.py"]

# ENTRYPOINT [ "bbot" ]
