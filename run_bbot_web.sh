#!/bin/bash

set -euo pipefail

PLATFORM="${BBOT_DOCKER_PLATFORM:-}"
SKIP_BUILD="${BBOT_SKIP_BUILD:-0}"

# Build the Docker image (unless explicitly skipped)
if [ "${SKIP_BUILD}" != "1" ]; then
    if [ -n "${PLATFORM}" ]; then
        echo "[+] Building BBOT Guardian Docker image for ${PLATFORM}..."
        docker build --platform "${PLATFORM}" -t bbot-guardian .
    else
        echo "[+] Building BBOT Guardian Docker image..."
        docker build -t bbot-guardian .
    fi
else
    echo "[+] Skipping image build (BBOT_SKIP_BUILD=1)"
fi

# Run the container
echo "[+] Starting BBOT Guardian..."
echo "[+] Web Interface will be available at http://localhost:8765"

# Ensure scan directory exists on host to persist data
mkdir -p "$HOME/.bbot/scans"

ENV_ARGS=()
TMP_ENV_FILE=""
ENV_FILE="${1:-}"
if [ -n "$ENV_FILE" ]; then
    if [ -f "$ENV_FILE" ]; then
        echo "[+] Using .env file: $ENV_FILE"
        TMP_ENV_FILE="$(mktemp /tmp/bbot-guardian-env.XXXXXX)"
        # Docker --env-file does not understand shell-style inline comments or quoted values.
        # Normalize to plain KEY=VALUE lines.
        awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                eq = index($0, "=")
                if (eq == 0) next
                key = substr($0, 1, eq - 1)
                val = substr($0, eq + 1)

                gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
                sub(/[[:space:]]+#.*$/, "", val)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)

                if (val ~ /^".*"$/) {
                    val = substr(val, 2, length(val) - 2)
                }
                print key "=" val
            }
        ' "$ENV_FILE" > "$TMP_ENV_FILE"
        ENV_ARGS=(--env-file "$TMP_ENV_FILE")
    else
        echo "[-] Error: .env file '$ENV_FILE' not found"
        exit 1
    fi
fi

RUN_PLATFORM_ARGS=()
if [ -n "${PLATFORM}" ]; then
    RUN_PLATFORM_ARGS+=(--platform "${PLATFORM}")
fi

DOCKER_CMD=(docker run)
if [ -t 0 ] && [ -t 1 ]; then
    DOCKER_CMD+=(-it)
fi

DOCKER_CMD+=(--rm)
if [ "${#RUN_PLATFORM_ARGS[@]}" -gt 0 ]; then
    DOCKER_CMD+=("${RUN_PLATFORM_ARGS[@]}")
fi
DOCKER_CMD+=(-p 8765:8765)
DOCKER_CMD+=(-v "$HOME/.bbot/scans:/root/.bbot/scans")
if [ "${#ENV_ARGS[@]}" -gt 0 ]; then
    DOCKER_CMD+=("${ENV_ARGS[@]}")
fi
DOCKER_CMD+=(--name bbot-guardian)
DOCKER_CMD+=(bbot-guardian)

"${DOCKER_CMD[@]}"

if [ -n "$TMP_ENV_FILE" ] && [ -f "$TMP_ENV_FILE" ]; then
    rm -f "$TMP_ENV_FILE"
fi
