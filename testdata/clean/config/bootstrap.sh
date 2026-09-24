#!/bin/bash
# Credentials are generated at boot, never stored.
set -euo pipefail

KUBE_CONTROLLER_MANAGER_TOKEN="$(secure_random 32)"
KUBE_SCHEDULER_TOKEN="$(head -c 32 /dev/urandom | base64)"
ADDON_MANAGER_TOKEN=`openssl rand -hex 32`
DATABASE_PASSWORD="${DATABASE_PASSWORD:?must be set}"
SERVICE_API_TOKEN=$SERVICE_API_TOKEN
REGISTRY_AUTH=$(cat /run/secrets/registry)

curl -H "Authorization: Bearer ${SERVICE_API_TOKEN}" https://api.internal/v1/ping
