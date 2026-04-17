#!/usr/bin/env bash
# Deploy the current HEAD to the NKS docker host via source-tarball upload.
#
# Usage:
#   ./scripts/deploy.sh                    # deploys current HEAD
#   DEPLOY_HOST=... DEPLOY_PATH=... ./scripts/deploy.sh
#
# Rationale:
# - /opt/nks-wdc-catalog on the prod host is not a git repo; files were
#   uploaded manually for the v0.2 cutover and we've kept that pattern
#   rather than reworking the host.
# - GHCR image exists (ghcr.io/nks-hub/wdc-catalog-api:vX.Y.Z) but the
#   package is private; until it's made public (org-settings) or the host
#   runs ``docker login ghcr.io`` with a PAT, local-build stays simpler.
# - Volume ownership: /state's ``catalog.db`` must be owned by uid 1000
#   (container's ``app`` user). First-time upgrades from older deploys
#   hit "readonly database" on Alembic's create_all if this is wrong;
#   the script fixes it proactively.

set -euo pipefail

: "${DEPLOY_HOST:=10.254.0.28}"
: "${DEPLOY_PATH:=/opt/nks-wdc-catalog}"
: "${DEPLOY_USER:=root}"
: "${DEPLOY_SSH_KEY:=${HOME}/.ssh/id_rsa}"
: "${DEPLOY_CONTAINER:=nks-wdc-catalog-api}"
: "${DEPLOY_VOLUME:=nks-wdc-catalog_catalog-state}"

ssh_cmd() { ssh -i "${DEPLOY_SSH_KEY}" "${DEPLOY_USER}@${DEPLOY_HOST}" "$@"; }
scp_up() { scp -i "${DEPLOY_SSH_KEY}" "$1" "${DEPLOY_USER}@${DEPLOY_HOST}:$2"; }

version=$(python -c "exec(open('app/__init__.py').read()); print(__version__)")
tag=$(git rev-parse --short HEAD)
tarball="/tmp/wdc-catalog-${tag}.tar.gz"

echo "→ packaging HEAD (${tag}, v${version})"
git archive --format=tar.gz HEAD -o "${tarball}"

echo "→ uploading to ${DEPLOY_USER}@${DEPLOY_HOST}:${DEPLOY_PATH}"
scp_up "${tarball}" "/tmp/"

echo "→ extracting + fixing volume permissions + rebuilding"
ssh_cmd bash -s <<REMOTE
set -e
cd "${DEPLOY_PATH}"
tar xzf "/tmp/$(basename ${tarball})" --exclude='docker-compose.yml' --exclude='.env'

# Fix /state ownership so Alembic can write on first boot after upgrade.
# ``chown`` runs unconditionally — it's cheap and idempotent.
mountpoint=\$(docker volume inspect "${DEPLOY_VOLUME}" --format '{{.Mountpoint}}' 2>/dev/null || true)
if [ -n "\${mountpoint}" ]; then
    chown -R 1000:1000 "\${mountpoint}"
fi

docker compose build
docker compose up -d

# Wait for readiness (up to 30s) before declaring success.
for i in \$(seq 1 30); do
    if curl -fsS http://127.0.0.1:18765/readyz >/dev/null 2>&1; then
        echo "→ /readyz OK after \${i}s"
        break
    fi
    sleep 1
done
docker ps --filter name=${DEPLOY_CONTAINER} --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
REMOTE

echo "→ deployed v${version} (${tag}) to ${DEPLOY_HOST}"
