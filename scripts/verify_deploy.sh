#!/usr/bin/env bash
# verify_deploy.sh — fail loudly when a running yads container is stale
# relative to the source it was supposedly deployed from.
#
# WHY: the app_yads update playbook already does `build: always` +
# `recreate: always`, so a normal update rebuilds correctly. The failure mode
# that has bitten twice (2026-08-23 and again 2026-08-25) is upstream of the
# playbook: code committed but NOT pushed to origin/main, so the deploy pulls
# and rebuilds identical code, the containers are recreated, and everything
# reports success — while the running image is still N commits behind what the
# operator believes they shipped. Nothing surfaced the drift.
#
# This compares the git SHA of the deployed source checkout on the host against
# the YADS_GIT_SHA baked into the running api/worker containers, and against
# origin/main. It exits non-zero (with a clear message) on any mismatch, so a
# deploy step — or a human — gets an unambiguous signal instead of a silent
# stale deploy.
#
# Usage (on the yads host, after a deploy):
#   scripts/verify_deploy.sh [SOURCE_DIR]
# SOURCE_DIR defaults to /opt/yads/yads (the app_yads yads_core_dir).
#
# To wire into the app_yads role, add a final task to update.yml:
#   - name: "[app_yads] Verify the deploy is not stale"
#     ansible.builtin.command: "{{ yads_core_dir }}scripts/verify_deploy.sh {{ yads_core_dir }}"
#     changed_when: false
set -euo pipefail

SRC_DIR="${1:-/opt/yads/yads}"

fail() { echo "STALE DEPLOY: $*" >&2; exit 1; }

command -v git >/dev/null || fail "git not found on host"
command -v docker >/dev/null || fail "docker not found on host"

HOST_SHA="$(git -C "$SRC_DIR" rev-parse --short HEAD 2>/dev/null)" || fail "cannot read git HEAD in $SRC_DIR"

# Warn (do not fail) if the checkout itself is behind origin/main — that means
# the deploy pulled but origin has newer commits, or local commits were never
# pushed. Best-effort: skip if we can't reach the remote.
if git -C "$SRC_DIR" fetch --quiet origin main 2>/dev/null; then
    ORIGIN_SHA="$(git -C "$SRC_DIR" rev-parse --short origin/main)"
    if [ "$HOST_SHA" != "$ORIGIN_SHA" ]; then
        echo "WARNING: deployed checkout ($HOST_SHA) != origin/main ($ORIGIN_SHA) — unpushed or unpulled commits?" >&2
    fi
fi

rc=0
for name in yads-api yads-worker; do
    cid="$(docker ps --filter "name=${name}" --format '{{.Names}}' | head -1)"
    [ -n "$cid" ] || { echo "WARNING: no running container matches '${name}'" >&2; continue; }
    csha="$(docker exec "$cid" printenv YADS_GIT_SHA 2>/dev/null || echo unknown)"
    if [ -z "$csha" ] || [ "$csha" = "unknown" ]; then
        # No SHA baked into the image — can't verify (not the same as stale).
        # Warn rather than fail so the guard doesn't cry wolf on an image built
        # without the YADS_GIT_SHA build arg.
        echo "WARNING: $cid has no YADS_GIT_SHA baked in — cannot verify version" >&2
    elif [ "$csha" != "$HOST_SHA" ]; then
        echo "STALE: container $cid is at YADS_GIT_SHA=$csha, host source is at $HOST_SHA" >&2
        rc=1
    else
        echo "OK: $cid at $csha matches host source"
    fi
done

[ "$rc" -eq 0 ] || fail "one or more containers are running code older than the deployed source"
echo "Deploy verified: containers match host source ($HOST_SHA)"
