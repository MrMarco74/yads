#!/bin/bash
# Pushes the current HEAD to the public GitHub mirror after a local
# safety scan. Normally triggered automatically by the pre-push hook
# (scripts/install-git-hooks.sh); can also be run manually.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="$(basename "$REPO_ROOT")"
LOG_PREFIX="[mirror_to_github]"
cd "$REPO_ROOT"

SECRET_PATTERN="BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY"
DENYLIST='musterbank|redacted|familie-frischkorn\.de|highantdev\.de|fritz\.box'
# This scan's own config (this script + .gitlab-ci.yml) legitimately contains
# the DENYLIST pattern text as configuration, not a leak -- exclude them so
# the scanner doesn't trip over its own source.
SCAN_EXCLUDES=(':(exclude)scripts/mirror_to_github.sh' ':(exclude).gitlab-ci.yml')

if git grep -rIlE "$SECRET_PATTERN" HEAD -- . "${SCAN_EXCLUDES[@]}" >/dev/null 2>&1; then
    echo "$LOG_PREFIX private key material found in HEAD, sync aborted:" >&2
    git grep -lE "$SECRET_PATTERN" HEAD -- . "${SCAN_EXCLUDES[@]}" >&2
    exit 1
fi

if git grep -rIlE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >/dev/null 2>&1; then
    echo "$LOG_PREFIX denylisted term found in HEAD, sync aborted:" >&2
    git grep -lE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >&2
    exit 1
fi

git push https://github.com/MrMarco74/"$REPO_NAME".git HEAD:main
echo "$LOG_PREFIX pushed to github.com/MrMarco74/$REPO_NAME"
