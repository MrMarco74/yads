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

if git grep -rIlE "$SECRET_PATTERN" HEAD -- . >/dev/null 2>&1; then
    echo "$LOG_PREFIX private key material found in HEAD, sync aborted:" >&2
    git grep -lE "$SECRET_PATTERN" HEAD -- . >&2
    exit 1
fi

if git grep -rIlE "$DENYLIST" HEAD -- . >/dev/null 2>&1; then
    echo "$LOG_PREFIX denylisted term found in HEAD, sync aborted:" >&2
    git grep -lE "$DENYLIST" HEAD -- . >&2
    exit 1
fi

git push https://github.com/MrMarco74/"$REPO_NAME".git HEAD:main
echo "$LOG_PREFIX pushed to github.com/MrMarco74/$REPO_NAME"
