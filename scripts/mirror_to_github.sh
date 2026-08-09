#!/bin/bash
# Pushes the current HEAD to the public GitHub mirror after a local
# safety scan. Normally triggered automatically by the pre-push hook
# (scripts/install-git-hooks.sh); can also be run manually.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="$(basename "$REPO_ROOT")"
LOG_PREFIX="[mirror_to_github]"
cd "$REPO_ROOT"

BEGIN_PATTERN="BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY"
END_PATTERN="END (RSA |OPENSSH |PGP )?PRIVATE KEY"
DENYLIST='musterbank|redacted|familie-frischkorn\.de|highantdev\.de|fritz\.box'
# This scan's own config (this script + .gitlab-ci.yml) legitimately contains
# the DENYLIST pattern text as configuration, not a leak -- exclude them so
# the scanner doesn't trip over its own source.
SCAN_EXCLUDES=(':(exclude)scripts/mirror_to_github.sh' ':(exclude).gitlab-ci.yml')

# A real embedded PEM key always has both a BEGIN and an END line; a bare
# BEGIN match alone is usually just a detection-pattern string literal (yads
# is a scanner -- its own modules legitimately contain
# "-----BEGIN PRIVATE KEY-----" as a regex to detect exposed keys on *scanned
# targets*, not an embedded key of its own).
_begin_files="$(git grep -lIE "$BEGIN_PATTERN" HEAD -- . "${SCAN_EXCLUDES[@]}" 2>/dev/null || true)"
_real_key_hit=""
for f in $_begin_files; do
    if git grep -qIE "$END_PATTERN" HEAD -- "$f" 2>/dev/null; then
        _real_key_hit="1"
        echo "$LOG_PREFIX private key material found in HEAD: $f" >&2
    fi
done
if [ -n "$_real_key_hit" ]; then
    echo "$LOG_PREFIX sync aborted." >&2
    exit 1
fi

if git grep -rIlE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >/dev/null 2>&1; then
    echo "$LOG_PREFIX denylisted term found in HEAD, sync aborted:" >&2
    git grep -lE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >&2
    exit 1
fi

git push https://github.com/MrMarco74/"$REPO_NAME".git HEAD:main
echo "$LOG_PREFIX pushed to github.com/MrMarco74/$REPO_NAME"
