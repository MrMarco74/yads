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
# The denylist of customer/private terms is deliberately NOT stored in the
# repo -- the pattern itself would be the leak. It comes from
# $YADS_MIRROR_DENYLIST or the local file below (see docs/ or the team vault
# for the canonical value). Missing config fails the push closed.
DENYLIST_FILE="${YADS_MIRROR_DENYLIST_FILE:-$HOME/.yads/mirror-denylist}"
DENYLIST="${YADS_MIRROR_DENYLIST:-}"
if [ -z "$DENYLIST" ] && [ -r "$DENYLIST_FILE" ]; then
    DENYLIST="$(head -n1 "$DENYLIST_FILE")"
fi
if [ -z "$DENYLIST" ]; then
    echo "$LOG_PREFIX no denylist configured (set YADS_MIRROR_DENYLIST or create" >&2
    echo "$LOG_PREFIX $DENYLIST_FILE); refusing to mirror to a public remote." >&2
    exit 1
fi
SCAN_EXCLUDES=()

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

# Exported so the pre-push hook this triggers (hooks are per-repo, not
# per-remote -- this push re-fires it) can recognize this as its own nested
# push and exit immediately instead of spawning another copy of this script.
export YADS_MIRROR_RUNNING=1
git push https://github.com/MrMarco74/"$REPO_NAME".git HEAD:main
echo "$LOG_PREFIX pushed to github.com/MrMarco74/$REPO_NAME"
