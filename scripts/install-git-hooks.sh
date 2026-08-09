#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_DIR" ]; then
    echo "Error: .git/hooks directory not found." >&2
    exit 1
fi

cat << 'HOOK_EOF' > "$HOOKS_DIR/pre-push"
#!/bin/bash
# Auto-installed by scripts/install-git-hooks.sh
#
# Guard against self-triggering: mirror_to_github.sh's own `git push` (to
# GitHub) fires this SAME pre-push hook again, regardless of which remote
# it targets -- git hooks are per-repo, not per-remote. Without this guard
# that recurses without bound: hook -> spawn -> push -> hook -> spawn -> ...
# (this actually happened, ~2026-08-09, load average ~65 before it was
# caught). mirror_to_github.sh exports YADS_MIRROR_RUNNING=1 before its
# push; a hook invocation that inherits it is that nested push, not a real
# `git push` from a human, so it exits immediately instead of spawning.
if [ -n "${YADS_MIRROR_RUNNING:-}" ]; then
    exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
nohup "$REPO_ROOT/scripts/mirror_to_github.sh" >> "$REPO_ROOT/.git/mirror.log" 2>&1 &
disown
exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-push"
echo "Git hooks installed."
