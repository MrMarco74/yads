#!/usr/bin/env bash
# YADS Support Watcher — launcher
# Startet den Tray-Daemon im Hintergrund. Läuft bereits? Kein zweiter Start.

WATCHER_SCRIPT="$HOME/Documents/gitlab/yads/tools/yads_support_watcher.py"
PIDFILE="$HOME/.local/share/yads-watcher/watcher.pid"

mkdir -p "$HOME/.local/share/yads-watcher"

# Already running?
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    if kill -0 "$PID" 2>/dev/null; then
        notify-send "YADS Support Watcher" "Läuft bereits (PID $PID)" \
            --icon="$HOME/.local/share/icons/yads-bug-watcher.png" 2>/dev/null || true
        exit 0
    fi
fi

python3 "$WATCHER_SCRIPT" &
echo $! > "$PIDFILE"
