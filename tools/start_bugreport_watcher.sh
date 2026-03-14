#!/usr/bin/env bash
# YADS Bug Report Watcher — manual launcher
# Opens a terminal showing the live watcher output.
# If already running, attaches to its log instead of starting a second instance.

WATCHER_SCRIPT="$HOME/Documents/gitlab/yads/tools/yads_bugreport_watcher.py"
LOG_FILE="$HOME/.local/share/yads-watcher/watcher.log"
PIDFILE="$HOME/.local/share/yads-watcher/watcher.pid"

mkdir -p "$HOME/.local/share/yads-watcher"

# Check if already running
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    if kill -0 "$PID" 2>/dev/null; then
        # Already running — open terminal showing live log
        x-terminal-emulator -T "YADS Bug Watcher (running, PID $PID)" \
            -e bash -c "echo '--- YADS Bug Report Watcher läuft bereits (PID $PID) ---'; echo '--- Live-Log: ---'; tail -n 40 -f \"$LOG_FILE\"; exec bash"
        exit 0
    fi
fi

# Not running — start it and track PID
x-terminal-emulator -T "YADS Bug Report Watcher" \
    -e bash -c "
        touch '$LOG_FILE'
        python3 '$WATCHER_SCRIPT' &
        echo \$! > '$PIDFILE'
        echo '--- YADS Bug Report Watcher gestartet ---'
        echo '--- Live-Log (Ctrl+C stoppt den Watcher): ---'
        tail -n 5 --retry -f '$LOG_FILE' &
        TAIL_PID=\$!
        wait \$(cat '$PIDFILE') 2>/dev/null
        kill \$TAIL_PID 2>/dev/null
        rm -f '$PIDFILE'
        echo '--- Watcher beendet ---'
        exec bash
    "
