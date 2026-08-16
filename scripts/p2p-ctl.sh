#!/usr/bin/env bash
# p2p-ctl.sh - simple Linux/macOS up/down/status control for p2p-client.
#
# Usage:
#   p2p-ctl.sh up   [mesh args...]   # start p2p-client mesh in background
#   p2p-ctl.sh down                  # stop the background p2p-client
#   p2p-ctl.sh status                # show whether it is running
#
# Environment:
#   P2P_PIDFILE  pid file location (default: /tmp/p2p-client.pid)
#   P2P_LOG      log file location  (default: /tmp/p2p-client.log)
set -euo pipefail

PIDFILE="${P2P_PIDFILE:-/tmp/p2p-client.pid}"
LOG="${P2P_LOG:-/tmp/p2p-client.log}"

case "${1:-}" in
  up)
    shift
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "p2p-client is already running (pid $(cat "$PIDFILE"))"
      exit 1
    fi
    nohup p2p-client mesh "$@" >"$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    echo "started p2p-client pid $(cat "$PIDFILE"), log: $LOG"
    ;;
  down)
    if [[ ! -f "$PIDFILE" ]]; then
      echo "no pid file at $PIDFILE"
      exit 1
    fi
    pid="$(cat "$PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "stopped p2p-client pid $pid"
    else
      echo "p2p-client pid $pid is not running"
    fi
    rm -f "$PIDFILE"
    ;;
  status)
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "running (pid $(cat "$PIDFILE"))"
    else
      echo "stopped"
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 {up|down|status} [mesh args...]" >&2
    exit 2
    ;;
esac
