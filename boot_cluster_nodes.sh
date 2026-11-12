#!/usr/bin/env bash
# Boot two exjabberd nodes from this repo for the Fase 7 cluster probe.
#
#   ./boot_cluster_nodes.sh start     # start A then B (B joins A's Mnesia)
#   ./boot_cluster_nodes.sh start-a   # only node A
#   ./boot_cluster_nodes.sh start-b   # only node B (joins A)
#   ./boot_cluster_nodes.sh stop      # stop both
#   ./boot_cluster_nodes.sh stop-a | stop-b
#   ./boot_cluster_nodes.sh restart   # stop both, start both
#   ./boot_cluster_nodes.sh status
#
# Topology:
#   node A: exjabberd-a, C2S 5222, S2S 5269, HTTP 5280, MQTT 1883, TURN 5478
#   node B: exjabberd-b, C2S 5225, S2S 5270, HTTP 5281, MQTT 1884, TURN 5479
#   (B's C2S must NOT be 5223 — that is A's direct-TLS port.)
#   same domain (localhost) on both — cross-node routing is via the
#   Erlang distribution connection, NOT S2S.
#
# Node B boots with EXJABBERD_CLUSTER_JOIN=exjabberd-a@HOST so it
# copies A's Mnesia schema (accounts, roster, offline, MAM, PubSub).
# Both nodes share the cookie from EXJABBERD_ERLANG_COOKIE
# (default: test-cluster-cookie-phase7). net_ticktime is 10 s so a
# dead node is noticed in ~10 s instead of the 60 s default.
#
# Working copies live in /tmp/exjabberd-cluster-a|b (fresh copy of
# this repo per start, excluding .git and mnesia dirs); logs in
# /tmp/cluster-a.log / /tmp/cluster-b.log, pids in
# /tmp/exjabberd-a.pid / /tmp/exjabberd-b.pid.
set -u
REPO="$(cd "$(dirname "$0")" && pwd)"
HOST="$(hostname)"
COOKIE="${EXJABBERD_ERLANG_COOKIE:-test-cluster-cookie-phase7}"
export EXJABBERD_ERLANG_COOKIE="$COOKIE"
export ELIXIR_ERL_OPTIONS="+fnu -kernel net_ticktime 10"
export PATH="$HOME/workspace/.toolchain/otp-28.1/bin:$HOME/workspace/.toolchain/elixir-1.19.7/bin:$PATH"

A_DIR=/tmp/exjabberd-cluster-a
B_DIR=/tmp/exjabberd-cluster-b
A_LOG=/tmp/cluster-a.log
B_LOG=/tmp/cluster-b.log

patch_yml() {
  # $1 = dir, $2 = a|b
  local dir="$1" side="$2"
  python3 - "$dir/exjabberd.yml" "$side" "$HOST" <<'PYEOF'
import sys
path, side, host = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if side == "b":
    # TLS C2S first (5223), then plain C2S (5222) — order matters.
    # B's pair moves to 5226/5225: 5223 is A's direct-TLS port.
    s = s.replace("port: 5223", "port: 5226", 1)
    s = s.replace("port: 5222", "port: 5225", 1)
    s = s.replace("port: 5269", "port: 5270", 1)
    s = s.replace("port: 5280", "port: 5281", 1)
    s = s.replace("port: 1883", "port: 1884", 1)
    s = s.replace("port: 5478", "port: 5479", 1)
    peer = "exjabberd-a@%s" % host
else:
    peer = "exjabberd-b@%s" % host
s = s.replace("  nodes: []", '  nodes: ["%s"]' % peer, 1)
open(path, "w").write(s)
PYEOF
}

prepare_copy() {
  # $1 = dest dir
  local dest="$1"
  rm -rf "$dest"
  mkdir -p "$dest"
  cp -a "$REPO/." "$dest/"
  rm -rf "$dest/.git" "$dest/mnesia_data" "$dest/mnesia_data_test" "$dest/mnesia_data_test"*
  rm -f "$dest"/*.log
}

wait_port() {
  # $1 = port, $2 = seconds
  local port="$1" tries="${2:-60}"
  for _ in $(seq 1 "$tries"); do
    (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null && return 0
    sleep 1
  done
  return 1
}

start_node() {
  # $1 = a|b
  local side="$1"
  local dir log pidfile node port join_env
  if [ "$side" = "a" ]; then
    dir="$A_DIR"; log="$A_LOG"; pidfile=/tmp/exjabberd-a.pid; node=exjabberd-a; port=5222
  else
    dir="$B_DIR"; log="$B_LOG"; pidfile=/tmp/exjabberd-b.pid; node=exjabberd-b; port=5225
  fi
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "node $node already running (pid $(cat "$pidfile"))"
    return 0
  fi
  epmd -daemon 2>/dev/null || true
  prepare_copy "$dir"
  patch_yml "$dir" "$side"
  echo "starting $node (C2S $port) from $dir, log $log"
  # Launch in THIS shell (no subshell) and disown: a background job
  # left in the shell's job table makes bash wait for it at exit
  # (do_wait) and the caller hangs. setsid detaches the session;
  # disown drops it from the job table. The beam pid is found
  # afterwards via pgrep (setsid may fork, so $! can be wrong).
  cd "$dir" || return 1
  if [ "$side" = "b" ]; then
    EXJABBERD_CLUSTER_JOIN="exjabberd-a@$HOST" setsid nohup elixir --sname "$node" -S mix run --no-halt > "$log" 2>&1 < /dev/null &
  else
    setsid nohup elixir --sname "$node" -S mix run --no-halt > "$log" 2>&1 < /dev/null &
  fi
  disown -a
  cd "$REPO" || true
  sleep 2
  pgrep -f -- "-sname $node" | head -1 > "$pidfile"
  if wait_port "$port" 90; then
    echo "node $node up (C2S $port, pid $(cat "$pidfile"))"
  else
    echo "node $node did NOT open C2S $port in 90s — see $log"
    tail -30 "$log"
    return 1
  fi
}

stop_node() {
  # $1 = a|b
  local pidfile node
  if [ "$1" = "a" ]; then pidfile=/tmp/exjabberd-a.pid; node=exjabberd-a;
  else pidfile=/tmp/exjabberd-b.pid; node=exjabberd-b; fi
  if [ -f "$pidfile" ]; then
    local pid
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      echo "stopping $node (pid $pid)"
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$pidfile"
  else
    echo "node $node not running (no pid file)"
  fi
}

status() {
  epmd -names 2>&1 | head -10
  for f in /tmp/exjabberd-a.pid /tmp/exjabberd-b.pid; do
    if [ -f "$f" ]; then
      local pid
      pid="$(cat "$f")"
      if kill -0 "$pid" 2>/dev/null; then echo "$f: running pid $pid"; else echo "$f: stale pid $pid"; fi
    else echo "$f: not running"; fi
  done
  for p in 5222 5223 5269 5270 5280 5281; do
    (echo > /dev/tcp/127.0.0.1/"$p") 2>/dev/null && echo "port $p: open" || echo "port $p: closed"
  done
}

case "${1:-status}" in
  start) start_node a && start_node b ;;
  start-a) start_node a ;;
  start-b) start_node b ;;
  stop) stop_node a; stop_node b ;;
  stop-a) stop_node a ;;
  stop-b) stop_node b ;;
  restart) stop_node a; stop_node b; start_node a && start_node b ;;
  status) status ;;
  *) echo "usage: $0 {start|start-a|start-b|stop|stop-a|stop-b|restart|status}"; exit 1 ;;
esac
