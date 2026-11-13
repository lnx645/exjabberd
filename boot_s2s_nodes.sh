#!/usr/bin/env bash
# Boot two exjabberd nodes from this repo for the Fase 3 S2S probe
# (test_s2s.py + test_s2s_slix.py).
#
#   ./boot_s2s_nodes.sh start     # start A then B
#   ./boot_s2s_nodes.sh start-a   # only node A
#   ./boot_s2s_nodes.sh start-b   # only node B
#   ./boot_s2s_nodes.sh stop      # stop both
#   ./boot_s2s_nodes.sh stop-a | stop-b
#   ./boot_s2s_nodes.sh restart   # stop both, start both
#   ./boot_s2s_nodes.sh status
#
# Topology (must match test_s2s.py):
#   node A: exjabberd-a, domain a.localhost, C2S 5222, TLS 5224,
#           S2S 5269, HTTP 5280, MQTT 1883, TURN 5478
#           dialback secret test-secret-node-a-7f3a9c
#           overrides b.localhost -> 127.0.0.1:5270,
#                     ghost.localhost -> 127.0.0.1:59999 (closed port,
#                     for the unreachable-domain check)
#   node B: exjabberd-b, domain b.localhost, C2S 5223, TLS 5226,
#           S2S 5270, HTTP 5281, MQTT 1884, TURN 5479
#           dialback secret test-secret-node-b-41bd27
#           overrides a.localhost -> 127.0.0.1:5269
#
# The TLS ports move because B's plain C2S is 5223, which is A's
# direct-TLS port in the default config — the two nodes cannot both
# listen on 5223. The dialback secrets are TEST secrets only; they
# must match the values test_s2s.py computes keys with, so they are
# intentionally fixed here, never used in production.
#
# Working copies live in /tmp/exjabberd-s2s-a|b (fresh copy of this
# repo per start, excluding .git and mnesia dirs); logs in
# /tmp/s2s-a.log / /tmp/s2s-b.log, pids in /tmp/exjabberd-s2s-a.pid /
# /tmp/exjabberd-s2s-b.pid. Unlike the cluster nodes these two do NOT
# share a Mnesia schema and do NOT join a cluster — they are two
# independent servers that federate over S2S only.
set -u
REPO="$(cd "$(dirname "$0")" && pwd)"
HOST="$(hostname)"
export ELIXIR_ERL_OPTIONS="+fnu"
export PATH="$HOME/workspace/.toolchain/otp-28.1/bin:$HOME/workspace/.toolchain/elixir-1.19.7/bin:$PATH"

A_DIR=/tmp/exjabberd-s2s-a
B_DIR=/tmp/exjabberd-s2s-b
A_LOG=/tmp/s2s-a.log
B_LOG=/tmp/s2s-b.log

patch_yml() {
  # $1 = dir, $2 = a|b
  local dir="$1" side="$2"
  python3 - "$dir/exjabberd.yml" "$side" <<'PYEOF'
import sys
path, side = sys.argv[1], sys.argv[2]
s = open(path).read()
if side == "a":
    domain, secret = "a.localhost", "test-secret-node-a-7f3a9c"
    # TLS C2S moves 5223 -> 5224 (B's plain C2S needs 5223).
    s = s.replace("port: 5223", "port: 5224", 1)
    overrides = (
        "s2s_host_overrides:\n"
        "  b.localhost:\n"
        "    host: 127.0.0.1\n"
        "    port: 5270\n"
        "  ghost.localhost:\n"
        "    host: 127.0.0.1\n"
        "    port: 59999\n"
    )
else:
    domain, secret = "b.localhost", "test-secret-node-b-41bd27"
    # TLS C2S first (5223 -> 5226), then plain C2S (5222 -> 5223) —
    # order matters, as in boot_cluster_nodes.sh.
    s = s.replace("port: 5223", "port: 5226", 1)
    s = s.replace("port: 5222", "port: 5223", 1)
    s = s.replace("port: 5269", "port: 5270", 1)
    s = s.replace("port: 5280", "port: 5281", 1)
    s = s.replace("port: 1883", "port: 1884", 1)
    s = s.replace("port: 5478", "port: 5479", 1)
    overrides = (
        "s2s_host_overrides:\n"
        "  a.localhost:\n"
        "    host: 127.0.0.1\n"
        "    port: 5269\n"
    )
s = s.replace("  - localhost", "  - %s" % domain, 1)
s = s.replace(
    '# s2s_dialback_secret: "change-me-to-a-long-random-secret"',
    's2s_dialback_secret: "%s"' % secret, 1)
# Fase 19: SASL EXTERNAL trust = pinning; the bundle itself is
# assembled by the probe once both nodes have generated their
# (SAN-carrying) certificates.
s = s.replace(
    '# s2s_pinned_certs: "priv/ssl/pinned-peers.pem"',
    's2s_pinned_certs: "priv/ssl/pinned.pem"', 1)
commented = (
    "# s2s_host_overrides:\n"
    "#   example.com:\n"
    "#     host: 127.0.0.1\n"
    "#     port: 5269\n"
)
assert commented in s, "commented s2s_host_overrides block not found in exjabberd.yml"
s = s.replace(commented, overrides, 1)
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
  # Drop any stale dev certificate from the repo copy: the node
  # must generate its own, whose SANs name ITS domain (Fase 19 —
  # SASL EXTERNAL identity checks rely on that).
  rm -f "$dest/priv/ssl/cert.pem" "$dest/priv/ssl/key.pem"
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
  local dir log pidfile node port
  if [ "$side" = "a" ]; then
    dir="$A_DIR"; log="$A_LOG"; pidfile=/tmp/exjabberd-s2s-a.pid; node=exjabberd-a; port=5222
  else
    dir="$B_DIR"; log="$B_LOG"; pidfile=/tmp/exjabberd-s2s-b.pid; node=exjabberd-b; port=5223
  fi
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "node $node already running (pid $(cat "$pidfile"))"
    return 0
  fi
  epmd -daemon 2>/dev/null || true
  prepare_copy "$dir"
  patch_yml "$dir" "$side"
  echo "starting $node (domain ${side}.localhost, C2S $port) from $dir, log $log"
  # Launch in THIS shell (no subshell) and disown: a background job
  # left in the shell's job table makes bash wait for it at exit
  # (do_wait) and the caller hangs. setsid detaches the session;
  # disown drops it from the job table. The beam pid is found
  # afterwards via pgrep (setsid may fork, so $! can be wrong).
  cd "$dir" || return 1
  setsid nohup elixir --sname "$node" -S mix run --no-halt > "$log" 2>&1 < /dev/null &
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
  if [ "$1" = "a" ]; then pidfile=/tmp/exjabberd-s2s-a.pid; node=exjabberd-a;
  else pidfile=/tmp/exjabberd-s2s-b.pid; node=exjabberd-b; fi
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
  for f in /tmp/exjabberd-s2s-a.pid /tmp/exjabberd-s2s-b.pid; do
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
