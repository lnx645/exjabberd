#!/usr/bin/env bash
# verify.sh — one-command full verification for exjabberd.
#
# Runs, in order:
#   0. mix deps.get (no-op when deps/ is populated; required fresh-clone)
#   1. mix compile (warnings are errors — see mix.exs)
#   2. mix test (ExUnit, 119 tests; wipes mnesia_data_test/ first)
#   3. single-node dev server + every single-node probe:
#      audit_raw_test.py, audit_slix_test.py, test_sm_carbons_csi.py,
#      test_mam_pubsub.py, test_mam_pubsub_slix.py, test_http_phase4.py,
#      test_jingle_phase5.py, test_stun_turn_phase5.py, test_mqtt_phase6.py,
#      test_longtail_phase10.py, test_subscriptions_phase11.py
#   4. test_auth_sqlite_phase8.py (boots its own server)
#   4b. test_starttls_anon_phase11.py (boots its own server)
#   4c. a fresh dev server for the probes that assume one on 5222:
#      test_muc_admin_phase12.py, test_pubsub_extra_phase13.py,
#      test_mix_phase14.py; then test_http_edges_phase15.py
#      (boots its own server)
#   5. two-node S2S (boot_s2s_nodes.sh + test_s2s.py + test_s2s_slix.py)
#   6. two-node cluster (boot_cluster_nodes.sh + test_cluster_phase7.py)
#
# Usage: ./verify.sh
#
# Requirements:
#   - Elixir ~> 1.19 / OTP 28 on PATH, or in $EXJABBERD_TOOLCHAIN
#     (default: $HOME/workspace/.toolchain — otp-28.1/bin +
#     elixir-1.19.7/bin). The toolchain is NOT in this repo.
#   - Python with slixmpp + paho-mqtt: $EXJABBERD_PY, or
#     $HOME/workspace/.venv-xmpp/bin/python when present, else python3.
#   - `sqlite3` CLI (for the Fase 8 probe) and `epmd`.
#   - No server already listening on 5222/5223/5225/5269/5270/5280/1883:
#     the script refuses to start when a port is taken instead of
#     killing something it does not own.
#
# Every step's output is saved under /tmp/exjabberd-verify-logs/.
# The script keeps going after a failed step so one run shows every
# failure, then exits non-zero. All servers it started are stopped
# on exit (trap), including after a failure or Ctrl-C.
#
# Known sandbox limitation, documented in the README: the sandbox
# blocks UDP sendto with EPERM, so the live UDP STUN/TURN checks in
# test_stun_turn_phase5.py skip loudly there and the same logic is
# covered in-process by ExUnit instead. A skip is NOT a failure —
# run that probe where UDP is allowed for the full UDP wire proof.
set -u
REPO="$(cd "$(dirname "$0")" && pwd)"
LOGDIR=/tmp/exjabberd-verify-logs
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"
DEV_PIDFILE=/tmp/exjabberd-verify.pid
DEV_LOG=/tmp/exjabberd-verify-server.log

# --- toolchain ---------------------------------------------------------
TOOLCHAIN="${EXJABBERD_TOOLCHAIN:-$HOME/workspace/.toolchain}"
if ! command -v elixir >/dev/null 2>&1; then
  if [ -x "$TOOLCHAIN/elixir-1.19.7/bin/elixir" ] && [ -x "$TOOLCHAIN/otp-28.1/bin/erl" ]; then
    export PATH="$TOOLCHAIN/otp-28.1/bin:$TOOLCHAIN/elixir-1.19.7/bin:$PATH"
  fi
fi
export ELIXIR_ERL_OPTIONS="+fnu"
if ! command -v elixir >/dev/null 2>&1 || ! command -v mix >/dev/null 2>&1; then
  echo "ERROR: elixir/mix not found. Put Elixir ~> 1.19 + OTP 28 on PATH"
  echo "or set EXJABBERD_TOOLCHAIN to a dir holding otp-28.1/bin + elixir-1.19.7/bin."
  exit 1
fi
if [ -n "${EXJABBERD_PY:-}" ]; then
  PY="$EXJABBERD_PY"
elif [ -x "$HOME/workspace/.venv-xmpp/bin/python" ]; then
  PY="$HOME/workspace/.venv-xmpp/bin/python"
else
  PY="python3"
fi
if ! "$PY" -c "import slixmpp, paho.mqtt.client" 2>/dev/null; then
  echo "ERROR: $PY has no slixmpp/paho-mqtt. Use the venv python"
  echo "(\$HOME/workspace/.venv-xmpp/bin/python) or set EXJABBERD_PY."
  exit 1
fi
command -v sqlite3 >/dev/null 2>&1 || { echo "ERROR: sqlite3 CLI not found (needed by test_auth_sqlite_phase8.py)."; exit 1; }
command -v epmd >/dev/null 2>&1 || { echo "ERROR: epmd not found."; exit 1; }
epmd -daemon 2>/dev/null || true
echo "toolchain: $(elixir --version | tr '\n' ' ')"
echo "python: $PY ($("$PY" -c "import slixmpp; print('slixmpp', slixmpp.__version__)"))"
echo "logs: $LOGDIR"

# --- helpers -----------------------------------------------------------
FAILURES=0
declare -a STEP_RESULTS=()

port_open() { (echo > /dev/tcp/127.0.0.1/"$1") 2>/dev/null; }

wait_port() {
  # $1 = port, $2 = want open (1) or closed (0), $3 = seconds
  local port="$1" want="$2" tries="${3:-90}"
  for _ in $(seq 1 "$tries"); do
    if port_open "$port"; then [ "$want" = 1 ] && return 0; else [ "$want" = 0 ] && return 0; fi
    sleep 1
  done
  return 1
}

record() {
  # $1 = name, $2 = 0 pass / 1 fail
  if [ "$2" = 0 ]; then STEP_RESULTS+=("PASS  $1"); else STEP_RESULTS+=("FAIL  $1"); FAILURES=$((FAILURES + 1)); fi
  echo "== $1: $([ "$2" = 0 ] && echo PASS || echo FAIL) (log: $LOGDIR/$1.log)"
}

# Run a command as a step; its output goes to $LOGDIR/<name>.log.
run_step() {
  # $1 = name, rest = command
  local name="$1"; shift
  echo "--- step: $name ---"
  if "$@" > "$LOGDIR/$name.log" 2>&1; then record "$name" 0; else record "$name" 1; tail -15 "$LOGDIR/$name.log"; fi
}

# Run a python probe as a step: fails on non-zero exit OR any [FAIL] line.
run_probe() {
  # $1 = name (probe file, run from $REPO)
  local name="$1"
  echo "--- probe: $name ---"
  (cd "$REPO" && "$PY" "$name" > "$LOGDIR/$name.log" 2>&1)
  local rc=$?
  local fails
  fails=$(grep -c "^\[FAIL\]" "$LOGDIR/$name.log" || true)
  grep -E "passed|SUMMARY" "$LOGDIR/$name.log" | tail -3
  if [ "$rc" != 0 ] || [ "$fails" != 0 ]; then
    echo "probe $name failed (exit $rc, $fails FAIL lines):"
    grep "^\[FAIL\]" "$LOGDIR/$name.log" | head -10
    record "$name" 1
  else
    record "$name" 0
  fi
}

stop_dev_server() {
  if [ -f "$DEV_PIDFILE" ]; then
    local pid
    pid="$(cat "$DEV_PIDFILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true  # SIGTERM: clean stop, Mnesia dumps its log
      for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$DEV_PIDFILE"
  fi
}

# Boot the single-node dev server and wait for port 5222.
# Returns non-zero when the server does not come up in time.
start_dev_server() {
  (cd "$REPO" && setsid nohup elixir --sname exjabberd -S mix run --no-halt > "$DEV_LOG" 2>&1 < /dev/null & disown -a)
  sleep 2
  pgrep -f -- "-sname exjabberd" | head -1 > "$DEV_PIDFILE"
  wait_port 5222 1 90
}

cleanup() {
  stop_dev_server
  "$REPO/boot_s2s_nodes.sh" stop >/dev/null 2>&1 || true
  "$REPO/boot_cluster_nodes.sh" stop >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# --- 0. preconditions ----------------------------------------------------
echo "--- preconditions: ports must be free ---"
for p in 5222 5223 5225 5269 5270 5280 5281 1883 1884; do
  if port_open "$p"; then echo "ERROR: port $p already in use — stop that server first."; exit 1; fi
done

# --- 0b. dependencies -----------------------------------------------------
# No-op when deps/ is already populated; required for a fresh clone,
# where deps/ and _build/ are gitignored and absent.
run_step "00-mix-deps-get" mix deps.get

# --- 1. compile ----------------------------------------------------------
run_step "01-mix-compile" mix compile

# --- 2. ExUnit -----------------------------------------------------------
# The suite boots the app on port 5222 itself; wipe the test Mnesia
# dir first so a stale schema from an earlier run cannot leak in.
rm -rf "$REPO/mnesia_data_test"
run_step "02-mix-test" env ELIXIR_ERL_OPTIONS="+fnu -sname exjabberd-test" mix test

# --- 3. single-node probes ----------------------------------------------
echo "--- step: 03-dev-server (single node on 5222) ---"
if start_dev_server; then
  record "03-dev-server" 0
else
  record "03-dev-server" 1; tail -30 "$DEV_LOG"; echo "dev server failed to start — see $DEV_LOG"
fi
if [ "$FAILURES" = 0 ]; then
  run_probe "audit_raw_test.py"
  run_probe "audit_slix_test.py"
  run_probe "test_sm_carbons_csi.py"
  run_probe "test_mam_pubsub.py"
  run_probe "test_mam_pubsub_slix.py"
  run_probe "test_http_phase4.py"
  run_probe "test_jingle_phase5.py"
  run_probe "test_stun_turn_phase5.py"
  run_probe "test_mqtt_phase6.py"
  run_probe "test_longtail_phase10.py"
  run_probe "test_subscriptions_phase11.py"
fi
stop_dev_server
wait_port 5222 0 30 || echo "WARNING: port 5222 still open after stopping the dev server"

# --- 4. SQLite auth probe (boots its own server) ------------------------
run_probe "test_auth_sqlite_phase8.py"

# --- 4a2. SQL (PostgreSQL) auth probe (boots its own server + PG) -------
run_probe "test_auth_sql_phase16.py"

# --- 4a3. JWT / OAuth / external auth probe (boots its own server) ------
run_probe "test_auth_backends_phase16.py"

# --- 4b. starttls_required + anonymous auth (boots its own server) ------
run_probe "test_starttls_anon_phase11.py"

# --- 4c. Fase 12-14 probes ------------------------------------------------
# These three probes ASSUME a dev server on 5222 (they create their
# users over Erlang RPC against the running node), so boot a fresh one
# for them; the step-03 server was stopped above on purpose (the Fase 8
# probe needs the port for its own server).
echo "--- step: 04c-dev-server (single node on 5222, for fase 12-14 probes) ---"
if start_dev_server; then
  record "04c-dev-server" 0
  run_probe "test_muc_admin_phase12.py"
  run_probe "test_pubsub_extra_phase13.py"
  run_probe "test_mix_phase14.py"
else
  record "04c-dev-server" 1; tail -30 "$DEV_LOG"; echo "dev server failed to start — see $DEV_LOG"
  record "test_muc_admin_phase12.py" 1
  record "test_pubsub_extra_phase13.py" 1
  record "test_mix_phase14.py" 1
fi
stop_dev_server
wait_port 5222 0 30 || echo "WARNING: port 5222 still open after stopping the dev server"

# --- 4d. HTTP edges (boots its own server) --------------------------------
run_probe "test_http_edges_phase15.py"

# --- 5. S2S (two nodes) ---------------------------------------------------
echo "--- step: 05-s2s-nodes ---"
if "$REPO/boot_s2s_nodes.sh" start > "$LOGDIR/05-s2s-nodes.log" 2>&1; then
  record "05-s2s-nodes" 0
  run_probe "test_s2s.py"
  run_probe "test_s2s_slix.py"
else
  record "05-s2s-nodes" 1; tail -20 "$LOGDIR/05-s2s-nodes.log"
fi
"$REPO/boot_s2s_nodes.sh" stop >/dev/null 2>&1 || true

# --- 6. cluster (two nodes) ----------------------------------------------
echo "--- step: 06-cluster-nodes ---"
if "$REPO/boot_cluster_nodes.sh" start > "$LOGDIR/06-cluster-nodes.log" 2>&1; then
  record "06-cluster-nodes" 0
  run_probe "test_cluster_phase7.py"
else
  record "06-cluster-nodes" 1; tail -20 "$LOGDIR/06-cluster-nodes.log"
fi
"$REPO/boot_cluster_nodes.sh" stop >/dev/null 2>&1 || true

# --- summary --------------------------------------------------------------
echo
echo "================ verify.sh summary ================"
printf '%s\n' "${STEP_RESULTS[@]}"
echo "---------------------------------------------------"
if [ "$FAILURES" = 0 ]; then
  echo "ALL GREEN: ${#STEP_RESULTS[@]} steps passed."
  exit 0
else
  echo "$FAILURES of ${#STEP_RESULTS[@]} steps FAILED. Logs in $LOGDIR."
  exit 1
fi
