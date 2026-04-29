#!/usr/bin/env bash
# Bring up a local Linux kanonproxy demo end-to-end:
#   1. Create the kanon TUN device
#   2. Start the proxy server (UDP :8080)
#   3. Start the proxy client (tunnels TUN traffic to 127.0.0.1:8080)
#   4. Add a host route for one target IP through the kanon device
#   5. curl that target IP through the proxy
#
# Usage: bash client/scripts/demo.sh [target-ip]
#   target-ip defaults to 1.1.1.1 (Cloudflare). Whatever you pick must
#   speak HTTP on port 80 since this demo issues a plain HTTP curl.
#
# Run client/scripts/cleanup.sh afterwards to tear everything down.

set -euo pipefail

TARGET="${1:-1.1.1.1}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/build/demo-logs"
mkdir -p "$LOG_DIR"

cd "$REPO_ROOT"

echo "[1/5] Creating kanon TUN device (sudo will be required)..."
bash client/scripts/tuntap.sh "$USER"

echo "[2/5] Starting proxy server on UDP :8080 (logs: $LOG_DIR/server.log)..."
./gradlew --no-daemon -q :server:run --args="8080" \
    > "$LOG_DIR/server.log" 2>&1 &
SERVER_PID=$!
echo "      server pid=$SERVER_PID"

echo "[3/5] Waiting for server to start listening..."
for i in $(seq 1 30); do
    if ss -lun | grep -q ":8080"; then
        echo "      server is listening"
        break
    fi
    sleep 1
done

echo "[4/5] Starting proxy client (logs: $LOG_DIR/client.log)..."
./gradlew --no-daemon -q :client:run --args="127.0.0.1 8080" \
    > "$LOG_DIR/client.log" 2>&1 &
CLIENT_PID=$!
echo "      client pid=$CLIENT_PID"
sleep 3

echo "[5/5] Routing $TARGET through kanon and issuing curl..."
sudo ip route add "$TARGET" dev kanon || true
echo "---- curl -v http://$TARGET/ ----"
curl -v --max-time 15 "http://$TARGET/" || true
echo "---- end curl ----"

cat <<EOF

Demo finished. Server (pid=$SERVER_PID) and client (pid=$CLIENT_PID) are still
running so you can attach Wireshark:
    wireshark -k -i TCP@127.0.0.1:19000   # client-side dumper
    wireshark -k -i TCP@127.0.0.1:19001   # server-side dumper

To tear everything down:
    sudo ip route del $TARGET dev kanon 2>/dev/null || true
    bash client/scripts/cleanup.sh

Logs: $LOG_DIR/{server,client}.log
EOF
