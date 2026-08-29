#!/bin/sh
set -eu

state_dir=${STATE_DIR:-/state}
socket=/tmp/tailscaled.sock
socks5=127.0.0.1:1055

cp /state/headscale/tls.crt /usr/local/share/ca-certificates/headscale.crt
update-ca-certificates >/dev/null

until [ -s "$state_dir/${NODE_NAME}.authkey" ]; do
  sleep 1
done
auth_key=$(head -n 1 "$state_dir/${NODE_NAME}.authkey")

tailscaled \
  --tun=userspace-networking \
  --socks5-server="$socks5" \
  --socket="$socket" \
  --state=mem: \
  --no-logs-no-support &
tailscaled_pid=$!
trap 'kill "$tailscaled_pid" 2>/dev/null || true; wait "$tailscaled_pid" 2>/dev/null || true' EXIT INT TERM

until [ -S "$socket" ]; do
  sleep 1
done

tailscale --socket="$socket" up \
  --login-server="$CONTROL_URL" \
  --auth-key="$auth_key" \
  --hostname="$NODE_NAME" \
  --accept-dns=false \
  --reset \
  --timeout=60s

tailscale --socket="$socket" ip -4 | head -n 1 >"$state_dir/${NODE_NAME}.addr"

until [ -s "$state_dir/${WGO_NODE}.addr" ]; do
  sleep 1
done
wgo_addr=$(head -n 1 "$state_dir/${WGO_NODE}.addr")

remaining=120
while [ "$remaining" -gt 0 ]; do
  body=$(ALL_PROXY="socks5://$socks5/" curl --fail --silent --show-error --max-time 10 "http://$wgo_addr/" || true)
  if [ "$body" = "hello from $WGO_NODE" ]; then
    printf 'ok\n' >"$state_dir/${NODE_NAME}.success"
    echo "$NODE_NAME: curl reached $WGO_NODE at $wgo_addr"
    wait "$tailscaled_pid"
    exit 0
  fi
  remaining=$((remaining - 1))
  sleep 1
done

echo "$NODE_NAME: curl could not reach $WGO_NODE at $wgo_addr" >&2
tailscale --socket="$socket" status >&2 || true
exit 1
