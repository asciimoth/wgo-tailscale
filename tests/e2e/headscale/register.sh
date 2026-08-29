#!/bin/sh
set -eu

until headscale --config /etc/headscale/config.yaml users list >/dev/null 2>&1; do
  sleep 1
done
headscale --config /etc/headscale/config.yaml users create e2e >/dev/null 2>&1 || true

for node in node-a node-b; do
  until [ -s "/state/${node}.auth" ]; do
    sleep 1
  done
  auth_url=$(head -n 1 "/state/${node}.auth")
  auth_id=$(printf '%s' "$auth_url" | sed -e 's:/*$::' -e 's:.*/::')
  until headscale --config /etc/headscale/config.yaml auth register --user e2e --auth-id "$auth_id"; do
    sleep 1
  done
done

printf 'ok\n' >/state/registrar.success

# The verifier is the only service whose successful exit should end the
# Compose run. Stay alive after registration so --abort-on-container-exit does
# not tear down clients while they are exchanging tunnel traffic.
while :; do
  sleep 3600
done
