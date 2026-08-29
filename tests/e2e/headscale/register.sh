#!/bin/sh
set -eu

until headscale --config /etc/headscale/config.yaml users list >/dev/null 2>&1; do
  sleep 1
done
headscale --config /etc/headscale/config.yaml users create e2e >/dev/null 2>&1 || true

for node in ${PREAUTHKEY_NODES:-}; do
  [ -s "/state/${node}.authkey" ] && continue
  key=$(headscale --config /etc/headscale/config.yaml preauthkeys create --user 1 --reusable --expiration 2h)
  printf '%s\n' "$key" >"/state/${node}.authkey"
done

nodes=${TEST_NODES:-"node-a node-b"}
registered=" "
# The verifier is the only service whose successful exit should end the
# Compose run. Keep this process alive and register auth files as they appear.
while :; do
  for node in $nodes; do
    case "$registered" in
      *" $node "*) continue ;;
    esac
    [ -s "/state/${node}.auth" ] || continue
    auth_url=$(head -n 1 "/state/${node}.auth")
    auth_id=$(printf '%s' "$auth_url" | sed -e 's:/*$::' -e 's:.*/::')
    if headscale --config /etc/headscale/config.yaml auth register --user e2e --auth-id "$auth_id"; then
      registered="${registered}${node} "
      printf 'ok\n' >/state/registrar.success
    fi
  done
  sleep 1
done
