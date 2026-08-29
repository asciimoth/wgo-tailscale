#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
compose="$root/tests/e2e/docker-compose.yml"
state="$root/tests/e2e/.state"

# Keep Docker Compose output non-interactive so test logs stay visible.
export COMPOSE_MENU=false

skip() {
	printf 'SKIP: %s\n' "$1"
	exit 0
}

command -v docker >/dev/null 2>&1 || skip "docker is not installed"
docker compose version >/dev/null 2>&1 || skip "docker compose is unavailable"
docker info >/dev/null 2>&1 || skip "docker daemon is unavailable or permission was denied"

mkdir -p "$state/headscale" "$state/headscale-alpha" "$state/headscale-beta" "$state/run" "$state/run-alpha" "$state/run-beta"
# Identity caches and Headscale's database intentionally survive between runs,
# but outcome and interaction markers must describe this run only.
rm -f \
	"$state/derp-a.success" "$state/derp-b.success" \
	"$state/stun-a.success" "$state/stun-b.success" \
	"$state/local-a.success" "$state/local-b.success" \
	"$state/mixed-wgo.success" "$state/mixed-official.success" \
	"$state/multi-a.success" "$state/multi-b.success" "$state/multi-c.success" \
	"$state/derp-a.addr" "$state/derp-b.addr" \
	"$state/stun-a.addr" "$state/stun-b.addr" \
	"$state/local-a.addr" "$state/local-b.addr" \
	"$state/mixed-wgo.addr" "$state/mixed-official.addr" \
	"$state/multi-a-alpha.addr" "$state/multi-c-alpha.addr" \
	"$state/multi-b-beta.addr" "$state/multi-c-beta.addr" \
	"$state/derp-a.auth" "$state/derp-b.auth" \
	"$state/stun-a.auth" "$state/stun-b.auth" \
	"$state/local-a.auth" "$state/local-b.auth" \
	"$state/mixed-wgo.auth" "$state/mixed-official.authkey" \
	"$state/multi-a-alpha.auth" "$state/multi-c-alpha.auth" \
	"$state/multi-b-beta.auth" "$state/multi-c-beta.auth" \
	"$state/registrar.success" "$state/registrar-alpha.success" "$state/registrar-beta.success"

cleanup() {
	docker compose --ansi never --progress plain -f "$compose" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# Run one-shot containers separately from the long-lived services. Attached
# compose shutdown output can obscure test logs in non-interactive runs.
docker compose --ansi never --progress plain -f "$compose" run --rm --build certgen

docker compose --ansi never --progress plain -f "$compose" up \
	--build \
	--detach \
	headscale headscale-alpha headscale-beta \
	registrar registrar-alpha registrar-beta \
	derp-a derp-b stun-a stun-b local-a local-b mixed-wgo mixed-official \
	multi-a multi-b multi-c

docker compose --ansi never --progress plain -f "$compose" run \
	--rm \
	--build \
	--no-deps \
	-T \
	verifier
