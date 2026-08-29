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

mkdir -p "$state/headscale" "$state/run"
# Identity caches and Headscale's database intentionally survive between runs,
# but outcome and interaction markers must describe this run only.
rm -f \
	"$state/node-a.success" "$state/node-b.success" \
	"$state/node-a.addr" "$state/node-b.addr" \
	"$state/node-a.auth" "$state/node-b.auth" \
	"$state/registrar.success"

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
	headscale registrar node-a node-b

docker compose --ansi never --progress plain -f "$compose" run \
	--rm \
	--build \
	--no-deps \
	-T \
	verifier
