set shell := ["bash", "-euo", "pipefail", "-c"]

check: typos tidy fmt lint vet test-total fuzzing

typos:
  typos

test:
	go test -race ./...

test-e2e:
	./tests/e2e/run.sh

test-real:
	go run ./cmd/tailscale_real_e2e

test-total: test test-e2e

# Fuzz all untrusted-input boundaries for one shared wall-clock interval.
fuzzing:
	#!/usr/bin/env bash
	if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
	  echo "Skipping fuzzing in GitHub Actions."
	  exit 0
	fi
	fuzz_time="${FUZZ_TIME:-1m}"
	pids=()
	cleanup() {
	  for pid in "${pids[@]:-}"; do
	    kill "$pid" 2>/dev/null || true
	  done
	}
	trap cleanup EXIT INT TERM
	for package in . ./internal/controlproto ./internal/tailnet; do
	  go test -run='^$' -fuzz='^FuzzUntrustedInput$' -fuzztime="$fuzz_time" "$package" &
	  pids+=("$!")
	done
	status=0
	for pid in "${pids[@]}"; do
	  if ! wait "$pid"; then
	    status=1
	  fi
	done
	exit "$status"

fuzz: fuzzing

vet:
	go vet ./...

tidy:
	go mod tidy

fmt:
  golangci-lint fmt

lint:
  golangci-lint run
