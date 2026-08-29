set shell := ["bash", "-euo", "pipefail", "-c"]

check: typos tidy fmt lint vet test-total

typos:
  typos

test:
	go test -race ./...

test-e2e:
	./tests/e2e/run.sh

test-real:
	go run ./cmd/tailscale_real_e2e

test-total: test test-e2e

vet:
	go vet ./...

tidy:
	go mod tidy

fmt:
  golangci-lint fmt

lint:
  golangci-lint run
