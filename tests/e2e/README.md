# End-to-end tests

## Headscale Docker cycle

The Compose scenario builds two independent client processes and Headscale
`v0.29.3`. Each process:

1. creates a wgo instance with a pre-existing deterministic node key;
2. starts `wgo-tailscale` through a mandatory native `gonnect.Network`;
3. writes the UI-neutral authentication URL to a shared test directory;
4. is approved by the registrar container with `headscale auth register`;
5. waits for both peers to be installed in wgo;
6. injects an IPv4 datagram into its in-memory test TUN and verifies a datagram
   from the other client emerges after WireGuard encryption/decryption.

Headscale's embedded DERP and STUN endpoints are enabled behind a test-only
self-signed TLS certificate. The clients disable direct DISCO discovery for
this scenario and assert that the encrypted packets used the embedded DERP
path, so the test covers the mandatory TLS fallback rather than merely setting
up its metadata.

Run from the repository root:

```sh
./tests/e2e/run.sh
```

The runner skips cleanly if Docker or Compose is unavailable and always removes
its containers and network. It clears per-run success/address/auth markers but
retains the gitignored identity caches and Headscale database, which exercises
cache reuse. Removing `.state` before the run forces a fresh registration
cycle.

## Optional hosted Tailscale service

The regular Go suite compiles this test but skips it unless
`real-service.json` exists:

```sh
cp tests/e2e/real-service.json.example tests/e2e/real-service.json
# Fill control URL, a dedicated wgo node private key, and optionally an auth key.
go test -v ./tests/e2e -run TestRealTailscaleService
```

With no auth key, the test prints:

```text
authenticate this node in your admin panel with this link: https://...
```

Authorize the node before the configured timeout. Machine/DISCO identity is
atomically persisted to the gitignored cache file, so repeat runs reuse the
registered device instead of adding one every time. The wgo node private key
remains exclusively in `real-service.json` and is never generated or
overwritten by the library.

The interactive real traffic check uses two real nodes and userspace VTuns:

```sh
cp tests/e2e/real-service.json.example tests/e2e/real-service.json
just test-real
```

The command can generate missing node private keys and save them back to the
gitignored config. It waits for both nodes, asks you to approve them when
needed, waits until the ACL permits TCP 80 in both directions, and then runs
HTTP both ways over the WireGuard VTun. It checks both the direct auto-discovery
path and the forced TLS DERP tunnel path.
