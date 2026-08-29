# End-to-end test docket

Run the Docker docket from the repository root:

```sh
./tests/e2e/run.sh
```

The runner skips if Docker or Compose is not available. It removes its
containers and network after the run. It clears per-run success, address, and
auth markers. It keeps the gitignored identity caches and Headscale database to
test cache reuse. Remove `tests/e2e/.state` to force a clean registration
cycle.

The Docker docket uses Headscale `v0.29.3` with embedded DERP and STUN behind a
test-only self-signed TLS certificate. The registrar container approves wgo
nodes with `headscale auth register` and creates preauth keys for official
Tailscale containers.

## TLS DERP tunnel

Test setup:

- Services: `derp-a`, `derp-b`, Headscale, registrar, verifier.
- Both nodes use deterministic wgo node keys and native `gonnect.Network`.
- `DISABLE_DISCOVERY=1` prevents local, STUN, and DISCO endpoints.
- DERP stays enabled and uses Headscale's HTTPS/TLS DERP endpoint.

Testing sequence:

1. Each node starts `wgo-tailscale` and writes its auth URL to shared state.
2. The registrar approves both auth URLs in Headscale.
3. Each node waits until the intended peer is installed in wgo.
4. Each node injects one IPv4 UDP packet into its in-memory TUN.
5. Each node waits for the peer packet to emerge after WireGuard processing.
6. Each node checks that the peer path is `derp-tls`.

Expected result:

- Both nodes receive the expected peer payload.
- Both nodes report `derp-tls`, which proves encrypted WireGuard packets moved
  through the TLS DERP tunnel when UDP discovery was disabled.

## STUN and NAT traversal

Test setup:

- Services: `stun-a`, `stun-b`, Headscale, registrar, verifier.
- Both nodes use deterministic wgo node keys and native `gonnect.Network`.
- Discovery is enabled.
- `DISABLE_DERP=1` prevents DERP from carrying test traffic.
- The assertion requires the Headscale DERP map to advertise a STUN endpoint.

Testing sequence:

1. Each node starts and is approved by the registrar.
2. Each node receives the Headscale DERP map with the embedded STUN endpoint.
3. Each node checks that the DERP map includes a STUN port.
4. Each node waits until the intended peer is installed in wgo.
5. Each node exchanges one encrypted IPv4 UDP payload through the in-memory TUN.
6. Each node checks that the peer path is `direct-udp`.

Expected result:

- The control map contains a usable STUN endpoint for discovery and netcheck.
- Bidirectional encrypted traffic succeeds with `direct-udp` while DERP is
  disabled.
- This proves the Docker fixture receives STUN discovery metadata and can use a
  direct UDP path with DERP disabled. On Docker backends where the mapped
  address equals the bridge-local endpoint, this test does not require a
  distinct public endpoint.

## Local peer discovery

Test setup:

- Services: `local-a`, `local-b`, Headscale, registrar, verifier.
- Both nodes use deterministic wgo node keys and native `gonnect.Network`.
- Discovery is enabled.
- `DISABLE_DERP=1` prevents fallback through DERP.
- Each node must publish at least one local endpoint with source `local`.

Testing sequence:

1. Each node starts and is approved by the registrar.
2. Each node opens its UDP bind and discovers local interface endpoints.
3. Each node publishes those local endpoints to Headscale.
4. Each node waits until the intended peer is installed in wgo.
5. Each node exchanges one encrypted IPv4 UDP payload through the in-memory TUN.
6. Each node checks that the peer path is `direct-udp`.

Expected result:

- Both nodes publish a `local` endpoint.
- Both nodes receive the expected peer payload.
- Both nodes report `direct-udp`, which proves local peer discovery can create a
  usable direct path without DERP.

## Official client curl

Test setup:

- Services: `mixed-wgo`, `mixed-official`, Headscale, registrar, verifier.
- `mixed-wgo` uses `wgo-tailscale`, a userspace VTun, and an in-memory HTTP
  server on TCP `80`.
- `mixed-official` uses the official `tailscale` and `tailscaled` binaries in
  userspace networking mode with a SOCKS5 proxy for `curl`.
- The Headscale policy allows TCP `80` from the official client to the wgo
  node.

Testing sequence:

1. `mixed-wgo` starts, writes its auth URL, and is approved by the registrar.
2. The registrar creates a Headscale preauth key for `mixed-official`.
3. `mixed-official` trusts the test Headscale certificate and logs in with the
   preauth key.
4. `mixed-wgo` waits until the official peer is installed in wgo and the ACL
   view allows TCP `80`.
5. `mixed-official` runs `curl` through the Tailscale SOCKS5 proxy to the
   HTTP server on `mixed-wgo`.

Expected result:

- `curl` in the official Tailscale client container receives
  `hello from mixed-wgo`.

## Multi-Headscale shared device

Test setup:

- Services: `headscale-alpha`, `headscale-beta`, `multi-a`, `multi-b`,
  `multi-c`, two registrars, and verifier.
- `headscale-alpha` uses `100.64.0.0/16`; `headscale-beta` uses
  `100.65.0.0/16`.
- `multi-a` connects only to `headscale-alpha`.
- `multi-b` connects only to `headscale-beta`.
- `multi-c` starts two `wgo-tailscale` clients against the same wgo device.
  Each client uses its own cache file and `TransportID`.
- DERP is disabled so each edge must use a direct UDP path.

Testing sequence:

1. Each `wgo-tailscale` client writes one auth URL for its Headscale server.
2. The matching registrar approves each auth URL.
3. `multi-c` waits until both control servers are running and both peers are
   installed in the same wgo device.
4. `multi-a` exchanges one encrypted IPv4 UDP payload with `multi-c` through
   `headscale-alpha`.
5. `multi-b` exchanges one encrypted IPv4 UDP payload with `multi-c` through
   `headscale-beta`.
6. Each node checks that its peer path is `direct-udp`.

Expected result:

- `multi-c` receives traffic from both independent Headscale tailnets through
  one wgo device.
- `multi-a` and `multi-b` each receive the expected `multi-c` payload.
- The two controllers keep separate transports and do not remove or overwrite
  each other's peers.

## Hosted service registration

This Go test compiles with the regular suite but skips unless
`tests/e2e/real-service.json` exists:

```sh
cp tests/e2e/real-service.json.example tests/e2e/real-service.json
# Fill control URL, hostname, node private key, and optionally an auth key.
go test -v ./tests/e2e -run TestRealTailscaleService
```

Test setup:

- One real control service account or Headscale service.
- One wgo node private key in `real-service.json`.
- One gitignored cache file for machine and DISCO identity reuse.

Testing sequence:

1. The test creates a wgo device and `wgo-tailscale` client.
2. The client starts with the configured control URL and TLS config.
3. If the control service requires approval, the test prints the auth URL.
4. The test waits until control returns a running self node.

Expected result:

- The node reaches `StateRunning`.
- Repeat runs reuse the cache instead of creating a new machine identity.

## Hosted two-node real traffic

Run the interactive real traffic check with:

```sh
cp tests/e2e/real-service.json.example tests/e2e/real-service.json
just test-real
```

Test setup:

- Two real nodes from `real-service.json`.
- Userspace VTuns from `gonnect-netstack`.
- ACLs that allow TCP `80` in both directions between the two node addresses.

Testing sequence:

1. The command starts both nodes.
2. If needed, it prints auth URLs and waits for approval.
3. It waits until both nodes are running and each peer is installed in wgo.
4. It waits until ACL checks allow TCP `80` in both directions.
5. It attaches userspace VTuns and starts HTTP servers on both node addresses.
6. It sends HTTP requests both ways with discovery enabled.
7. It repeats the HTTP check with discovery disabled.

Expected result:

- HTTP succeeds in both directions in direct discovery mode.
- HTTP succeeds in both directions in forced TLS DERP mode.
- The observed peer paths match `direct-udp` and `derp-tls` respectively.
