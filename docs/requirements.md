# Basic-scope conformance

This matrix maps the library's requested scope to its public surface and test
coverage. “Implemented” means the behavior is present in production code; it
does not mean that the host application has installed any operating-system
configuration.

| Requirement | Status | Public surface / implementation | Main verification |
|---|---|---|---|
| Mandatory application network | Implemented | `New(gonnect.Network, ...)` rejects nil; control, lookup, STUN, DISCO, DERP, HTTPS netcheck, and direct peer traffic use that instance unless `UseDefaultTransportForDirectPeers` puts direct peer endpoints on wgo's default transport | production-code direct-network audit; tailnet integration tests |
| Existing wgo node key | Implemented | `Start` reads `WGODevice.PrivateKey`; no key setter is in `WGODevice`; control self-key mismatch and cache identity changes fail | `TestStartUsesExistingWGOKey`, `TestControlSelfKeyMustMatchExistingWGOIdentity` |
| Control authentication and registration | Implemented | `/key`, ts2021 Noise IK, `/machine/register`, auth keys, cancellable authorization follow-ups | Noise tests; Headscale cycle; optional hosted-service test |
| Streaming control updates | Implemented | framed `/machine/map`, keepalives, full maps, deltas, patches, removals, session resume metadata, liveness pings | reducer tests; Headscale cycle |
| Shared wgo device | Implemented | named transport plus complete `UpsertPeer` specs and ownership-checked `DeletePeer`; no bulk replacement | multi-controller/conflict/takeover tests |
| Peer discovery | Implemented | local endpoint refresh, expiring STUN endpoints, authenticated DISCO Ping/Pong and DERP CallMeMaybe, control candidates | DISCO, STUN, bind reopen, and netcheck tests |
| UDP-blocked tunnel | Implemented | standard DERP datagrams over HTTPS/TLS, including DERP-only bind startup when UDP sockets are unavailable; direct-candidate fallback if DERP itself fails | DERP-only bind/framing tests; Docker cycle forces and asserts DERP traffic |
| MagicDNS without system integration | Implemented | immutable `DNSView`; live in-memory `LookupNetIP`, `LookupHost`, and `LookupAddr` | DNS lookup/revision/event tests |
| Desired network provider | Implemented | `DesiredNetworkConfiguration` returns interface name, up/down, MTU, addresses, routes, and DNS; never applies them | network and shutdown tests |
| Read-only ACL | Implemented | flattened and named immutable rule views plus optional `ACLAllows` query; no enforcement or administration | ACL matching and deep-copy tests |
| Rich changing views | Implemented | coherent `Snapshot`, focused getters, typed node/client/DERP/path data, raw node JSON, monotonic revisions, coalescable subscriptions | view deep-copy and event-order tests |
| UI-neutral user interaction | Implemented | `Interaction`, `EventInteraction`, `ResumeInteraction`; registration polling remains cancellable | interaction test; Headscale registrar; optional hosted-service stdout flow |
| Optional peer confirmation | Implemented | awaiting peers remain visible but outside both wgo and the tailnet bind until `ConfirmPeer`; revocation withdraws them | confirmation/network/cache tests |
| Optional AmneziaWG | Implemented | validated profile copied to every peer owned by this client | obfuscation ownership test |
| Optional persistence | Implemented | versioned callback blob for machine/DISCO identity, node-key fingerprint, backend ID, and confirmations; writes serialized | cache identity/round-trip/concurrency tests |
| Headscale E2E | Implemented | two wgo processes, registration links, mock approval, peer setup, bidirectional encrypted traffic through forced DERP | `tests/e2e/run.sh` |
| Hosted-service opt-in | Implemented | gitignored JSON inputs and cache, automatic skip, printed authorization URL | `TestRealTailscaleService` |

## Deliberate limits

The client advertises capability version 119 even though the pinned reference
source is at 145. Version 120 introduced peer-hosted UDP relay behavior. Not
advertising it prevents other nodes and control from assuming support for the
new allocation messages; direct DISCO and standard DERP provide the requested
basic discovery and blocked-UDP path.

Router port mapping, ICMP netcheck, map compression, tailnet-lock signing/key
rotation, stateful ACL enforcement, and advanced application features are not
implemented. The first three are optional connectivity/efficiency extensions;
the remaining items are outside this controller's stated ownership or basic
feature boundary.
