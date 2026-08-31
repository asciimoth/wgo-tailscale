# wgo-tailscale

`wgo-tailscale` connects an existing [`wgo`](https://github.com/asciimoth/wgo)
device to a [Tailscale](https://tailscale.com/kb/1151/what-is-tailscale)
compatible control plane. It is a controller library, not a VPN application:
the host owns the wgo device, its TUN, its private node key, and every
operating-system setting.

> [!WARNING]
> This project is experimental. APIs and behavior can change without notice.
> Do not use it for production systems without your own review and tests.

It was reviewed against Tailscale capability version 145 but advertises
capability version 119. That is the last version before peer-hosted UDP relay
semantics, which this basic client intentionally leaves to standard
[DERP](https://tailscale.com/docs/reference/derp-servers) fallback.

Implemented features:

- [ts2021](https://pkg.go.dev/tailscale.com/control/ts2021)
  [Noise](https://noiseprotocol.org/) control authentication, registration, and
  streaming map updates;
- direct UDP, [STUN](https://tailscale.com/docs/reference/stun-protocol)
  endpoint discovery, authenticated
  [DISCO](https://pkg.go.dev/tailscale.com/disco) probing, and DERP over TLS
  fallback with latency-aware home-region selection;
- publication of complete peer specifications through tracked
  `device.DeviceAPI` peer and transport methods, with an option to use wgo's
  default transport for direct UDP peer endpoints;
- optional local peer confirmation and optional AmneziaWG configuration;
- UI-neutral authentication interactions and change subscriptions;
- versioned callback-based cache state;
- immutable client, node, peer, DERP,
  [MagicDNS](https://tailscale.com/docs/features/magicdns),
  [ACL](https://tailscale.com/docs/features/access-control/acls), and
  desired-network views;
- in-memory MagicDNS lookup without system resolver integration.

The library does not create a TUN, create or close the wgo device, change the
wgo node key, install routes or addresses, change system DNS, or administer a
[tailnet](https://tailscale.com/docs/concepts/tailnet).

Every control-plane, DNS, STUN, DISCO, and DERP operation requires a
`gonnect.Network` passed to `tailscale.New`. Direct peer traffic also uses that
network by default. Set `Options.UseDefaultTransportForDirectPeers` when wgo's
default transport already sends packets through the wanted network.

## Minimal controller setup

```go
network := (&gonnect.NativeConfig{}).Build()

// dev is an existing *device.Device with its WireGuard private key. A detached
// API gives this controller an independent resource lifetime.
api := device.DetachDevice(dev)
defer api.Close()

client, err := tailscale.New(network, api, tailscale.Options{
    Hostname:    "my-vpn-node",
    ControlURL: tailscale.DefaultControlURL,
    TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
    ConfirmPeers: true,
})
if err != nil {
    return err
}
if err := client.Start(ctx); err != nil {
    return err
}
defer client.Close()
```

When an API is present, `Start` returns after it attaches the tracked wgo
transport. `Start` also accepts a nil API. In that case, the client stays in
`StateStarting` until `AttachDevice` supplies one. If registration needs a
person, `Snapshot().Interaction` contains an authorization URL while the client
continues running and remains cancellable.

See the [application usage guide](docs/usage.md) for shared-device ownership,
interactions, DNS, ACLs, cache handling, and desired network configuration.
See [ARCHITECTURE.md](ARCHITECTURE.md) for protocol and component design.
The [basic-scope conformance matrix](docs/requirements.md) maps each requested
capability to its API and tests.

## Status

The requested basic controller scope is implemented. Unit and integration
checks run with:

```sh
go test ./...
go test -race ./...
go vet ./...
```

The Headscale Docker scenario and optional hosted-service test are under
[`tests/e2e`](tests/e2e/README.md); run the container cycle with
`./tests/e2e/run.sh` (it skips if Docker is unavailable). Protocol extensions
such as [Tailscale file transfer](https://tailscale.com/docs/features/taildrop),
[SSH](https://tailscale.com/docs/features/tailscale-ssh),
[Funnel](https://tailscale.com/docs/reference/tailscale-cli/funnel),
exit-node policy UI,
[Tailnet Lock](https://tailscale.com/docs/features/tailnet-lock) key rotation,
and administration APIs are intentionally outside this library.

## License and attribution

The project is MIT licensed. Small independent implementations of Tailscale's
Noise, DISCO, STUN, DERP, and
[netcheck](https://tailscale.com/docs/reference/device-connectivity) behavior
retain Tailscale's BSD-3-Clause copyright and attribution headers in their
source files. No Tailscale Go package is imported.
