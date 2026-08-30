# Application usage guide

This guide starts after the application already has a `gonnect.Network`, an
existing wgo device, a TUN chosen by the application, and a private key assigned
to that device. TUN creation and operating-system configuration are deliberately
not covered here.

## Attach the controller

```go
client, err := tailscale.New(network, dev, tailscale.Options{
    Hostname:   "laptop",
    ControlURL: tailscale.DefaultControlURL, // or a Headscale URL
    TLSConfig:  &tls.Config{MinVersion: tls.VersionTLS12},
    AuthKey:    os.Getenv("TS_AUTHKEY"),      // optional

    // New control-plane peers remain visible but are not sent to wgo until
    // the application calls ConfirmPeer.
    ConfirmPeers: true,

    // This ID must be unique among controllers sharing dev.
    TransportID: "tailscale",
})
if err != nil {
    return err
}
if err := client.Start(ctx); err != nil {
    return err
}
defer client.Close()
```

The wgo device must already have a nonzero private key. The node registered
with control uses that exact key. If control asks for node-key rotation, the
client reports `tailscale.ErrNodeKeyExpired`; the host must decide how to
replace or recreate its shared identity.

## Present authentication without coupling a UI

Subscribe to hints and read a fresh snapshot after each one:

```go
events, unsubscribe := client.Subscribe(8)
defer unsubscribe()

go func() {
    for range events {
        snapshot := client.Snapshot()
        interaction := snapshot.Interaction
        if interaction == nil {
            continue
        }
        switch interaction.Kind {
        case tailscale.InteractionAuthenticate:
            ui.ShowAuthorizationLink(interaction.URL)
        case tailscale.InteractionNodeKeyExpired:
            ui.ShowError(interaction.Message)
        }
    }
}()
```

After the user or an administrator acts, the UI may call:

```go
_ = client.ResumeInteraction(interaction.ID)
```

This only expedites the next check. The client also polls in the background,
and cancellation or `Close` interrupts pending requests. A CLI can print the
URL, a desktop app can open a browser, and a service can send it to its own API;
the library assumes none of those choices.

## Confirm peers locally

With `ConfirmPeers`, every received peer remains in
`PeerAwaitingConfirmation` and `AppliedToWGO == false`:

```go
for _, peer := range client.Peers() {
    if peer.Confirmation == tailscale.PeerAwaitingConfirmation {
        ui.AskToTrust(peer.PeerID, peer.Node.Name, peer.Node.PublicKey)
    }
}

if err := client.ConfirmPeer(ctx, peerID); err != nil {
    return err
}
```

Confirmations use the control server's stable ID when present and can be
persisted in the client cache. `RevokePeerConfirmation` withdraws the peer from
wgo. Confirmation is local admission control; it does not change a Tailnet ACL
or administer the control service.

## Share one wgo device with another control plane

Start both controllers against the same `*device.Device`:

```go
thirdParty, err := otherplane.NewController(dev, otherOptions)
if err != nil { return err }

tailscaleClient, err := tailscale.New(network, dev, tailscale.Options{
    Hostname:    "combined-node",
    TransportID: "tailscale", // not the default or the other controller's ID
    TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
})
if err != nil { return err }

go thirdParty.Run(ctx)
if err := tailscaleClient.Start(ctx); err != nil { return err }
```

Both services see the device's one public key. They must assign disjoint peer
public keys and route prefixes. `wgo-tailscale` publishes only its complete peer
specs, and on close it deletes a peer only if its current endpoint still uses
the client's named transport. An existing spec on another transport produces
`ErrPeerConflict` rather than being overwritten.

The host shuts down controllers before the shared resources:

```go
cancelControllers()
_ = tailscaleClient.Close()
thirdParty.Wait()
dev.Close()
// Close or detach the host's concrete network if that network has a lifecycle.
```

## MagicDNS lookups

No system resolver is changed. Use the live in-memory resolver:

```go
addresses, err := client.Resolver().LookupNetIP(ctx, "ip", "db.my-tailnet.ts.net")
if err != nil {
    return err
}
```

`LookupHost` and `LookupAddr` are also available. Short names use the
control-provided search domains. A/AAAA records are derived from self and peer
nodes, while control-provided extra records—including CNAMEs—are retained in
`client.DNS().Records`.

Applications that need other record types can inspect the immutable DNS view
and combine it with their own resolver policy. The resolver never falls back
to the operating system or sends DNS traffic.

## Read ACL rules

```go
view := client.ACL()
for _, rule := range view.Rules {
    audit.Store(rule.SourceIPs, rule.Destinations, rule.IPProtocols)
}

allowed := client.ACLAllows(srcIP, dstIP, 6 /* TCP */, 443)
```

The view is the reduced packet filter delivered to this node by control.
`view.NamedRules` also preserves the server's incremental packet-filter chunks;
`view.Rules` is their deterministic flattened form used by `ACLAllows`.
`ACLAllows` is a convenience query over that view. Neither method installs a
firewall or enforces packets, and the API is not a Tailnet administration API.

To configure a `gonnect/tun.Firewall`, convert the flattened ACL view to an
incoming allow list:

```go
firewall.SetConfig(client.ACLFirewallConfig())
```

The generated rules preserve remote source addresses, local destination
addresses, protocols, and service ports. They do not restrict outgoing traffic
because `gonnect.FirewallConfig.Exclude` is a deny list, while the Tailscale
packet filter is an allow list. The conversion does not install the config.

## Consume desired network configuration

```go
desired := client.DesiredNetworkConfiguration()
reconciler.SetDesiredVPNState(desired.InterfaceName, desired.MTU,
    desired.Addresses, desired.Routes, desired.DNS)
```

The value is descriptive. The library does not create an interface, add an
address, install a route, or configure DNS. Use `EventNetwork` to trigger the
application's own reconciliation and compare `Revision` to avoid stale work.

## Use wgo's default transport for direct peers

By default, peer traffic uses the Tailscale named transport. That transport
selects direct UDP or DERP behind one logical peer endpoint.

If the host already configured wgo's default transport to send UDP through the
wanted network, direct peer endpoints can use that default transport:

```go
client, err := tailscale.New(network, dev, tailscale.Options{
    Hostname: "my-vpn-node",
    TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
    UseDefaultTransportForDirectPeers: true,
})
```

DERP still uses the named transport. A peer that already exists on wgo's default
transport before this client applies it is reported as `ErrPeerConflict`,
because the default transport does not identify one controller.

## Inspect DERP selection

`DERP` is also a read-only live view. It identifies the selected home region
and the latest latency measurement for every region that answered netcheck:

```go
view := client.DERP()
for _, region := range view.Regions {
    metrics.RecordDERP(region.ID, region.Latency,
        string(region.LatencySource), region.LatencyMeasuredAt)
}
```

STUN measurements use the client's gonnect-created UDP socket. When UDP is
blocked, the client falls back to the DERP HTTPS latency endpoint through the
same `gonnect.Network`; `LatencySource` is then `DERPLatencyHTTPS`. Subscribe to
`EventDERP` to refresh the view. No system network setting is changed.

## Optional AmneziaWG obfuscation

One complete wgo AmneziaWG profile may be applied to every peer owned by this
client:

```go
profile := device.DefaultAmneziaWGConfig()
// Fill the same compatible profile used by every remote peer.

client, err := tailscale.New(network, dev, tailscale.Options{
    Hostname:    "obfuscated-node",
    Obfuscation: &profile,
    TLSConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
})
```

This changes wgo peer packet formatting; it does not modify Tailscale control,
DISCO, STUN, or DERP. Standard Tailscale peers do not negotiate AmneziaWG, so
the remote endpoints must already be configured compatibly.

## Persist identity and confirmations

```go
cache := tailscale.CacheCallbacks{
    Load: func(ctx context.Context) ([]byte, error) {
        return secureStore.Read(ctx, "tailscale-client")
    },
    Store: func(ctx context.Context, value []byte) error {
        return secureStore.AtomicReplace(ctx, "tailscale-client", value)
    },
}
```

Pass `cache` in `Options`. Treat the blob as sensitive: it contains machine and
DISCO private keys. It does not contain the wgo node private key. Without a
cache, the machine/DISCO identity changes between process runs and a control
service may require the node to be registered again.
