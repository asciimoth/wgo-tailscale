// Package tailscale connects an existing wgo device to a Tailscale-compatible
// control plane without taking ownership of the device, TUN, or operating
// system network configuration.
//
// Every control, DNS, STUN, DISCO, and DERP socket or lookup made by the
// package is performed through the gonnect.Network supplied to New. Direct peer
// traffic uses that network by default, but Options can leave direct endpoints
// on wgo's default transport. The client reads the wgo device's existing
// private key and never generates, replaces, or rotates it.
package tailscale
