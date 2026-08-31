// Package tailscale connects an attachable wgo device API to a
// Tailscale-compatible control plane without taking ownership of the API,
// device, TUN, or operating system network configuration.
//
// Every control, DNS, STUN, DISCO, and DERP socket or lookup made by the
// package is performed through the gonnect.Network supplied to New. Direct peer
// traffic uses that network by default, but Options can leave direct endpoints
// on wgo's default transport. The first usable API supplies the node private
// key. A replacement API must supply the same key. The client never generates,
// replaces, or rotates that key.
package tailscale
