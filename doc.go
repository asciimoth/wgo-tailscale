// Package tailscale connects an existing wgo device to a Tailscale-compatible
// control plane without taking ownership of the device, TUN, or operating
// system network configuration.
//
// Every socket and lookup made by the package is performed through the
// gonnect.Network supplied to New. The client reads the wgo device's existing
// private key and never generates, replaces, or rotates it.
package tailscale
