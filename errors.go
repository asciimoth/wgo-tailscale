package tailscale

import "errors"

var (
	ErrAlreadyStarted         = errors.New("tailscale: client already started")
	ErrNotStarted             = errors.New("tailscale: client not started")
	ErrClosed                 = errors.New("tailscale: client closed")
	ErrZeroNodeKey            = errors.New("tailscale: wgo device has no private node key")
	ErrNodeIdentityChanged    = errors.New("tailscale: cached node identity does not match the wgo device")
	ErrControlNodeKeyMismatch = errors.New("tailscale: control returned a self node key that does not match the wgo device")
	ErrNodeKeyExpired         = errors.New("tailscale: control requires node-key rotation, but the wgo device key is immutable to this client")
	ErrPeerNotFound           = errors.New("tailscale: peer not found")
	ErrPeerConflict           = errors.New("tailscale: peer public key is already owned by another wgo controller")
	ErrInteractionNotFound    = errors.New("tailscale: interaction not found")
)
