package tailscale

import (
	"context"
	"errors"
	"fmt"

	"github.com/asciimoth/wgo/device"
)

// Device returns the currently attached wgo control API. It returns nil if no
// API has been attached. A returned API can already be closed; callers can use
// its Wait channel to inspect its lifecycle. Client never closes the API.
func (c *Client) Device() device.DeviceAPI {
	c.deviceMu.RLock()
	defer c.deviceMu.RUnlock()
	return c.deviceAPI
}

// AttachDevice attaches api if the client has no current usable device API.
//
// A closed API does not occupy the attachment slot. If the client has already
// established its Tailscale identity, api must contain the same node private
// key. On success, the client installs its tracked transport and reconciles all
// current peers before this method returns. Client does not call Close, Up, or
// Down on api.
func (c *Client) AttachDevice(api device.DeviceAPI) error {
	if nilDeviceAPI(api) {
		return ErrDeviceRequired
	}
	if closedDeviceAPI(api) {
		return device.ErrDeviceClosed
	}

	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	if c.closed {
		return ErrClosed
	}

	c.deviceMu.Lock()
	current := c.deviceAPI
	if !nilDeviceAPI(current) && !closedDeviceAPI(current) {
		c.deviceMu.Unlock()
		return ErrDeviceAlreadyAttached
	}

	startWorkers := false
	if c.started && !c.runtimeStarted {
		// No identity-bound worker or device watcher exists yet, so the API
		// lock is not needed during cache callbacks and resource creation.
		c.deviceMu.Unlock()
		if err := c.initializeRuntime(c.ctx, api); err != nil {
			return err
		}
		c.deviceMu.Lock()
		startWorkers = true
	} else if c.runtimeStarted {
		if err := c.validateRuntimeIdentity(api); err != nil {
			c.deviceMu.Unlock()
			return err
		}
		if err := api.AddTrackedTransport(c.opts.TransportID, device.TransportConfig{
			Bind: c.bind, ListenPort: c.opts.ListenPort,
		}); err != nil {
			c.deviceMu.Unlock()
			return fmt.Errorf("tailscale: add wgo transport %q: %w", c.opts.TransportID, err)
		}
		c.clearAppliedDeviceLocked()
	}

	c.deviceAPI = api
	c.deviceGeneration++
	generation := c.deviceGeneration
	ctx := c.ctx
	started := c.started
	if started {
		c.restoreStateAfterDeviceAttach()
	}
	c.deviceMu.Unlock()

	if !started {
		return nil
	}
	if startWorkers {
		c.launchRuntimeLocked(ctx)
	}
	c.watchDeviceLocked(ctx, api, generation)
	c.reconcilePeers()
	return nil
}

// validateRuntimeIdentity prevents one control session from moving to a
// device that has a different WireGuard node identity.
func (c *Client) validateRuntimeIdentity(api device.DeviceAPI) error {
	privateKey := api.PrivateKey()
	if privateKey.IsZero() {
		return ErrZeroNodeKey
	}
	if !privateKey.PublicKey().Equals(device.NoisePublicKey(c.nodePrivate.PublicNode())) {
		return ErrNodeIdentityChanged
	}
	return nil
}

// watchDeviceLocked observes an attachment without taking ownership of it.
// The caller must hold lifeMu so a watcher cannot be added after Close starts
// waiting for client workers.
func (c *Client) watchDeviceLocked(ctx context.Context, api device.DeviceAPI, generation uint64) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-api.Wait():
		}

		c.deviceMu.Lock()
		if c.deviceGeneration != generation {
			c.deviceMu.Unlock()
			return
		}
		c.clearAppliedDeviceLocked()
		c.reportClosedDevice()
		c.deviceMu.Unlock()
	}()
}

// clearAppliedDeviceLocked forgets resources associated with the previous API
// after that API has released its tracked resources. The caller must hold
// deviceMu for writing, which excludes peer reconciliation on that API.
func (c *Client) clearAppliedDeviceLocked() {
	c.reconcileMu.Lock()
	c.mu.Lock()
	changed := len(c.applied) != 0
	clear(c.applied)
	for key, local := range c.peerLocal {
		if local != nil {
			local.applied = false
		}
		if c.bind != nil {
			c.bind.RemovePeer(key)
		}
	}
	var peerEvent, networkEvent Event
	if changed {
		c.bumpLocked()
		c.networkRevision = c.revision
		peerEvent = c.eventLocked(EventPeers, nil)
		networkEvent = c.eventLocked(EventNetwork, nil)
	}
	c.mu.Unlock()
	c.reconcileMu.Unlock()
	if changed {
		c.events.publish(peerEvent)
		c.events.publish(networkEvent)
	}
}

func (c *Client) reportClosedDevice() {
	c.mu.Lock()
	if c.state == StateStopping || c.state == StateStopped {
		c.mu.Unlock()
		return
	}
	c.state = StateDegraded
	c.lastError = device.ErrDeviceClosed.Error()
	c.bumpLocked()
	errorEvent := c.eventLocked(EventError, device.ErrDeviceClosed)
	stateEvent := c.eventLocked(EventState, nil)
	c.mu.Unlock()
	c.events.publish(errorEvent)
	c.events.publish(stateEvent)
}

func (c *Client) restoreStateAfterDeviceAttach() {
	c.mu.Lock()
	if c.state == StateStopping || c.state == StateStopped {
		c.mu.Unlock()
		return
	}
	if c.lastError == device.ErrDeviceClosed.Error() {
		c.lastError = ""
		if c.authenticated {
			c.state = StateRunning
		} else if c.interaction != nil {
			c.state = StateNeedsAuthentication
		} else {
			c.state = StateStarting
		}
	}
	c.bumpLocked()
	stateEvent := c.eventLocked(EventState, nil)
	metadataEvent := c.eventLocked(EventMetadata, nil)
	c.mu.Unlock()
	c.events.publish(stateEvent)
	c.events.publish(metadataEvent)
}

// Ignore errors caused only by an externally closed API. Its tracked resource
// cleanup has already completed before Wait closes.
func externalDeviceCloseError(err error) error {
	if errors.Is(err, device.ErrDeviceClosed) {
		return nil
	}
	return err
}
