package tailscale

import (
	"context"
	"slices"
)

// ConfirmPeer permits one control-provided peer to be published to wgo when
// confirmation mode is enabled. The ID is PeerInfo.PeerID, normally the
// control server's stable node ID.
func (c *Client) ConfirmPeer(ctx context.Context, id string) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.state == StateStopping || c.state == StateStopped {
		c.mu.Unlock()
		return ErrClosed
	}
	found := false
	for _, node := range c.peers {
		if peerID(node) == id {
			found = true
			break
		}
	}
	if !found {
		c.mu.Unlock()
		return ErrPeerNotFound
	}
	c.confirmed[id] = true
	c.syncConfirmedCacheLocked()
	cache := c.cache
	c.bumpLocked()
	event := c.eventLocked(EventPeers, nil)
	c.mu.Unlock()
	c.events.publish(event)
	storeErr := storeCache(ctx, c.opts.Cache, cache)
	c.reconcilePeers()
	return storeErr
}

// RevokePeerConfirmation removes a prior confirmation and withdraws that peer
// from wgo. It is useful when application policy changes locally.
func (c *Client) RevokePeerConfirmation(ctx context.Context, id string) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.state == StateStopping || c.state == StateStopped {
		c.mu.Unlock()
		return ErrClosed
	}
	if !c.confirmed[id] {
		c.mu.Unlock()
		return ErrPeerNotFound
	}
	delete(c.confirmed, id)
	c.syncConfirmedCacheLocked()
	cache := c.cache
	c.bumpLocked()
	event := c.eventLocked(EventPeers, nil)
	c.mu.Unlock()
	c.events.publish(event)
	storeErr := storeCache(ctx, c.opts.Cache, cache)
	c.reconcilePeers()
	return storeErr
}

func (c *Client) syncConfirmedCacheLocked() {
	c.cache.ConfirmedPeerIDs = c.cache.ConfirmedPeerIDs[:0]
	for id := range c.confirmed {
		c.cache.ConfirmedPeerIDs = append(c.cache.ConfirmedPeerIDs, id)
	}
	slices.Sort(c.cache.ConfirmedPeerIDs)
}
