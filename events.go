package tailscale

import (
	"sync"
	"time"
)

// EventKind identifies a mutable part of the client view.
type EventKind string

const (
	EventState       EventKind = "state"
	EventInteraction EventKind = "interaction"
	EventSelf        EventKind = "self"
	EventPeers       EventKind = "peers"
	EventPeerPath    EventKind = "peer-path"
	EventDNS         EventKind = "dns"
	EventACL         EventKind = "acl"
	EventNetwork     EventKind = "network"
	EventDERP        EventKind = "derp"
	EventUsers       EventKind = "users"
	EventMetadata    EventKind = "metadata"
	EventError       EventKind = "error"
)

// Event is a coalescable notification. Call Snapshot after receiving it to
// obtain one consistent, immutable view of all client state.
type Event struct {
	Kind     EventKind
	Revision uint64
	At       time.Time
	Err      error
}

type eventHub struct {
	mu     sync.Mutex
	next   uint64
	closed bool
	subs   map[uint64]chan Event
}

func (h *eventHub) subscribe(buffer int) (<-chan Event, func()) {
	if buffer < 1 {
		buffer = 1
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	ch := make(chan Event, buffer)
	if h.closed {
		close(ch)
		return ch, func() {}
	}
	if h.subs == nil {
		h.subs = make(map[uint64]chan Event)
	}
	h.next++
	id := h.next
	h.subs[id] = ch
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			if existing, ok := h.subs[id]; ok {
				delete(h.subs, id)
				close(existing)
			}
			h.mu.Unlock()
		})
	}
}

func (h *eventHub) publish(event Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	for _, ch := range h.subs {
		select {
		case ch <- event:
		default:
			// Events are hints; Snapshot is authoritative. Preserve the newest
			// notification when a subscriber is behind.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- event:
			default:
			}
		}
	}
}

func (h *eventHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for id, ch := range h.subs {
		delete(h.subs, id)
		close(ch)
	}
}
