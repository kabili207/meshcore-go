package room

import (
	"context"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/ack"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

const (
	// SyncPushInterval is the delay between post sync rounds.
	// Firmware: SYNC_PUSH_INTERVAL = 1200ms.
	SyncPushInterval = 1200 * time.Millisecond

	// SyncIdleInterval is the faster poll interval when no posts are pushed.
	// Firmware: SYNC_PUSH_INTERVAL / 8 = 150ms.
	SyncIdleInterval = 150 * time.Millisecond

	// PostSyncDelay is the minimum age a post must have before being pushed.
	// Firmware: POST_SYNC_DELAY_SECS = 6 seconds.
	PostSyncDelay uint32 = 6

	// MaxPushFailures is the maximum consecutive push failures before
	// skipping a client. Firmware: 3.
	MaxPushFailures = 3
)

// runSyncLoop runs the post sync loop until the context is cancelled.
func (s *Server) runSyncLoop(ctx context.Context) {
	timer := time.NewTimer(SyncPushInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			pushed := s.syncOnce()
			if pushed {
				timer.Reset(SyncPushInterval)
			} else {
				timer.Reset(SyncIdleInterval)
			}
		}
	}
}

// syncOnce performs one round of the sync loop: picks the next client and
// pushes the oldest unseen post. Returns true if a post was pushed.
func (s *Server) syncOnce() bool {
	clientCount := s.cfg.Clients.Count()
	if clientCount == 0 {
		return false
	}

	s.mu.Lock()
	idx := s.nextClientIdx
	s.nextClientIdx = (s.nextClientIdx + 1) % clientCount
	s.mu.Unlock()

	// Get client at this index
	var client *ClientInfo
	i := 0
	s.cfg.Clients.ForEach(func(c *ClientInfo) bool {
		if i == idx {
			client = c
			return false
		}
		i++
		return true
	})

	if client == nil {
		return false
	}

	// Skip if client is not ready for push
	if client.LastActivity == 0 {
		return false
	}
	if client.PushFailures >= MaxPushFailures {
		return false
	}

	// Find the oldest unsynced post for this client
	nowTS := s.cfg.Clock.GetCurrentTime()
	posts := s.cfg.Posts.GetPostsSince(client.SyncSince)

	for _, post := range posts {
		// Post must be old enough
		if nowTS < post.Timestamp+PostSyncDelay {
			continue
		}
		// Don't push a client's own posts back to them
		if post.SenderID == client.ID {
			continue
		}

		s.pushPostToClient(client, post)
		return true
	}

	return false
}

// pushPostToClient sends a post to a client and tracks the expected ACK.
func (s *Server) pushPostToClient(client *ClientInfo, post *PostInfo) {
	if len(post.Content) == 0 {
		return
	}

	// Get shared secret for encryption
	secret, err := s.cfg.Contacts.GetSharedSecret(client.ID)
	if err != nil {
		s.log.Debug("no shared secret for client", "peer", client.ID.String())
		return
	}

	// Encrypt the post content
	encrypted, err := crypto.EncryptAddressedWithSecret(post.Content, secret)
	if err != nil {
		s.log.Warn("failed to encrypt post for push", "error", err)
		return
	}

	// Build addressed packet
	destHash := client.ID.Hash()
	srcHash := core.MeshCoreID(s.cfg.PublicKey).Hash()
	payload := codec.BuildAddressedPayload(destHash, srcHash, 0, encrypted)

	pkt := &codec.Packet{
		Header:  codec.PayloadTypeTxtMsg << codec.PHTypeShift,
		Payload: payload,
	}

	// Compute expected ACK hash
	ackHash := crypto.ComputeAckHash(post.Content, s.cfg.PublicKey[:])

	// Track this push for ACK
	clientID := client.ID
	postTimestamp := post.Timestamp
	s.cfg.ACKTracker.Track(ackHash, ack.PendingACK{
		OnACK: func() {
			// ACK received — advance sync marker
			c := s.cfg.Clients.GetClient(clientID)
			if c != nil {
				c.SyncSince = postTimestamp
				c.PushFailures = 0
			}
		},
		OnTimeout: func() {
			// ACK timed out — increment failure counter
			c := s.cfg.Clients.GetClient(clientID)
			if c != nil {
				c.PushFailures++
			}
		},
	})

	client.PushPostTimestamp = postTimestamp

	// Send the packet
	ct := s.cfg.Contacts.GetByPubKey(client.ID)
	if ct != nil && ct.HasDirectPath() {
		s.cfg.Router.SendDirect(pkt, ct.OutPath[:ct.OutPathLen])
	} else {
		s.cfg.Router.SendFlood(pkt)
	}

	s.log.Debug("pushed post to client",
		"peer", client.ID.String(),
		"post_ts", postTimestamp)
}
