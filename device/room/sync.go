package room

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
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

// unsyncedCount returns how many stored posts are newer than the client's sync
// point and not authored by the client (firmware getUnsyncedCount). The result
// is clamped to a single byte for the keep-alive ACK.
func (s *Server) unsyncedCount(client *ClientInfo) uint8 {
	count := 0
	for _, p := range s.cfg.Posts.GetPostsSince(client.SyncSince) {
		if p.SenderID != client.ID {
			count++
		}
	}
	if count > 255 {
		count = 255
	}
	return uint8(count)
}

// pushPostToClient sends a post to a client and tracks the expected ACK.
func (s *Server) pushPostToClient(client *ClientInfo, post *PostInfo) {
	if len(post.Content) == 0 {
		return
	}

	// The stored content is the plain post body; extract the text so it can be
	// re-framed as a signed message carrying the author's identity.
	stored, err := codec.ParseTxtMsgContent(post.Content)
	if err != nil {
		s.log.Debug("failed to parse stored post", "peer", client.ID.String(), "error", err)
		return
	}

	// Build a SIGNED_PLAIN payload carrying the original author's 4-byte pubkey
	// prefix and the post's original timestamp, so the recipient can attribute it
	// (firmware pushPostToClient). The random attempt byte keeps the packet hash
	// unique across retransmissions.
	var rnd [1]byte
	_, _ = rand.Read(rnd[:])
	payload := codec.BuildTxtMsgContent(post.Timestamp, codec.TxtTypeSigned, rnd[0]&0x03, stored.Message, post.SenderID[:4])

	// Expected ACK: signed messages are keyed by the recipient's pubkey, hashed
	// over the full signed payload.
	ackHash := crypto.ComputeAckHash(payload, client.ID[:])

	// Track this push for ACK
	clientID := client.ID
	postTimestamp := post.Timestamp
	if s.cfg.ACKTracker != nil {
		s.cfg.ACKTracker.Track(ackHash, ack.PendingACK{
			OnACK: func() {
				c := s.cfg.Clients.GetClient(clientID)
				if c != nil {
					c.SyncSince = postTimestamp
					c.PushFailures = 0
				}
			},
			OnTimeout: func() {
				c := s.cfg.Clients.GetClient(clientID)
				if c != nil {
					c.PushFailures++
				}
			},
		})
	}

	client.PushPostTimestamp = postTimestamp

	// Use event-based sender if available, otherwise fall back to legacy
	if s.sender != nil {
		if err := s.sender.SendToContact(client.ID, codec.PayloadTypeTxtMsg, payload); err != nil {
			s.log.Debug("failed to push post", "peer", client.ID.String(), "error", err)
			return
		}
	} else {
		s.pushPostLegacy(client, payload)
	}

	if s.cfg.PostCounter != nil {
		s.cfg.PostCounter.IncrementPostPush()
	}

	s.log.Debug("pushed post to client",
		"peer", client.ID.String(),
		"post_ts", postTimestamp)
}

// pushPostLegacy sends a pre-built post payload using the legacy Router-based path.
// Deprecated: Use NodeSender via SetSender instead.
func (s *Server) pushPostLegacy(client *ClientInfo, plaintext []byte) {
	secret, err := s.cfg.Contacts.GetSharedSecret(client.ID)
	if err != nil {
		s.log.Debug("no shared secret for client", "peer", client.ID.String())
		return
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		s.log.Warn("failed to encrypt post for push", "error", err)
		return
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	destHash := client.ID.Hash()
	srcHash := core.MeshCoreID(s.cfg.PublicKey).Hash()
	payload := codec.BuildAddressedPayload(destHash, srcHash, mac, ciphertext)

	pkt := &codec.Packet{
		Header:  codec.PayloadTypeTxtMsg << codec.PHTypeShift,
		Payload: payload,
	}

	ct := s.cfg.Contacts.GetByPubKey(client.ID)
	if ct != nil && ct.HasDirectPath() {
		s.cfg.Router.SendDirect(pkt, ct.OutPath)
	} else {
		s.cfg.Router.SendFloodScoped(pkt)
	}
}
