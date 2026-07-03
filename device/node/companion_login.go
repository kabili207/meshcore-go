package node

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

// maxLoginPasswordLen is the firmware's password length cap.
const maxLoginPasswordLen = 15

// SendLogin sends an ANON_REQ login to a repeater or room server. The plaintext
// format matches firmware: a room server's login carries the contact's
// sync_since after the timestamp; other server types do not. On a login-OK
// response a LoginResponse event fires and the server is tracked for keep-alive.
// Returns the login send time (also used as an internal correlation key).
func (n *CompanionNode) SendLogin(to core.MeshCoreID, password string) (uint32, error) {
	ct := n.base.Contacts().GetByPubKey(to)
	if ct == nil {
		return 0, fmt.Errorf("unknown contact %s", to)
	}
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return 0, fmt.Errorf("shared secret: %w", err)
	}

	now := n.clk.GetCurrentTimeUnique()
	if len(password) > maxLoginPasswordLen {
		password = password[:maxLoginPasswordLen]
	}

	var plaintext []byte
	if ct.Type == codec.NodeTypeRoom {
		plaintext = make([]byte, 8+len(password))
		binary.LittleEndian.PutUint32(plaintext[0:4], now)
		binary.LittleEndian.PutUint32(plaintext[4:8], ct.SyncSince)
		copy(plaintext[8:], password)
	} else {
		plaintext = make([]byte, 4+len(password))
		binary.LittleEndian.PutUint32(plaintext[0:4], now)
		copy(plaintext[4:], password)
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		return 0, fmt.Errorf("encrypt login: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	selfPub := n.base.PublicKey()
	payload := codec.BuildAnonReqPayload(to.Hash(), selfPub, mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeAnonReq, codec.RouteTypeFlood, payload)
	n.sendToContact(pkt, ct)

	n.pendingMu.Lock()
	n.pendingLogins[to] = now
	n.pendingMu.Unlock()

	return now, nil
}

// SendKeepAlive sends a keep-alive request to a logged-in server and tracks the
// expected ACK so a reply refreshes the connection's liveness.
func (n *CompanionNode) SendKeepAlive(to core.MeshCoreID) error {
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}

	// Content is timestamp(4) + type(1) + forceSince(4). The server hashes these
	// 9 bytes with the client's pubkey to form the ACK; we send and hash the same.
	var forceSince [4]byte
	content := codec.BuildRequestContent(n.clk.GetCurrentTime(), codec.ReqTypeKeepalive, forceSince[:])

	selfID := n.base.ID()
	if n.ackTracker != nil {
		expected := crypto.ComputeAckHash(content, selfID[:])
		peer := to
		n.ackTracker.Track(expected, ack.PendingACK{
			OnACK: func() { n.connections.Touch(peer) },
		})
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		return fmt.Errorf("encrypt keepalive: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), selfID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeFlood, payload)
	n.sendToContact(pkt, n.base.Contacts().GetByPubKey(to))
	return nil
}

// IsConnected reports whether the given server is currently tracked as a live
// keep-alive connection.
func (n *CompanionNode) IsConnected(id core.MeshCoreID) bool {
	return n.connections.IsConnected(id)
}

// sendToContact routes a packet directly when a path to the contact is known,
// otherwise floods it.
func (n *CompanionNode) sendToContact(pkt *codec.Packet, ct *contact.ContactInfo) {
	if ct != nil && ct.HasDirectPath() {
		n.base.Router.SendDirect(pkt, ct.OutPath)
	} else {
		n.base.Router.SendFloodScoped(pkt)
	}
}

// onInternalEvent watches responses for login correlation and liveness.
func (n *CompanionNode) onInternalEvent(evt any) {
	switch e := evt.(type) {
	case *event.ResponseReceived:
		n.connections.Touch(e.From) // any response means the server is alive
		n.handleLoginResponse(e)
		n.handleTelemetryResponse(e)
	}
}

// handleLoginResponse promotes a RESP_SERVER_LOGIN_OK from a server we have a
// pending login with into a LoginResponse event and a tracked connection.
func (n *CompanionNode) handleLoginResponse(e *event.ResponseReceived) {
	n.pendingMu.Lock()
	_, pending := n.pendingLogins[e.From]
	n.pendingMu.Unlock()
	if !pending {
		return
	}
	// Login-OK content: resp_type(1) + legacy(1) + admin(1) + perms(1) + ...
	if len(e.Content) < 4 || e.Content[0] != codec.RespServerLoginOK {
		return
	}
	perms := e.Content[3]

	n.pendingMu.Lock()
	delete(n.pendingLogins, e.From)
	n.pendingMu.Unlock()

	n.connections.Register(e.From)
	n.base.emitEvent(&event.LoginResponse{
		Event:       event.Event{From: e.From, Timestamp: time.Now()},
		Permissions: perms,
	})
	n.log.Info("logged in to server", "peer", e.From.String(), "perms", perms)
}

// keepAliveLoop periodically sends keep-alives to all tracked connections.
func (n *CompanionNode) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(n.keepAliveEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, id := range n.connections.Peers() {
				if err := n.SendKeepAlive(id); err != nil {
					n.log.Debug("keepalive failed", "peer", id.String(), "error", err)
				}
			}
		}
	}
}
