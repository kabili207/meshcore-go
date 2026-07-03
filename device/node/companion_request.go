package node

import (
	"fmt"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/event"
)

// SendTelemetryReq requests CayenneLPP telemetry from a peer (repeater, room
// server, or sensor). The reply arrives as a TelemetryResponse event. Returns
// the request tag, which also correlates the response.
func (n *CompanionNode) SendTelemetryReq(to core.MeshCoreID) (uint32, error) {
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return 0, fmt.Errorf("shared secret: %w", err)
	}

	tag := n.clk.GetCurrentTimeUnique()
	// Request data is a 4-byte reserved field; the first byte is the inverted
	// permission mask. Zero requests all telemetry the peer permits.
	var reqData [4]byte
	content := codec.BuildRequestContent(tag, codec.ReqTypeGetTelemetry, reqData[:])

	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		return 0, fmt.Errorf("encrypt telemetry request: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	selfID := n.base.ID()
	payload := codec.BuildAddressedPayload(to.Hash(), selfID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeFlood, payload)
	n.sendToContact(pkt, n.base.Contacts().GetByPubKey(to))

	n.pendingMu.Lock()
	n.pendingTelemetry[tag] = to
	n.pendingMu.Unlock()

	return tag, nil
}

// handleTelemetryResponse promotes a response matching a pending telemetry
// request into a TelemetryResponse event.
func (n *CompanionNode) handleTelemetryResponse(e *event.ResponseReceived) {
	n.pendingMu.Lock()
	peer, pending := n.pendingTelemetry[e.Tag]
	if pending && peer == e.From {
		delete(n.pendingTelemetry, e.Tag)
	} else {
		pending = false
	}
	n.pendingMu.Unlock()
	if !pending {
		return
	}

	n.base.emitEvent(&event.TelemetryResponse{
		Event: n.base.baseEvent(e.RawPacket, e.Source, e.From),
		Data:  e.Content,
	})
}
