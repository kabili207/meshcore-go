package node

import (
	"encoding/binary"
	"fmt"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
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
	if _, err := n.sendRequestContent(to, secret, content); err != nil {
		return 0, fmt.Errorf("telemetry request: %w", err)
	}

	n.pendingMu.Lock()
	n.pendingTelemetry[tag] = to
	n.pendingMu.Unlock()

	return tag, nil
}

// SendStatusReq requests device status (RepeaterStats) from a repeater or room
// server. The reply arrives as a StatusResponse event. Returns the request tag,
// which also correlates the response.
func (n *CompanionNode) SendStatusReq(to core.MeshCoreID) (uint32, error) {
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return 0, fmt.Errorf("shared secret: %w", err)
	}

	tag := n.clk.GetCurrentTimeUnique()
	content := codec.BuildRequestContent(tag, codec.ReqTypeGetStats, nil)
	if _, err := n.sendRequestContent(to, secret, content); err != nil {
		return 0, fmt.Errorf("status request: %w", err)
	}

	n.pendingMu.Lock()
	n.pendingStatus[tag] = to
	n.pendingMu.Unlock()

	return tag, nil
}

// SendBinaryReq sends a request whose body the caller supplies, starting with
// the request type byte, as CMD_SEND_BINARY_REQ does. The reply arrives as a
// BinaryResponse event. Returns the request tag and whether the request was
// flooded (no direct path to the peer).
func (n *CompanionNode) SendBinaryReq(to core.MeshCoreID, data []byte) (tag uint32, flood bool, err error) {
	// Firmware's sendRequest limit: room for the tag and cipher padding.
	if len(data) > codec.MaxPacketPayload-16 {
		return 0, false, fmt.Errorf("request data too long: %d bytes", len(data))
	}
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return 0, false, fmt.Errorf("shared secret: %w", err)
	}

	tag = n.clk.GetCurrentTimeUnique()
	content := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(content, tag)
	copy(content[4:], data)
	if flood, err = n.sendRequestContent(to, secret, content); err != nil {
		return 0, false, fmt.Errorf("binary request: %w", err)
	}

	n.pendingMu.Lock()
	n.pendingBinary[tag] = to
	n.pendingMu.Unlock()

	return tag, flood, nil
}

// maxAnonReqData is the most request data an ANON_REQ can carry: the payload
// holds dest hash(1), our public key(32) and MAC(2), leaving 149 bytes, which
// pads down to 144 bytes of plaintext, less the 4-byte tag.
const maxAnonReqData = 140

// SendAnonReq sends an anonymous request (ANON_REQ) whose body the caller
// supplies, starting with the request type byte, as CMD_SEND_ANON_REQ does. It
// is signed with our identity, so the target needn't know us. The reply
// arrives as a BinaryResponse event. Returns the request tag and whether the
// request was flooded.
//
// Like firmware, a target that isn't a contact is first added as a transient
// contact with a zero-hop path. That is also what lets us decrypt the reply.
func (n *CompanionNode) SendAnonReq(to core.MeshCoreID, data []byte) (tag uint32, flood bool, err error) {
	if len(data) > maxAnonReqData {
		return 0, false, fmt.Errorf("request data too long: %d bytes", len(data))
	}
	contacts := n.base.Contacts()
	ct := contacts.GetByPubKey(to)
	if ct == nil {
		if ct, err = contacts.AddContact(&contact.ContactInfo{
			ID:         to,
			Type:       codec.NodeTypeNone,
			OutPathLen: 0, // zero-hop direct, firmware's default for an anon contact
			LastMod:    n.clk.GetCurrentTime(),
		}); err != nil {
			return 0, false, fmt.Errorf("add anon contact: %w", err)
		}
	}
	secret, err := contacts.GetSharedSecret(to)
	if err != nil {
		return 0, false, fmt.Errorf("shared secret: %w", err)
	}

	tag = n.clk.GetCurrentTimeUnique()
	plaintext := make([]byte, 4+len(data))
	binary.LittleEndian.PutUint32(plaintext, tag)
	copy(plaintext[4:], data)
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		return 0, false, fmt.Errorf("encrypt anon request: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAnonReqPayload(to.Hash(), n.base.PublicKey(), mac, ciphertext)
	n.sendToContact(codec.NewPacket(codec.PayloadTypeAnonReq, codec.RouteTypeFlood, payload), ct)

	n.pendingMu.Lock()
	n.pendingBinary[tag] = to
	n.pendingMu.Unlock()

	return tag, !ct.HasDirectPath(), nil
}

// sendRequestContent encrypts a REQ body for to and sends it, direct when a path
// is known and flooded otherwise. Reports whether it flooded.
func (n *CompanionNode) sendRequestContent(to core.MeshCoreID, secret, content []byte) (bool, error) {
	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		return false, fmt.Errorf("encrypt: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	selfID := n.base.ID()
	payload := codec.BuildAddressedPayload(to.Hash(), selfID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeFlood, payload)
	ct := n.base.Contacts().GetByPubKey(to)
	n.sendToContact(pkt, ct)
	return ct == nil || !ct.HasDirectPath(), nil
}

// handleBinaryResponse promotes a response matching a pending binary request
// into a BinaryResponse event. Reports whether it was consumed.
func (n *CompanionNode) handleBinaryResponse(e *event.ResponseReceived) bool {
	n.pendingMu.Lock()
	peer, pending := n.pendingBinary[e.Tag]
	if pending && peer == e.From {
		delete(n.pendingBinary, e.Tag)
	} else {
		pending = false
	}
	n.pendingMu.Unlock()
	if !pending {
		return false
	}

	n.base.emitEvent(&event.BinaryResponse{
		Event: n.base.baseEvent(e.RawPacket, e.Source, e.From),
		Tag:   e.Tag,
		Data:  e.Content,
	})
	return true
}

// handleStatusResponse promotes a response matching a pending status request
// into a StatusResponse event. Reports whether it was consumed.
func (n *CompanionNode) handleStatusResponse(e *event.ResponseReceived) bool {
	n.pendingMu.Lock()
	peer, pending := n.pendingStatus[e.Tag]
	if pending && peer == e.From {
		delete(n.pendingStatus, e.Tag)
	} else {
		pending = false
	}
	n.pendingMu.Unlock()
	if !pending {
		return false
	}

	n.base.emitEvent(&event.StatusResponse{
		Event: n.base.baseEvent(e.RawPacket, e.Source, e.From),
		Data:  e.Content,
	})
	return true
}

// handleTelemetryResponse promotes a response matching a pending telemetry
// request into a TelemetryResponse event. Reports whether it was consumed.
func (n *CompanionNode) handleTelemetryResponse(e *event.ResponseReceived) bool {
	n.pendingMu.Lock()
	peer, pending := n.pendingTelemetry[e.Tag]
	if pending && peer == e.From {
		delete(n.pendingTelemetry, e.Tag)
	} else {
		pending = false
	}
	n.pendingMu.Unlock()
	if !pending {
		return false
	}

	n.base.emitEvent(&event.TelemetryResponse{
		Event: n.base.baseEvent(e.RawPacket, e.Source, e.From),
		Data:  e.Content,
	})
	return true
}
