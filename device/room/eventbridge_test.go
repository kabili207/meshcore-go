package room

import (
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// This file exists so the room tests drive the same path production does.
//
// In production a room server never sees a raw packet: BaseNode decrypts, builds
// typed events, and RoomNode.dispatchToServer calls HandleLogin / HandleTextMessage /
// HandleRequest / HandlePath / HandleAdvertReceived. device/room cannot import
// device/node (device/node already imports device/room), so this shim reproduces
// BaseNode's packet-to-event conversion locally.
//
// It must stay in step with device/node/dispatch.go. If a test here passes while the
// real node misbehaves, suspect this file first.

// dispatchPacket converts pkt into the typed event BaseNode would emit and hands it
// to the matching Server handler, mirroring RoomNode.dispatchToServer.
func (h *testHarness) dispatchPacket(t *testing.T, pkt *codec.Packet, src transport.PacketSource) {
	t.Helper()

	switch pkt.PayloadType() {
	case codec.PayloadTypeAdvert:
		h.dispatchAdvert(t, pkt, src)
	case codec.PayloadTypeAnonReq:
		h.dispatchAnonReq(t, pkt, src)
	case codec.PayloadTypeTxtMsg, codec.PayloadTypeReq, codec.PayloadTypePath:
		h.dispatchAddressed(t, pkt, src)
	case codec.PayloadTypeAck:
		// BaseNode resolves ACKs against its tracker and emits AckReceived; the
		// room server has no event-path ACK handler, so only the resolve matters.
		if len(pkt.Payload) < codec.AckSize {
			return
		}
		if ackPayload, err := codec.ParseAckPayload(pkt.Payload); err == nil {
			h.tracker.Resolve(ackPayload.Checksum)
		}
	}
}

func (h *testHarness) dispatchAdvert(t *testing.T, pkt *codec.Packet, src transport.PacketSource) {
	t.Helper()

	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		return
	}
	if !crypto.VerifyAdvert(advert) {
		pkt.MarkDoNotRetransmit()
		return
	}

	var advertID core.MeshCoreID
	copy(advertID[:], advert.PubKey[:])

	// BaseNode stores the contact before emitting, and the room handler reads
	// evt.Contact to sync routing into the client store.
	result := contact.ProcessAdvert(h.contacts, advert, h.clk.GetCurrentTime(), true)

	h.server.HandleAdvertReceived(&event.AdvertReceived{
		Event:   baseTestEvent(pkt, src, advertID),
		Advert:  advert,
		Contact: result.Contact,
		IsNew:   result.IsNew,
	})
}

func (h *testHarness) dispatchAnonReq(t *testing.T, pkt *codec.Packet, src transport.PacketSource) {
	t.Helper()

	anonPayload, err := codec.ParseAnonReqPayload(pkt.Payload)
	if err != nil {
		return
	}

	secret, err := crypto.ComputeSharedSecret(h.serverKey.PrivateKey, anonPayload.PubKey[:])
	if err != nil {
		return
	}
	plaintext, err := crypto.DecryptAddressedWithSecret(
		codec.PrependMAC(anonPayload.MAC, anonPayload.Ciphertext), secret)
	if err != nil {
		return
	}

	var senderID core.MeshCoreID
	copy(senderID[:], anonPayload.PubKey[:])

	h.server.HandleLogin(&event.AnonRequestReceived{
		Event:           baseTestEvent(pkt, src, senderID),
		Reply:           h.replyContext(pkt, senderID, secret),
		EphemeralPubKey: anonPayload.PubKey,
		Plaintext:       plaintext,
	})
}

// dispatchAddressed mirrors BaseNode.decryptAddressed: find the sender by source
// hash, decrypt with their shared secret, then emit the payload-specific event.
func (h *testHarness) dispatchAddressed(t *testing.T, pkt *codec.Packet, src transport.PacketSource) {
	t.Helper()

	addrPayload, err := codec.ParseAddressedPayload(pkt.Payload)
	if err != nil {
		return
	}

	for _, ct := range h.contacts.SearchByHash(addrPayload.SrcHash) {
		secret, err := h.contacts.GetSharedSecret(ct.ID)
		if err != nil {
			continue
		}
		plaintext, err := crypto.DecryptAddressedWithSecret(
			codec.PrependMAC(addrPayload.MAC, addrPayload.Ciphertext), secret)
		if err != nil {
			continue
		}

		reply := h.replyContextForContact(pkt, ct, secret)

		switch pkt.PayloadType() {
		case codec.PayloadTypeTxtMsg:
			content, err := codec.ParseTxtMsgContent(plaintext)
			if err != nil {
				return
			}
			// BaseNode auto-ACKs before emitting; the room server relies on that
			// and deliberately does not ACK posts itself (see HandleTextMessage).
			h.autoACK(ct, content, plaintext, reply)
			h.server.HandleTextMessage(&event.TextMessageReceived{
				Event:              baseTestEvent(pkt, src, ct.ID),
				Reply:              reply,
				Message:            content.Message,
				TxtType:            content.TxtType,
				Attempt:            content.Attempt,
				Timestamp:          content.Timestamp,
				SenderPubKeyPrefix: content.SenderPubKeyPrefix,
			})

		case codec.PayloadTypeReq:
			content, err := codec.ParseRequestContent(plaintext)
			if err != nil {
				return
			}
			h.server.HandleRequest(&event.RequestReceived{
				Event:       baseTestEvent(pkt, src, ct.ID),
				Reply:       reply,
				RequestType: content.RequestType,
				RequestData: content.RequestData,
				Tag:         content.Timestamp,
			})

		case codec.PayloadTypePath:
			content, err := codec.ParsePathContent(plaintext)
			if err != nil {
				return
			}
			h.server.HandlePath(&event.PathReceived{
				Event:      baseTestEvent(pkt, src, ct.ID),
				Reply:      reply,
				ReturnPath: content.Path,
				InnerType:  content.ExtraType,
				InnerData:  content.Extra,
			})
		}
		return
	}
}

// autoACK mirrors the auto-ACK block in BaseNode.handleTxtMsg.
func (h *testHarness) autoACK(ct *contact.ContactInfo, content *codec.TxtMsgContent, plaintext []byte, reply event.ReplyContext) {
	sender := &testSender{h: h}

	switch content.TxtType {
	case codec.TxtTypePlain:
		ackData := codec.TrimTxtMsgContent(plaintext, content)
		ackHash := crypto.ComputeAckHash(ackData, ct.ID[:])
		ackPayload := codec.BuildPlainTextAck(ackHash, plaintext, ackData)

		if len(reply.FloodPath) > 0 {
			_ = sender.sendPathReturn(reply, ct.ID, codec.PayloadTypeAck, ackPayload)
		} else {
			sender.SendACKPayload(ct.ID, ackPayload)
		}
	case codec.TxtTypeSigned:
		ackData := codec.TrimTxtMsgContent(plaintext, content)
		var selfID core.MeshCoreID
		copy(selfID[:], h.serverKey.PublicKey)
		ackHash := crypto.ComputeAckHash(ackData, selfID[:])
		sender.SendACKPayload(ct.ID, codec.BuildAckPayload(ackHash))
	}
}

func baseTestEvent(pkt *codec.Packet, src transport.PacketSource, from core.MeshCoreID) event.Event {
	return event.Event{
		From:      from,
		Timestamp: time.Now(),
		RawPacket: pkt,
		Source:    src,
	}
}

// replyContext builds a ReplyContext for a sender with no stored contact (anon
// login), mirroring the flood-path half of BaseNode.buildReplyContext.
func (h *testHarness) replyContext(pkt *codec.Packet, _ core.MeshCoreID, secret []byte) event.ReplyContext {
	reply := event.ReplyContext{
		SharedSecret:  secret,
		DirectPathLen: contact.PathUnknown,
	}
	if pkt.IsFlood() && pkt.HopCount() > 0 {
		reply.FloodPath = codec.ReverseFloodPath(pkt)
		reply.PathHashSize = pkt.PathHashSize
	}
	return reply
}

func (h *testHarness) replyContextForContact(pkt *codec.Packet, ct *contact.ContactInfo, secret []byte) event.ReplyContext {
	reply := event.ReplyContext{
		SharedSecret:  secret,
		DirectPathLen: ct.OutPathLen,
	}
	if ct.HasDirectPath() {
		reply.DirectPath = make([]byte, len(ct.OutPath))
		copy(reply.DirectPath, ct.OutPath)
	}
	if pkt.IsFlood() && pkt.HopCount() > 0 {
		reply.FloodPath = codec.ReverseFloodPath(pkt)
		reply.PathHashSize = pkt.PathHashSize
	}
	return reply
}

// testSender implements NodeSender the way BaseNode does, so responses reach the
// harness router (and its mock transport) instead of being silently dropped.
// Without a sender the room server's event path produces no output at all, which
// looks exactly like a behavior failure.
type testSender struct {
	h *testHarness
}

func (s *testSender) SendReply(reply event.ReplyContext, to core.MeshCoreID, payloadType uint8, plaintext []byte) error {
	if len(reply.FloodPath) > 0 {
		return s.sendPathReturn(reply, to, payloadType, plaintext)
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, reply.SharedSecret)
	if err != nil {
		return err
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), s.selfHash(), mac, ciphertext)
	pkt := codec.NewPacket(payloadType, codec.RouteTypeFlood, payload)

	if reply.DirectPathLen != contact.PathUnknown && len(reply.DirectPath) > 0 {
		s.h.router.SendDirect(pkt, reply.DirectPath)
	} else {
		s.h.router.SendFloodWithKey(pkt, reply.ReplyScope)
	}
	return nil
}

func (s *testSender) sendPathReturn(reply event.ReplyContext, to core.MeshCoreID, extraType uint8, plaintext []byte) error {
	hashSize := reply.PathHashSize
	if hashSize == 0 {
		hashSize = 1
	}
	pathContent := codec.BuildPathContent(reply.FloodPath, hashSize, extraType, plaintext)

	encrypted, err := crypto.EncryptAddressedWithSecret(pathContent, reply.SharedSecret)
	if err != nil {
		return err
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), s.selfHash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypePath, codec.RouteTypeFlood, payload)

	s.h.router.SendFloodPathWithKey(pkt, reply.ReplyScope)
	return nil
}

func (s *testSender) SendACK(to core.MeshCoreID, ackHash uint32) {
	s.SendACKPayload(to, codec.BuildAckPayload(ackHash))
}

func (s *testSender) SendACKPayload(to core.MeshCoreID, payload []byte) {
	pkt := codec.NewPacket(codec.PayloadTypeAck, codec.RouteTypeFlood, payload)
	if ct := s.h.contacts.GetByPubKey(to); ct != nil && ct.HasDirectPath() {
		s.h.router.SendDirect(pkt, ct.OutPath)
	} else {
		s.h.router.SendFloodScoped(pkt)
	}
}

func (s *testSender) SendToContact(to core.MeshCoreID, payloadType uint8, plaintext []byte) error {
	secret, err := s.h.contacts.GetSharedSecret(to)
	if err != nil {
		return err
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		return err
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), s.selfHash(), mac, ciphertext)
	pkt := codec.NewPacket(payloadType, codec.RouteTypeFlood, payload)

	if ct := s.h.contacts.GetByPubKey(to); ct != nil && ct.HasDirectPath() {
		s.h.router.SendDirect(pkt, ct.OutPath)
	} else {
		s.h.router.SendFloodScoped(pkt)
	}
	return nil
}

func (s *testSender) selfHash() uint8 {
	return core.MeshCoreID(s.h.server.cfg.PublicKey).Hash()
}

// --- Coverage for handlers the legacy path used to obscure ---

func TestHandlePath_SyncsClientRouting(t *testing.T) {
	h := newTestHarness(t)
	_, clientID := h.makeClientKeyAndContact(t)

	if _, err := h.clients.AddClient(&ClientInfo{Client: acl.Client{ID: clientID}}); err != nil {
		t.Fatal(err)
	}

	// BaseNode stores the learned path on the contact before emitting; the room
	// server mirrors it into the client store.
	ct := h.contacts.GetByPubKey(clientID)
	ct.OutPathLen = 2
	ct.OutPath = []byte{0xAA, 0xBB}

	h.server.HandlePath(&event.PathReceived{
		Event: event.Event{From: clientID},
	})

	client := h.clients.GetClient(clientID)
	if client.OutPathLen != 2 {
		t.Errorf("client OutPathLen = %d, want 2", client.OutPathLen)
	}
	if len(client.OutPath) != 2 || client.OutPath[0] != 0xAA {
		t.Errorf("client OutPath = %v, want [aa bb]", client.OutPath)
	}
}

func TestHandlePath_ResolvesPiggybackedACK(t *testing.T) {
	h := newTestHarness(t)
	_, clientID := h.makeClientKeyAndContact(t)

	resolved := false
	h.tracker.Track(0xCAFEBABE, ack.PendingACK{OnACK: func() { resolved = true }})

	h.server.HandlePath(&event.PathReceived{
		Event:     event.Event{From: clientID},
		InnerType: codec.PayloadTypeAck,
		InnerData: codec.BuildAckPayload(0xCAFEBABE),
	})

	if !resolved {
		t.Error("a PATH carrying an ACK should resolve the pending entry")
	}
}

func TestHandlePath_ClearsStalePathWhenContactHasNone(t *testing.T) {
	h := newTestHarness(t)
	_, clientID := h.makeClientKeyAndContact(t)

	if _, err := h.clients.AddClient(&ClientInfo{
		Client: acl.Client{ID: clientID, OutPathLen: 3, OutPath: []byte{1, 2, 3}},
	}); err != nil {
		t.Fatal(err)
	}

	// Contact has no direct path, so the client's stale one must be cleared.
	h.server.HandlePath(&event.PathReceived{Event: event.Event{From: clientID}})

	if client := h.clients.GetClient(clientID); client.OutPath != nil {
		t.Errorf("stale client OutPath should be cleared, got %v", client.OutPath)
	}
}

func TestHandleAdvertReceived_SyncsClientRouting(t *testing.T) {
	h := newTestHarness(t)
	_, clientID := h.makeClientKeyAndContact(t)

	if _, err := h.clients.AddClient(&ClientInfo{Client: acl.Client{ID: clientID}}); err != nil {
		t.Fatal(err)
	}

	ct := h.contacts.GetByPubKey(clientID)
	ct.OutPathLen = 1
	ct.OutPath = []byte{0x7F}

	h.server.HandleAdvertReceived(&event.AdvertReceived{
		Event:   event.Event{From: clientID},
		Contact: ct,
	})

	client := h.clients.GetClient(clientID)
	if client.OutPathLen != 1 || len(client.OutPath) != 1 || client.OutPath[0] != 0x7F {
		t.Errorf("client routing not synced from advert: len=%d path=%v",
			client.OutPathLen, client.OutPath)
	}
}

func TestHandleAdvertReceived_NilContactIgnored(t *testing.T) {
	h := newTestHarness(t)
	// Must not panic when the advert produced no stored contact.
	h.server.HandleAdvertReceived(&event.AdvertReceived{Event: event.Event{}})
}
