package node

import (
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// processPacket is the main dispatch pipeline. It is registered as the
// router's PacketHandler and converts raw packets into typed events.
func (b *BaseNode) processPacket(pkt *codec.Packet, src transport.PacketSource) {
	switch pkt.PayloadType() {
	case codec.PayloadTypeAdvert:
		b.handleAdvert(pkt, src)
	case codec.PayloadTypeTxtMsg:
		b.handleTxtMsg(pkt, src)
	case codec.PayloadTypeAck:
		b.handleAck(pkt, src)
	case codec.PayloadTypeAnonReq:
		b.handleAnonReq(pkt, src)
	case codec.PayloadTypeReq:
		b.handleReq(pkt, src)
	case codec.PayloadTypeResponse:
		b.handleResponse(pkt, src)
	case codec.PayloadTypePath:
		b.handlePath(pkt, src)
	case codec.PayloadTypeGrpTxt:
		b.handleGrpTxt(pkt, src)
	case codec.PayloadTypeGrpData:
		b.handleGrpData(pkt, src)
	default:
		b.emitEvent(&event.PacketReceived{
			Event: b.baseEvent(pkt, src, core.MeshCoreID{}),
		})
	}
}

// baseEvent constructs the common Event fields.
func (b *BaseNode) baseEvent(pkt *codec.Packet, src transport.PacketSource, from core.MeshCoreID) event.Event {
	return event.Event{
		From:      from,
		Timestamp: time.Now(),
		RawPacket: pkt,
		Source:    src,
	}
}

// handleAdvert processes an ADVERT packet: verify signature, update contacts,
// extract flood path, then emit AdvertReceived.
func (b *BaseNode) handleAdvert(pkt *codec.Packet, src transport.PacketSource) {
	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		b.log.Debug("failed to parse advert", "error", err)
		return
	}

	var advertID core.MeshCoreID
	copy(advertID[:], advert.PubKey[:])

	if b.autoUpdateContacts {
		nowTS := b.clock.GetCurrentTime()
		result := contact.ProcessAdvert(b.contacts, advert, nowTS, true)
		if result.Rejected {
			b.log.Debug("advert rejected", "reason", result.RejectReason)
			return
		}

		// Update path from flood route if available
		if result.Contact != nil {
			b.updateContactPathFromFlood(pkt, result.Contact)
		}

		b.emitEvent(&event.AdvertReceived{
			Event:   b.baseEvent(pkt, src, advertID),
			Advert:  advert,
			Contact: result.Contact,
			IsNew:   result.IsNew,
		})
	} else {
		// Even without auto-update, still emit the event
		b.emitEvent(&event.AdvertReceived{
			Event:  b.baseEvent(pkt, src, advertID),
			Advert: advert,
		})
	}
}

// handleTxtMsg processes an addressed TXT_MSG packet: find sender, decrypt,
// parse content, auto-ACK, update contact path, then emit TextMessageReceived.
func (b *BaseNode) handleTxtMsg(pkt *codec.Packet, src transport.PacketSource) {
	ct, secret, plaintext := b.decryptAddressed(pkt)
	if ct == nil {
		return
	}

	content, err := codec.ParseTxtMsgContent(plaintext)
	if err != nil {
		b.log.Debug("failed to parse txt msg", "error", err)
		return
	}

	// Update contact path from flood route
	b.updateContactPathFromFlood(pkt, ct)

	// Auto-ACK before emitting event (matches firmware behavior)
	if b.autoACK && content.TxtType == codec.TxtTypePlain {
		ackData := codec.TrimTxtMsgContent(plaintext, content)
		ackHash := crypto.ComputeAckHash(ackData, ct.ID[:])
		b.sendACK(ct.ID, ackHash)
	}

	reply := b.buildReplyContext(pkt, ct, secret)

	b.emitEvent(&event.TextMessageReceived{
		Event:              b.baseEvent(pkt, src, ct.ID),
		Reply:              reply,
		Message:            content.Message,
		TxtType:            content.TxtType,
		Attempt:            content.Attempt,
		SenderPubKeyPrefix: content.SenderPubKeyPrefix,
	})
}

// handleAck processes an ACK packet: resolve in tracker, then emit AckReceived.
func (b *BaseNode) handleAck(pkt *codec.Packet, src transport.PacketSource) {
	if len(pkt.Payload) < codec.AckSize {
		return
	}
	ackPayload, err := codec.ParseAckPayload(pkt.Payload)
	if err != nil {
		return
	}

	// Resolve pending ACK if tracker is configured
	if b.ack != nil {
		b.ack.Resolve(ackPayload.Checksum)
	}

	b.emitEvent(&event.AckReceived{
		Event:    b.baseEvent(pkt, src, core.MeshCoreID{}),
		Checksum: ackPayload.Checksum,
	})
}

// handleAnonReq processes an ANON_REQ packet: decrypt with ephemeral key,
// then emit AnonRequestReceived.
func (b *BaseNode) handleAnonReq(pkt *codec.Packet, src transport.PacketSource) {
	anonPayload, err := codec.ParseAnonReqPayload(pkt.Payload)
	if err != nil {
		b.log.Debug("failed to parse anon req", "error", err)
		return
	}

	// Decrypt using our private key and the sender's ephemeral public key
	plaintext, err := crypto.DecryptAnonymous(
		codec.PrependMAC(anonPayload.MAC, anonPayload.Ciphertext),
		b.privateKey,
		anonPayload.PubKey[:],
	)
	if err != nil {
		b.log.Debug("failed to decrypt anon req", "error", err)
		return
	}

	// Compute shared secret for reply encryption
	secret, err := crypto.ComputeSharedSecret(b.privateKey, anonPayload.PubKey[:])
	if err != nil {
		b.log.Debug("failed to compute shared secret for anon req", "error", err)
		return
	}

	var senderID core.MeshCoreID
	copy(senderID[:], anonPayload.PubKey[:])

	reply := event.ReplyContext{
		SharedSecret:  secret,
		DirectPathLen: contact.PathUnknown,
	}
	if pkt.IsFlood() && pkt.PathLen > 0 {
		reply.FloodPath = codec.ReverseFloodPath(pkt)
	}

	b.emitEvent(&event.AnonRequestReceived{
		Event:           b.baseEvent(pkt, src, senderID),
		Reply:           reply,
		EphemeralPubKey: anonPayload.PubKey,
		Plaintext:       plaintext,
	})
}

// handleReq processes an addressed REQ packet: decrypt, parse request header,
// then emit RequestReceived.
func (b *BaseNode) handleReq(pkt *codec.Packet, src transport.PacketSource) {
	ct, secret, plaintext := b.decryptAddressed(pkt)
	if ct == nil {
		return
	}

	content, err := codec.ParseRequestContent(plaintext)
	if err != nil {
		b.log.Debug("failed to parse request", "error", err)
		return
	}

	// Update contact path from flood route
	b.updateContactPathFromFlood(pkt, ct)

	reply := b.buildReplyContext(pkt, ct, secret)

	b.emitEvent(&event.RequestReceived{
		Event:       b.baseEvent(pkt, src, ct.ID),
		Reply:       reply,
		RequestType: content.RequestType,
		RequestData: content.RequestData,
		Tag:         content.Timestamp,
	})
}

// handleResponse processes an addressed RESPONSE packet: decrypt, parse
// response header, then emit ResponseReceived.
func (b *BaseNode) handleResponse(pkt *codec.Packet, src transport.PacketSource) {
	ct, secret, plaintext := b.decryptAddressed(pkt)
	if ct == nil {
		return
	}

	content, err := codec.ParseResponseContent(plaintext)
	if err != nil {
		b.log.Debug("failed to parse response", "error", err)
		return
	}

	// Update contact path from flood route
	b.updateContactPathFromFlood(pkt, ct)

	reply := b.buildReplyContext(pkt, ct, secret)

	b.emitEvent(&event.ResponseReceived{
		Event:   b.baseEvent(pkt, src, ct.ID),
		Reply:   reply,
		Tag:     content.Tag,
		Content: content.Content,
	})
}

// handlePath processes an addressed PATH packet: decrypt, update contact
// routing, then emit inner event (for known types) or PathReceived.
func (b *BaseNode) handlePath(pkt *codec.Packet, src transport.PacketSource) {
	ct, secret, plaintext := b.decryptAddressed(pkt)
	if ct == nil {
		return
	}

	pathContent, err := codec.ParsePathContent(plaintext)
	if err != nil {
		b.log.Debug("failed to parse path", "error", err)
		return
	}

	// Update contact's direct routing path from PATH content
	nowTS := b.clock.GetCurrentTime()
	contact.ProcessPath(b.contacts, ct.ID, pathContent, nowTS)

	reply := b.buildReplyContext(pkt, ct, secret)

	// Unwrap known inner types into their own events
	switch pathContent.ExtraType {
	case codec.PayloadTypeAck:
		if len(pathContent.Extra) >= codec.AckSize {
			ackPayload, err := codec.ParseAckPayload(pathContent.Extra)
			if err == nil {
				if b.ack != nil {
					b.ack.Resolve(ackPayload.Checksum)
				}
				b.emitEvent(&event.AckReceived{
					Event:    b.baseEvent(pkt, src, ct.ID),
					Checksum: ackPayload.Checksum,
				})
				return
			}
		}

	case codec.PayloadTypeResponse:
		if len(pathContent.Extra) >= 4 {
			respContent, err := codec.ParseResponseContent(pathContent.Extra)
			if err == nil {
				b.emitEvent(&event.ResponseReceived{
					Event:   b.baseEvent(pkt, src, ct.ID),
					Reply:   reply,
					Tag:     respContent.Tag,
					Content: respContent.Content,
				})
				return
			}
		}
	}

	// Unknown inner type — emit PathReceived
	b.emitEvent(&event.PathReceived{
		Event:      b.baseEvent(pkt, src, ct.ID),
		Reply:      reply,
		ReturnPath: pathContent.Path,
		InnerType:  pathContent.ExtraType,
		InnerData:  pathContent.Extra,
	})
}

// handleGrpTxt processes a group text message.
func (b *BaseNode) handleGrpTxt(pkt *codec.Packet, src transport.PacketSource) {
	grp, err := codec.ParseGroupPayload(pkt.Payload)
	if err != nil {
		b.log.Debug("failed to parse group text", "error", err)
		return
	}

	// TODO: group decryption using channel shared key
	// For now, emit with the raw ciphertext info
	b.emitEvent(&event.GroupTextReceived{
		Event:       b.baseEvent(pkt, src, core.MeshCoreID{}),
		ChannelHash: grp.ChannelHash,
		Message:     string(grp.Ciphertext), // Placeholder until group crypto is implemented
	})
}

// handleGrpData processes a group datagram.
func (b *BaseNode) handleGrpData(pkt *codec.Packet, src transport.PacketSource) {
	grp, err := codec.ParseGroupPayload(pkt.Payload)
	if err != nil {
		b.log.Debug("failed to parse group data", "error", err)
		return
	}

	// TODO: group decryption using channel shared key
	b.emitEvent(&event.GroupDataReceived{
		Event:       b.baseEvent(pkt, src, core.MeshCoreID{}),
		ChannelHash: grp.ChannelHash,
		Data:        grp.Ciphertext, // Placeholder until group crypto is implemented
	})
}

// decryptAddressed handles the common addressed packet decryption flow:
// parse addressed header, search contacts by source hash, try decrypting
// with each candidate's shared secret. Returns the matching contact,
// shared secret, and decrypted plaintext, or nil if decryption fails.
func (b *BaseNode) decryptAddressed(pkt *codec.Packet) (*contact.ContactInfo, []byte, []byte) {
	if len(pkt.Payload) < codec.AddressedHeaderSize {
		return nil, nil, nil
	}

	addrPayload, err := codec.ParseAddressedPayload(pkt.Payload)
	if err != nil {
		b.log.Debug("failed to parse addressed payload", "error", err)
		return nil, nil, nil
	}

	candidates := b.contacts.SearchByHash(addrPayload.SrcHash)
	if len(candidates) == 0 {
		b.log.Debug("unknown sender hash", "hash", addrPayload.SrcHash)
		return nil, nil, nil
	}

	for _, ct := range candidates {
		secret, err := b.contacts.GetSharedSecret(ct.ID)
		if err != nil {
			continue
		}

		plaintext, err := crypto.DecryptAddressedWithSecret(
			codec.PrependMAC(addrPayload.MAC, addrPayload.Ciphertext),
			secret,
		)
		if err != nil {
			continue
		}

		return ct, secret, plaintext
	}

	b.log.Debug("could not decrypt addressed payload")
	return nil, nil, nil
}
