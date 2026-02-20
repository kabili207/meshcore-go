package room

import (
	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/transport"
)

// HandlePacket is the main packet dispatch entry point. It should be
// registered with the router via Router.SetPacketHandler.
func (s *Server) HandlePacket(pkt *codec.Packet, src transport.PacketSource) {
	switch pkt.PayloadType() {
	case codec.PayloadTypeAdvert:
		s.handleAdvert(pkt)
	case codec.PayloadTypeAnonReq:
		s.handleAnonReq(pkt)
	case codec.PayloadTypeAck:
		s.handleACK(pkt)
	case codec.PayloadTypeTxtMsg, codec.PayloadTypeReq, codec.PayloadTypePath:
		s.handleAddressed(pkt)
	default:
		s.log.Debug("unhandled payload type",
			"type", codec.PayloadTypeName(pkt.PayloadType()))
	}
}

// handleAdvert processes a received ADVERT via the contact store.
func (s *Server) handleAdvert(pkt *codec.Packet) {
	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		s.log.Debug("failed to parse advert", "error", err)
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	result := contact.ProcessAdvert(s.cfg.Contacts, advert, nowTS, true)
	if result.Rejected {
		s.log.Debug("advert rejected", "reason", result.RejectReason)
	}
}

// handleACK processes an incoming ACK packet by resolving it in the tracker.
func (s *Server) handleACK(pkt *codec.Packet) {
	if len(pkt.Payload) < codec.AckSize {
		return
	}
	ackPayload, err := codec.ParseAckPayload(pkt.Payload)
	if err != nil {
		return
	}
	if s.cfg.ACKTracker.Resolve(ackPayload.Checksum) {
		s.log.Debug("ack resolved", "hash", ackPayload.Checksum)
	}
}

// handleDecryptedPath processes an already-decrypted PATH payload.
// The sender identity has been resolved and the plaintext contains the
// PathContent: [path_len || path || extra_type || extra_data].
func (s *Server) handleDecryptedPath(_ *codec.Packet, senderID core.MeshCoreID, _ []byte, plaintext []byte) {
	pathContent, err := codec.ParsePathContent(plaintext)
	if err != nil {
		s.log.Debug("failed to parse path", "error", err)
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	ct, extraType, extraData, err := contact.ProcessPath(s.cfg.Contacts, senderID, pathContent, nowTS)
	if err != nil {
		s.log.Debug("failed to process path", "error", err)
		return
	}

	// Also update client's path if they're in the client store
	client := s.cfg.Clients.GetClient(ct.ID)
	if client != nil {
		client.OutPathLen = ct.OutPathLen
		if ct.OutPathLen >= 0 && len(ct.OutPath) > 0 {
			client.OutPath = make([]byte, len(ct.OutPath))
			copy(client.OutPath, ct.OutPath)
		} else {
			client.OutPath = nil
		}
	}

	// Handle piggybacked extra
	if extraType == codec.PayloadTypeAck && len(extraData) >= 4 {
		ackPayload, err := codec.ParseAckPayload(extraData)
		if err == nil {
			s.cfg.ACKTracker.Resolve(ackPayload.Checksum)
		}
	}
}

// handleAddressed processes an addressed (encrypted) packet from a known client.
func (s *Server) handleAddressed(pkt *codec.Packet) {
	if len(pkt.Payload) < codec.AddressedHeaderSize {
		return
	}

	addrPayload, err := codec.ParseAddressedPayload(pkt.Payload)
	if err != nil {
		s.log.Debug("failed to parse addressed payload", "error", err)
		return
	}

	// Search contacts by source hash for the sender identity
	contactCandidates := s.cfg.Contacts.SearchByHash(addrPayload.SrcHash)
	if len(contactCandidates) == 0 {
		s.log.Debug("unknown sender hash", "hash", addrPayload.SrcHash)
		return
	}

	// Try decrypting with each candidate's shared secret
	for _, ct := range contactCandidates {
		secret, err := s.cfg.Contacts.GetSharedSecret(ct.ID)
		if err != nil {
			continue
		}

		plaintext, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addrPayload.MAC, addrPayload.Ciphertext), secret)
		if err != nil {
			continue
		}

		// Decryption succeeded — this is the sender
		// PATH packets don't require the sender to be a client
		if pkt.PayloadType() == codec.PayloadTypePath {
			s.handleDecryptedPath(pkt, ct.ID, secret, plaintext)
			return
		}

		client := s.cfg.Clients.GetClient(ct.ID)
		if client == nil {
			s.log.Debug("addressed from non-client", "peer", ct.ID.String())
			return
		}

		nowTS := s.cfg.Clock.GetCurrentTime()
		client.LastActivity = nowTS

		switch pkt.PayloadType() {
		case codec.PayloadTypeTxtMsg:
			s.handleTextMessage(pkt, client, ct.ID, secret, plaintext)
		case codec.PayloadTypeReq:
			s.handleRequest(pkt, client, ct.ID, secret, plaintext)
		}
		return
	}

	s.log.Debug("could not decrypt addressed payload")
}

// handleTextMessage processes a decrypted text message from a client.
func (s *Server) handleTextMessage(pkt *codec.Packet, client *ClientInfo, senderID core.MeshCoreID, secret, plaintext []byte) {
	if len(plaintext) < 5 {
		return
	}

	content, err := codec.ParseTxtMsgContent(plaintext)
	if err != nil {
		s.log.Debug("failed to parse txt msg", "error", err)
		return
	}

	// Replay check
	if content.Timestamp <= client.LastTimestamp {
		s.log.Debug("txt replay", "peer", senderID.String())
		return
	}
	client.LastTimestamp = content.Timestamp
	client.PushFailures = 0

	// Compute ACK hash using the unpadded content length. The decrypted
	// plaintext may have trailing zero bytes from AES-128 ECB block padding,
	// but the firmware computes the ACK hash using header + strlen(text),
	// which excludes padding. We must match that to produce a valid ACK.
	ackData := trimTxtMsgContent(plaintext, content)
	ackHash := crypto.ComputeAckHash(ackData, senderID[:])

	switch content.TxtType {
	case codec.TxtTypePlain:
		if !client.CanWrite() {
			// Guests can't post — but still send ACK? Firmware doesn't for guests
			if client.IsGuest() {
				return
			}
		}

		// Store the post (use unpadded content so sync ACK hashes match)
		nowTS := s.cfg.Clock.GetCurrentTimeUnique()
		_ = s.cfg.Posts.AddPost(&PostInfo{
			Timestamp: nowTS,
			SenderID:  senderID,
			Content:   ackData,
		})
		if s.cfg.PostCounter != nil {
			s.cfg.PostCounter.IncrementPosted()
		}

		s.log.Debug("post stored",
			"sender", senderID.String(),
			"timestamp", nowTS)

		// Send ACK back (plain text only — firmware doesn't ACK CLI commands)
		s.sendACK(pkt, senderID, secret, ackHash)

	case codec.TxtTypeCLI:
		// CLI commands — admin only, reply instead of ACK
		if !client.IsAdmin() {
			return
		}
		s.handleCLICommand(pkt, senderID, secret, content)
	}
}

// handleRequest processes a decrypted REQ from a client.
func (s *Server) handleRequest(pkt *codec.Packet, client *ClientInfo, senderID core.MeshCoreID, secret, plaintext []byte) {
	if len(plaintext) < 5 {
		return
	}

	content, err := codec.ParseRequestContent(plaintext)
	if err != nil {
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	client.LastActivity = nowTS

	// The request's timestamp is reflected back as the response tag.
	tag := content.Timestamp

	switch content.RequestType {
	case codec.ReqTypeKeepalive:
		s.log.Debug("keepalive", "peer", senderID.String())
		ackData := trimRequestContent(plaintext, content)
		ackHash := crypto.ComputeAckHash(ackData, senderID[:])
		s.sendACK(pkt, senderID, secret, ackHash)

	case codec.ReqTypeGetStats:
		s.log.Debug("get_status", "peer", senderID.String())
		s.handleGetStatus(pkt, tag, senderID, secret)

	case codec.ReqTypeGetTelemetry:
		s.log.Debug("get_telemetry", "peer", senderID.String())
		s.handleGetTelemetry(pkt, tag, client, senderID, secret, content.RequestData)

	case codec.ReqTypeGetAccessList:
		s.log.Debug("get_access_list", "peer", senderID.String())
		s.handleGetAccessList(pkt, tag, client, senderID, secret, content.RequestData)

	default:
		s.log.Debug("unhandled request type",
			"type", codec.RequestTypeName(content.RequestType),
			"peer", senderID.String())
	}
}

// sendACK sends an ACK packet back to the sender.
func (s *Server) sendACK(origPkt *codec.Packet, recipientID core.MeshCoreID, secret []byte, ackHash uint32) {
	ackPayloadBytes := codec.BuildAckPayload(ackHash)

	ackPkt := &codec.Packet{
		Header:  codec.PayloadTypeAck << codec.PHTypeShift,
		Payload: ackPayloadBytes,
	}

	// Send direct if we have a path, otherwise flood
	ct := s.cfg.Contacts.GetByPubKey(recipientID)
	if ct != nil && ct.HasDirectPath() {
		s.cfg.Router.SendDirect(ackPkt, ct.OutPath[:ct.OutPathLen])
	} else {
		s.cfg.Router.SendFlood(ackPkt)
	}
}
