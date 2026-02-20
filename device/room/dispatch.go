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
	case codec.PayloadTypePath:
		s.handlePath(pkt)
	case codec.PayloadTypeTxtMsg, codec.PayloadTypeReq:
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

// handlePath processes a PATH packet — updates the contact's routing path
// and handles any piggybacked extra (ACK or RESPONSE).
func (s *Server) handlePath(pkt *codec.Packet) {
	pathContent, err := codec.ParsePathContent(pkt.Payload)
	if err != nil {
		s.log.Debug("failed to parse path", "error", err)
		return
	}

	// Determine sender from the path itself (first byte = sender hash)
	// The full sender ID is resolved via the contact store.
	if pathContent.PathLen == 0 {
		return
	}
	senderHash := pathContent.Path[0]
	contacts := s.cfg.Contacts.SearchByHash(senderHash)
	if len(contacts) == 0 {
		return
	}

	// Try each matching contact (hash collisions are possible)
	nowTS := s.cfg.Clock.GetCurrentTime()
	for _, c := range contacts {
		ct, extraType, extraData, err := contact.ProcessPath(s.cfg.Contacts, c.ID, pathContent, nowTS)
		if err != nil {
			continue
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
		break
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

	// Compute ACK hash for this message
	ackHash := crypto.ComputeAckHash(plaintext, senderID[:])

	txtType := content.TxtType >> 2 // upper 6 bits

	switch txtType {
	case codec.TxtTypePlain:
		if !client.CanWrite() {
			// Guests can't post — but still send ACK? Firmware doesn't for guests
			if client.IsGuest() {
				return
			}
		}

		// Store the post
		nowTS := s.cfg.Clock.GetCurrentTimeUnique()
		_ = s.cfg.Posts.AddPost(&PostInfo{
			Timestamp: nowTS,
			SenderID:  senderID,
			Content:   plaintext,
		})

		s.log.Debug("post stored",
			"sender", senderID.String(),
			"timestamp", nowTS)

	case codec.TxtTypeCLI:
		// CLI commands — admin only
		if !client.IsAdmin() {
			return
		}
		// TODO: handle CLI commands in a future tier
	}

	// Send ACK back
	s.sendACK(pkt, senderID, secret, ackHash)
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
		ackHash := crypto.ComputeAckHash(plaintext, senderID[:])
		s.sendACK(pkt, senderID, secret, ackHash)

	case codec.ReqTypeGetStats:
		s.log.Debug("get_status", "peer", senderID.String())
		s.handleGetStatus(tag, senderID, secret)

	case codec.ReqTypeGetTelemetry:
		s.log.Debug("get_telemetry", "peer", senderID.String())
		s.handleGetTelemetry(tag, client, senderID, secret, content.RequestData)

	case codec.ReqTypeGetAccessList:
		s.log.Debug("get_access_list", "peer", senderID.String())
		s.handleGetAccessList(tag, client, senderID, secret, content.RequestData)

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
