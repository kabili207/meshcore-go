package room

import (
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
)

// HandleLogin processes a login attempt from a decrypted AnonRequestReceived
// event. This is the event-based equivalent of handleAnonReq.
func (s *Server) HandleLogin(evt *event.AnonRequestReceived) {
	if len(evt.Plaintext) < loginDataMinSize {
		s.log.Debug("anon req too short", "len", len(evt.Plaintext))
		return
	}

	senderTimestamp := binary.LittleEndian.Uint32(evt.Plaintext[0:4])
	senderSyncSince := binary.LittleEndian.Uint32(evt.Plaintext[4:8])
	password := extractNullTerminated(evt.Plaintext[8:])

	senderID := evt.From

	existingClient := s.cfg.Clients.GetClient(senderID)

	perm := s.resolvePermissions(existingClient, password)
	if perm < 0 {
		s.log.Debug("login rejected (no matching password)", "peer", senderID.String())
		return
	}

	var client *ClientInfo
	var err error
	if existingClient != nil {
		if senderTimestamp <= existingClient.LastTimestamp {
			s.log.Debug("login replay", "peer", senderID.String())
			return
		}
		client = existingClient
	} else {
		client, err = s.cfg.Clients.AddClient(&ClientInfo{
			ID: senderID,
		})
		if err != nil {
			s.log.Warn("failed to add client", "error", err)
			return
		}
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	client.LastTimestamp = senderTimestamp
	client.SyncSince = senderSyncSince
	client.PushFailures = 0
	client.LastActivity = nowTS
	client.Permissions = uint8(perm)

	// Ensure the client exists in the contact store
	if s.cfg.Contacts.GetByPubKey(senderID) == nil {
		s.cfg.Contacts.AddContact(&contact.ContactInfo{
			ID:         senderID,
			OutPathLen: contact.PathUnknown,
			LastMod:    nowTS,
		})
	}

	s.log.Info("client logged in",
		"peer", senderID.String(),
		"perms", perm,
		"sync_since", senderSyncSince)

	// Build and send login response
	s.sendLoginResponseEvent(evt.Reply, senderID, uint8(perm), nowTS)
}

// sendLoginResponseEvent sends a login OK response using the event-based sender.
func (s *Server) sendLoginResponseEvent(reply event.ReplyContext, recipientID core.MeshCoreID, perms uint8, nowTS uint32) {
	resp := make([]byte, loginResponseSize)
	binary.LittleEndian.PutUint32(resp[0:4], nowTS)
	resp[4] = codec.RespServerLoginOK
	resp[5] = 0

	switch perms & codec.PermACLRoleMask {
	case codec.PermACLAdmin:
		resp[6] = 1
	case codec.PermACLGuest, codec.PermACLReadOnly:
		resp[6] = 2
	default:
		resp[6] = 0
	}

	resp[7] = perms
	resp[12] = FirmwareVersion

	if s.sender != nil {
		if err := s.sender.SendReply(reply, recipientID, codec.PayloadTypeResponse, resp); err != nil {
			s.log.Warn("failed to send login response", "error", err)
		}
	}
	s.log.Debug("sent login response", "peer", recipientID.String())
}

// HandleTextMessage processes a decrypted text message event from a client.
// This is the event-based equivalent of handleTextMessage.
func (s *Server) HandleTextMessage(evt *event.TextMessageReceived) {
	senderID := evt.From

	client := s.cfg.Clients.GetClient(senderID)
	if client == nil {
		s.log.Debug("addressed from non-client", "peer", senderID.String())
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	client.LastActivity = nowTS

	// Replay check — the event's timestamp is from the parsed content
	// We need to parse the raw packet content for the timestamp
	// since the event only carries the text message string.
	// The BaseNode has already parsed the content, but we need the sender
	// timestamp for replay protection.
	//
	// For the event-based flow, the event carries the message text but
	// the room server needs to do its own replay check using the raw
	// packet timestamp. Since the event doesn't expose the raw timestamp,
	// we use the RawPacket if available, or trust the event (BaseNode
	// already verified decryption).
	//
	// TODO: Consider adding Timestamp to TextMessageReceived event.

	switch evt.TxtType {
	case codec.TxtTypePlain:
		if !client.CanWrite() {
			if client.IsGuest() {
				return
			}
		}

		// Store the post
		postNowTS := s.cfg.Clock.GetCurrentTimeUnique()
		// Build content for ACK hash computation and storage.
		// The event carries the message string; we reconstruct the content
		// for storage using the same format the firmware expects.
		content := codec.BuildTxtMsgContent(postNowTS, codec.TxtTypePlain, 0, evt.Message, nil)
		ackData := codec.TrimTxtMsgContent(content, &codec.TxtMsgContent{
			TxtType: codec.TxtTypePlain,
			Message: evt.Message,
		})

		_ = s.cfg.Posts.AddPost(&PostInfo{
			Timestamp: postNowTS,
			SenderID:  senderID,
			Content:   ackData,
		})
		if s.cfg.PostCounter != nil {
			s.cfg.PostCounter.IncrementPosted()
		}

		s.log.Debug("post stored",
			"sender", senderID.String(),
			"timestamp", postNowTS)

		// Note: ACK is already sent by BaseNode's auto-ACK for TxtTypePlain.
		// The room server does NOT need to send ACK separately.

	case codec.TxtTypeCLI:
		if !client.IsAdmin() {
			return
		}
		s.handleCLICommandEvent(evt.Reply, senderID, evt.Message)
	}
}

// handleCLICommandEvent processes a CLI command and sends the reply via the event-based sender.
func (s *Server) handleCLICommandEvent(reply event.ReplyContext, senderID core.MeshCoreID, cmd string) {
	// Strip optional companion radio prefix
	prefix := ""
	if len(cmd) > 4 && cmd[2] == '|' {
		prefix = cmd[:3]
		cmd = cmd[3:]
	}

	s.log.Debug("cli command",
		"peer", senderID.String(),
		"cmd", cmd)

	replyText := s.executeCLI(cmd)
	if replyText == "" {
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	content := codec.BuildTxtMsgContent(nowTS, codec.TxtTypeCLI, 0, prefix+replyText, nil)

	if s.sender != nil {
		if err := s.sender.SendReply(reply, senderID, codec.PayloadTypeTxtMsg, content); err != nil {
			s.log.Warn("failed to send CLI reply", "error", err)
		}
	}
}

// HandleRequest processes a decrypted request event from a client.
// This is the event-based equivalent of handleRequest.
func (s *Server) HandleRequest(evt *event.RequestReceived) {
	senderID := evt.From

	client := s.cfg.Clients.GetClient(senderID)
	if client == nil {
		s.log.Debug("request from non-client", "peer", senderID.String())
		return
	}

	nowTS := s.cfg.Clock.GetCurrentTime()
	client.LastActivity = nowTS

	tag := evt.Tag

	switch evt.RequestType {
	case codec.ReqTypeKeepalive:
		s.log.Debug("keepalive", "peer", senderID.String())
		// For keepalive, compute ACK hash from the raw request content.
		// Since the event doesn't carry raw plaintext, we reconstruct
		// the request content to compute the hash.
		reqContent := codec.BuildRequestContent(tag, codec.ReqTypeKeepalive, nil)
		ackData := codec.TrimRequestContent(reqContent, &codec.RequestContent{
			RequestType: codec.ReqTypeKeepalive,
		})
		ackHash := crypto.ComputeAckHash(ackData, senderID[:])
		if s.sender != nil {
			s.sender.SendACK(senderID, ackHash)
		}

	case codec.ReqTypeGetStats:
		s.log.Debug("get_status", "peer", senderID.String())
		s.handleGetStatusEvent(evt.Reply, tag, senderID)

	case codec.ReqTypeGetTelemetry:
		s.log.Debug("get_telemetry", "peer", senderID.String())
		s.handleGetTelemetryEvent(evt.Reply, tag, client, senderID, evt.RequestData)

	case codec.ReqTypeGetAccessList:
		s.log.Debug("get_access_list", "peer", senderID.String())
		s.handleGetAccessListEvent(evt.Reply, tag, client, senderID, evt.RequestData)

	default:
		s.log.Debug("unhandled request type",
			"type", codec.RequestTypeName(evt.RequestType),
			"peer", senderID.String())
	}
}

// handleGetStatusEvent handles GET_STATUS using the event-based sender.
func (s *Server) handleGetStatusEvent(reply event.ReplyContext, tag uint32, senderID core.MeshCoreID) {
	if s.cfg.Stats == nil {
		return
	}

	stats := s.cfg.Stats.GetStats()
	statsBytes := stats.MarshalBinary()

	resp := make([]byte, 4+ServerStatsSize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], statsBytes)

	if s.sender != nil {
		s.sender.SendReply(reply, senderID, codec.PayloadTypeResponse, resp)
	}
}

// handleGetTelemetryEvent handles GET_TELEMETRY using the event-based sender.
func (s *Server) handleGetTelemetryEvent(reply event.ReplyContext, tag uint32, client *ClientInfo, senderID core.MeshCoreID, requestData []byte) {
	if s.cfg.Telemetry == nil {
		return
	}

	var permMask uint8
	if len(requestData) > 0 {
		permMask = ^requestData[0]
	}

	if client.IsGuest() {
		permMask = 0x00
	}

	telemetryData := s.cfg.Telemetry.GetTelemetry(permMask)

	resp := make([]byte, 4+len(telemetryData))
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], telemetryData)

	if s.sender != nil {
		s.sender.SendReply(reply, senderID, codec.PayloadTypeResponse, resp)
	}
}

// handleGetAccessListEvent handles GET_ACCESS_LIST using the event-based sender.
func (s *Server) handleGetAccessListEvent(reply event.ReplyContext, tag uint32, client *ClientInfo, senderID core.MeshCoreID, requestData []byte) {
	if !client.IsAdmin() {
		return
	}

	if len(requestData) >= 2 && (requestData[0] != 0 || requestData[1] != 0) {
		return
	}

	resp := make([]byte, 4, maxReplySize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)

	s.cfg.Clients.ForEach(func(c *ClientInfo) bool {
		if !c.IsAdmin() {
			return true
		}
		if len(resp)+aclEntrySize > maxReplySize {
			return false
		}
		entry := make([]byte, aclEntrySize)
		copy(entry[0:aclPrefixSize], c.ID[:aclPrefixSize])
		entry[aclPrefixSize] = c.Permissions
		resp = append(resp, entry...)
		return true
	})

	if s.sender != nil {
		s.sender.SendReply(reply, senderID, codec.PayloadTypeResponse, resp)
	}
}

// HandlePath processes a decrypted PATH event. Updates client routing
// info and handles piggybacked ACKs.
func (s *Server) HandlePath(evt *event.PathReceived) {
	senderID := evt.From

	// Update client's path if they're in the client store
	ct := s.cfg.Contacts.GetByPubKey(senderID)
	if ct != nil {
		client := s.cfg.Clients.GetClient(senderID)
		if client != nil {
			client.OutPathLen = ct.OutPathLen
			if ct.OutPathLen >= 0 && len(ct.OutPath) > 0 {
				client.OutPath = make([]byte, len(ct.OutPath))
				copy(client.OutPath, ct.OutPath)
			} else {
				client.OutPath = nil
			}
		}
	}

	// Handle piggybacked ACK (already handled by BaseNode's PATH unwrapping,
	// but for PATH packets with unknown inner types we handle here)
	if evt.InnerType == codec.PayloadTypeAck && len(evt.InnerData) >= 4 {
		ackPayload, err := codec.ParseAckPayload(evt.InnerData)
		if err == nil && s.cfg.ACKTracker != nil {
			s.cfg.ACKTracker.Resolve(ackPayload.Checksum)
		}
	}
}

// HandleAdvertReceived processes an advert event. Updates client routing
// info if the advertiser is a known client.
func (s *Server) HandleAdvertReceived(evt *event.AdvertReceived) {
	// Contact update is already handled by BaseNode.
	// Room server only needs to sync routing info to client store.
	if evt.Contact == nil {
		return
	}

	client := s.cfg.Clients.GetClient(evt.Contact.ID)
	if client != nil {
		client.OutPathLen = evt.Contact.OutPathLen
		if evt.Contact.OutPathLen >= 0 && len(evt.Contact.OutPath) > 0 {
			client.OutPath = make([]byte, len(evt.Contact.OutPath))
			copy(client.OutPath, evt.Contact.OutPath)
		} else {
			client.OutPath = nil
		}
	}
}
