package room

import (
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
)

const (
	// loginDataMinSize is the minimum decrypted ANON_REQ data size for login:
	// timestamp(4) + sync_since(4) + password(at least 1 null byte).
	loginDataMinSize = 9

	// loginResponseSize is the size of the login response content.
	// timestamp(4) + resp_type(1) + legacy(1) + admin_flag(1) + perms(1) + random(4) + version(1)
	loginResponseSize = 13

	// FirmwareVersion is the protocol version reported in login responses.
	FirmwareVersion = 0x01
)

// handleAnonReq processes an ANON_REQ packet (login attempt).
func (s *Server) handleAnonReq(pkt *codec.Packet) {
	anonPayload, err := codec.ParseAnonReqPayload(pkt.Payload)
	if err != nil {
		s.log.Debug("failed to parse anon req", "error", err)
		return
	}

	// Decrypt using our private key and the sender's ephemeral public key.
	// The MAC lives in the parsed header; re-prepend it for decryption.
	plaintext, err := crypto.DecryptAnonymous(
		codec.PrependMAC(anonPayload.MAC, anonPayload.Ciphertext),
		s.cfg.PrivateKey,
		anonPayload.PubKey[:],
	)
	if err != nil {
		s.log.Debug("failed to decrypt anon req", "error", err)
		return
	}

	if len(plaintext) < loginDataMinSize {
		s.log.Debug("anon req too short", "len", len(plaintext))
		return
	}

	// Parse login data
	senderTimestamp := binary.LittleEndian.Uint32(plaintext[0:4])
	senderSyncSince := binary.LittleEndian.Uint32(plaintext[4:8])
	password := extractNullTerminated(plaintext[8:])

	// Compute shared secret with the ephemeral key for response encryption
	secret, err := crypto.ComputeSharedSecret(s.cfg.PrivateKey, anonPayload.PubKey[:])
	if err != nil {
		s.log.Debug("failed to compute shared secret", "error", err)
		return
	}

	// Determine sender identity from the ephemeral public key
	var senderID core.MeshCoreID
	copy(senderID[:], anonPayload.PubKey[:])

	// Check if sender is already a known client
	existingClient := s.cfg.Clients.GetClient(senderID)

	// Determine permissions
	perm := s.resolvePermissions(existingClient, password)
	if perm < 0 {
		// No permission granted — silently ignore (firmware behavior)
		s.log.Debug("login rejected (no matching password)", "peer", senderID.String())
		return
	}

	// Get or create client
	var client *ClientInfo
	if existingClient != nil {
		// Replay check
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

	// Update client state
	nowTS := s.cfg.Clock.GetCurrentTime()
	client.LastTimestamp = senderTimestamp
	client.SyncSince = senderSyncSince
	client.PushFailures = 0
	client.LastActivity = nowTS
	client.Permissions = uint8(perm)

	// Ensure the client exists in the contact store so that addressed
	// packets (TXT_MSG, REQ) can be decrypted via SearchByHash/GetSharedSecret.
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
	s.sendLoginResponse(pkt, senderID, secret, uint8(perm), nowTS)
}

// resolvePermissions determines what permission level to grant for a login.
// Returns -1 if no permission should be granted (reject).
func (s *Server) resolvePermissions(existing *ClientInfo, password string) int {
	// If client already exists and is re-logging in, keep their permissions
	if existing != nil && password == "" {
		return int(existing.Permissions)
	}

	// Try admin password
	if s.cfg.AdminPassword != "" && password == s.cfg.AdminPassword {
		return int(codec.PermACLAdmin)
	}

	// Try guest password
	if s.cfg.GuestPassword != "" && password == s.cfg.GuestPassword {
		return int(codec.PermACLReadWrite)
	}

	// Open room (read-only access)
	if s.cfg.AllowReadOnly {
		return int(codec.PermACLReadOnly)
	}

	return -1
}

// sendLoginResponse sends a login OK response back to the client.
func (s *Server) sendLoginResponse(origPkt *codec.Packet, recipientID core.MeshCoreID, secret []byte, perms uint8, nowTS uint32) {
	// Build response content
	resp := make([]byte, loginResponseSize)
	binary.LittleEndian.PutUint32(resp[0:4], nowTS)
	resp[4] = codec.RespServerLoginOK
	resp[5] = 0 // legacy: keep-alive interval (unused)

	// Admin/guest flag for backward compatibility
	switch perms & codec.PermACLRoleMask {
	case codec.PermACLAdmin:
		resp[6] = 1
	case codec.PermACLGuest, codec.PermACLReadOnly:
		resp[6] = 2
	default:
		resp[6] = 0
	}

	resp[7] = perms
	// resp[8:12] = random blob (leave as zero — acceptable for our purposes)
	resp[12] = FirmwareVersion

	s.sendEncryptedResponse(recipientID, secret, codec.PayloadTypeResponse, resp)
	s.log.Debug("sent login response", "peer", recipientID.String())
}

// extractNullTerminated extracts a null-terminated string from data.
func extractNullTerminated(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}
