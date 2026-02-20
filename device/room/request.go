package room

import (
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

const (
	// aclEntrySize is the wire size of one ACL entry in GET_ACCESS_LIST responses:
	// pubkey_prefix(6) + permissions(1).
	aclEntrySize = 7

	// aclPrefixSize is the number of public key bytes included per ACL entry.
	aclPrefixSize = 6

	// maxReplySize is the maximum plaintext response size (firmware: sizeof(reply_data)).
	// The firmware uses a 60-byte buffer: tag(4) + up to 56 bytes of data.
	maxReplySize = 60
)

// handleGetStatus handles a GET_STATUS request. Returns the 52-byte ServerStats
// struct as a binary blob. No special permission check is required.
func (s *Server) handleGetStatus(tag uint32, senderID core.MeshCoreID, secret []byte) {
	if s.cfg.Stats == nil {
		return
	}

	stats := s.cfg.Stats.GetStats()
	statsBytes := stats.MarshalBinary()

	// Response: tag(4) + stats(52) = 56 bytes
	resp := make([]byte, 4+ServerStatsSize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], statsBytes)

	s.sendEncryptedResponse(senderID, secret, codec.PayloadTypeResponse, resp)
}

// handleGetTelemetry handles a GET_TELEMETRY request. Returns CayenneLPP-encoded
// sensor data. Guest clients are restricted to base telemetry (battery only).
func (s *Server) handleGetTelemetry(tag uint32, client *ClientInfo, senderID core.MeshCoreID, secret []byte, requestData []byte) {
	if s.cfg.Telemetry == nil {
		return
	}

	// Permission mask from request: payload[1] is the inverted mask.
	// Firmware: perm_mask = ~(payload[1])
	var permMask uint8
	if len(requestData) > 0 {
		permMask = ^requestData[0]
	}

	// Guests only get base telemetry (firmware zeroes the mask).
	if client.IsGuest() {
		permMask = 0x00
	}

	telemetryData := s.cfg.Telemetry.GetTelemetry(permMask)

	// Response: tag(4) + CayenneLPP data(variable)
	resp := make([]byte, 4+len(telemetryData))
	binary.LittleEndian.PutUint32(resp[0:4], tag)
	copy(resp[4:], telemetryData)

	s.sendEncryptedResponse(senderID, secret, codec.PayloadTypeResponse, resp)
}

// handleGetAccessList handles a GET_ACCESS_LIST request. Admin-only: returns
// the list of admin clients as 7-byte entries (6-byte pubkey prefix + permissions).
func (s *Server) handleGetAccessList(tag uint32, client *ClientInfo, senderID core.MeshCoreID, secret []byte, requestData []byte) {
	// Admin-only check
	if !client.IsAdmin() {
		return
	}

	// Reserved bytes must be zero (firmware validation).
	if len(requestData) >= 2 && (requestData[0] != 0 || requestData[1] != 0) {
		return
	}

	// Build response: tag(4) + entries(7*N), capped at maxReplySize.
	resp := make([]byte, 4, maxReplySize)
	binary.LittleEndian.PutUint32(resp[0:4], tag)

	s.cfg.Clients.ForEach(func(c *ClientInfo) bool {
		// Only include admin entries (firmware behavior).
		if !c.IsAdmin() {
			return true
		}

		// Check if we have room for another entry.
		if len(resp)+aclEntrySize > maxReplySize {
			return false
		}

		// Append 6-byte pubkey prefix + permissions byte.
		entry := make([]byte, aclEntrySize)
		copy(entry[0:aclPrefixSize], c.ID[:aclPrefixSize])
		entry[aclPrefixSize] = c.Permissions
		resp = append(resp, entry...)

		return true
	})

	s.sendEncryptedResponse(senderID, secret, codec.PayloadTypeResponse, resp)
}
