package room

import (
	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// sendEncryptedResponse encrypts plaintext content and sends it as the given
// payload type (typically PayloadTypeResponse) to the recipient. This is the
// common encrypt-split-build-route pattern used by login responses, REQ
// responses, and post pushes.
//
// When origPkt is non-nil and was flood-routed, the response is bundled inside
// a PATH packet (firmware's createPathReturn behavior). Otherwise, a bare
// RESPONSE datagram is sent directly or flooded based on the contact's path.
func (s *Server) sendEncryptedResponse(origPkt *codec.Packet, recipientID core.MeshCoreID, secret []byte, payloadType uint8, plaintext []byte) {
	// If the original request arrived via flood, send response inside a PATH packet
	if origPkt != nil && origPkt.IsFlood() {
		s.sendPathReturn(origPkt, recipientID, secret, payloadType, plaintext)
		return
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		s.log.Warn("failed to encrypt response", "error", err)
		return
	}

	mac, ciphertext := codec.SplitMAC(encrypted)

	destHash := recipientID.Hash()
	srcHash := core.MeshCoreID(s.cfg.PublicKey).Hash()
	payload := codec.BuildAddressedPayload(destHash, srcHash, mac, ciphertext)

	pkt := &codec.Packet{
		Header:  payloadType << codec.PHTypeShift,
		Payload: payload,
	}

	ct := s.cfg.Contacts.GetByPubKey(recipientID)
	if ct != nil && ct.HasDirectPath() {
		s.cfg.Router.SendDirect(pkt, ct.OutPath[:ct.OutPathLen])
	} else {
		s.cfg.Router.SendFlood(pkt)
	}
}

// sendPathReturn builds a PATH packet with the response bundled as extra data
// and sends it via flood. This matches the firmware's createPathReturn():
//  1. Reverse the original flood packet's path for the return route
//  2. Encrypt the response → build inner addressed payload (the "extra")
//  3. Build PATH content: [path_len || reversed_path || extra_type || extra]
//  4. Encrypt the PATH content → build outer addressed payload
//  5. Send via SendFloodPath (priority 2, 300ms delay)
func (s *Server) sendPathReturn(origPkt *codec.Packet, recipientID core.MeshCoreID, secret []byte, extraType uint8, plaintext []byte) {
	// Step 1: Reverse the flood path for the return route
	returnPath := reverseFloodPath(origPkt)

	// Step 2: Encrypt the response plaintext as an addressed payload (the "extra")
	innerEncrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		s.log.Warn("failed to encrypt path return extra", "error", err)
		return
	}
	innerMAC, innerCiphertext := codec.SplitMAC(innerEncrypted)

	destHash := recipientID.Hash()
	srcHash := core.MeshCoreID(s.cfg.PublicKey).Hash()
	extraPayload := codec.BuildAddressedPayload(destHash, srcHash, innerMAC, innerCiphertext)

	// Step 3: Build PATH content with the response as extra data
	pathContent := codec.BuildPathContent(returnPath, extraType, extraPayload)

	// Step 4: Encrypt the PATH content as the outer addressed payload
	outerEncrypted, err := crypto.EncryptAddressedWithSecret(pathContent, secret)
	if err != nil {
		s.log.Warn("failed to encrypt path return", "error", err)
		return
	}
	outerMAC, outerCiphertext := codec.SplitMAC(outerEncrypted)
	outerPayload := codec.BuildAddressedPayload(destHash, srcHash, outerMAC, outerCiphertext)

	// Step 5: Send as PATH via flood with delay
	pkt := &codec.Packet{
		Header:  codec.PayloadTypePath << codec.PHTypeShift,
		Payload: outerPayload,
	}
	s.cfg.Router.SendFloodPath(pkt)

	s.log.Debug("sent path return",
		"peer", recipientID.String(),
		"path_len", len(returnPath))
}

// reverseFloodPath extracts and reverses the flood path from a packet.
// The flood path lists relay hashes from sender → this node. Reversing it
// gives a direct route from this node → relays → sender.
func reverseFloodPath(pkt *codec.Packet) []byte {
	if pkt == nil || pkt.PathLen == 0 {
		return nil
	}
	path := make([]byte, pkt.PathLen)
	for i := range pkt.PathLen {
		path[i] = pkt.Path[pkt.PathLen-1-i]
	}
	return path
}
