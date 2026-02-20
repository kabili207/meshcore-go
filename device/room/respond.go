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
func (s *Server) sendEncryptedResponse(recipientID core.MeshCoreID, secret []byte, payloadType uint8, plaintext []byte) {
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
