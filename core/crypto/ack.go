package crypto

import (
	"crypto/sha256"
	"encoding/binary"
)

// ComputeAckHash computes the 4-byte ACK hash for a message, matching the
// firmware's method: SHA256(contentData, senderPubKey) truncated to 4 bytes.
//
// contentData is the raw decrypted content bytes (e.g. for a text message:
// timestamp(4 LE) + flags(1) + text). senderPubKey is the 32-byte Ed25519
// public key of the message sender.
//
// For plain text messages (TxtTypePlain), the hash uses the sender's public key.
// For signed text messages (TxtTypeSigned), the hash uses the receiver's public key.
func ComputeAckHash(contentData []byte, pubKey []byte) uint32 {
	h := sha256.New()
	h.Write(contentData)
	h.Write(pubKey)
	sum := h.Sum(nil)
	return binary.LittleEndian.Uint32(sum[:4])
}
