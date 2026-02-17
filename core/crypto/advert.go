package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/kabili207/meshcore-go/core/codec"
)

// SignAdvert signs an ADVERT payload using Ed25519.
// The signed message is: pubKey(32) || timestamp(4 LE) || appDataBytes.
// appDataBytes should be the wire-format appdata (from BuildAdvertAppData), or nil.
func SignAdvert(privateKey ed25519.PrivateKey, pubKey [32]byte, timestamp uint32, appDataBytes []byte) ([64]byte, error) {
	var sig [64]byte

	msg := buildAdvertSignedMessage(pubKey, timestamp, appDataBytes)

	rawSig := ed25519.Sign(privateKey, msg)
	if len(rawSig) != 64 {
		return sig, fmt.Errorf("unexpected signature length: %d", len(rawSig))
	}
	copy(sig[:], rawSig)

	return sig, nil
}

// VerifyAdvert verifies the Ed25519 signature of a parsed ADVERT payload.
// The signed message is reconstructed from the payload fields.
func VerifyAdvert(advert *codec.AdvertPayload) bool {
	// Reconstruct the appdata bytes from the parsed payload
	appDataBytes := codec.BuildAdvertAppData(advert.AppData)

	msg := buildAdvertSignedMessage(advert.PubKey, advert.Timestamp, appDataBytes)

	return ed25519.Verify(advert.PubKey[:], msg, advert.Signature[:])
}

// buildAdvertSignedMessage constructs the message bytes that are signed in an ADVERT.
// Format: pubKey(32) || timestamp(4 LE) || appData(variable)
func buildAdvertSignedMessage(pubKey [32]byte, timestamp uint32, appDataBytes []byte) []byte {
	msg := make([]byte, 32+4+len(appDataBytes))
	copy(msg[0:32], pubKey[:])
	binary.LittleEndian.PutUint32(msg[32:36], timestamp)
	if len(appDataBytes) > 0 {
		copy(msg[36:], appDataBytes)
	}
	return msg
}
