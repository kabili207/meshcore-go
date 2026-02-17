package crypto

import (
	"crypto/ed25519"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
)

func TestSignVerifyAdvert(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)
	timestamp := uint32(1704067200)

	lat := 37.7749
	lon := -122.4194
	appData := &codec.AdvertAppData{
		NodeType: codec.NodeTypeChat,
		Name:     "TestNode",
		Lat:      &lat,
		Lon:      &lon,
	}
	appDataBytes := codec.BuildAdvertAppData(appData)

	// Sign
	sig, err := SignAdvert(kp.PrivateKey, pubKey, timestamp, appDataBytes)
	if err != nil {
		t.Fatalf("SignAdvert() error = %v", err)
	}

	// Build a full advert payload and parse it
	payload := codec.BuildAdvertPayload(pubKey, timestamp, sig, appData)
	parsed, err := codec.ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	// Verify
	if !VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = false, want true")
	}
}

func TestSignVerifyAdvertMinimal(t *testing.T) {
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)
	timestamp := uint32(1704067200)

	// No appdata
	sig, err := SignAdvert(kp.PrivateKey, pubKey, timestamp, nil)
	if err != nil {
		t.Fatalf("SignAdvert() error = %v", err)
	}

	payload := codec.BuildAdvertPayload(pubKey, timestamp, sig, nil)
	parsed, err := codec.ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if !VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = false for minimal advert, want true")
	}
}

func TestVerifyAdvertBadSignature(t *testing.T) {
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)
	timestamp := uint32(1704067200)

	sig, _ := SignAdvert(kp.PrivateKey, pubKey, timestamp, nil)

	// Corrupt the signature
	sig[0] ^= 0xFF

	payload := codec.BuildAdvertPayload(pubKey, timestamp, sig, nil)
	parsed, err := codec.ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = true for corrupted signature, want false")
	}
}

func TestVerifyAdvertWrongKey(t *testing.T) {
	kpSigner, _ := GenerateKeyPair()
	kpOther, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kpSigner.PublicKey)
	timestamp := uint32(1704067200)

	sig, _ := SignAdvert(kpSigner.PrivateKey, pubKey, timestamp, nil)

	// Replace the pubkey in the payload with a different key
	var otherPubKey [32]byte
	copy(otherPubKey[:], kpOther.PublicKey)

	payload := codec.BuildAdvertPayload(otherPubKey, timestamp, sig, nil)
	parsed, _ := codec.ParseAdvertPayload(payload)

	if VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = true for wrong key, want false")
	}
}

func TestVerifyAdvertTamperedTimestamp(t *testing.T) {
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)

	sig, _ := SignAdvert(kp.PrivateKey, pubKey, 1704067200, nil)

	// Build with different timestamp
	payload := codec.BuildAdvertPayload(pubKey, 9999999, sig, nil)
	parsed, _ := codec.ParseAdvertPayload(payload)

	if VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = true for tampered timestamp, want false")
	}
}

func TestVerifyAdvertTamperedAppData(t *testing.T) {
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)
	timestamp := uint32(1704067200)

	originalAppData := &codec.AdvertAppData{
		NodeType: codec.NodeTypeChat,
		Name:     "Original",
	}
	appDataBytes := codec.BuildAdvertAppData(originalAppData)

	sig, _ := SignAdvert(kp.PrivateKey, pubKey, timestamp, appDataBytes)

	// Build with different appdata
	tamperedAppData := &codec.AdvertAppData{
		NodeType: codec.NodeTypeChat,
		Name:     "Tampered",
	}

	payload := codec.BuildAdvertPayload(pubKey, timestamp, sig, tamperedAppData)
	parsed, _ := codec.ParseAdvertPayload(payload)

	if VerifyAdvert(parsed) {
		t.Error("VerifyAdvert() = true for tampered appdata, want false")
	}
}

func TestSignAdvertDeterministic(t *testing.T) {
	// Ed25519 signing is deterministic
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)

	sig1, _ := SignAdvert(kp.PrivateKey, pubKey, 1704067200, nil)
	sig2, _ := SignAdvert(kp.PrivateKey, pubKey, 1704067200, nil)

	if sig1 != sig2 {
		t.Error("Ed25519 signatures should be deterministic")
	}
}

func TestSignAdvertMatchesStdLib(t *testing.T) {
	// Verify our signing matches standard ed25519.Sign
	kp, _ := GenerateKeyPair()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)
	timestamp := uint32(1704067200)

	sig, _ := SignAdvert(kp.PrivateKey, pubKey, timestamp, nil)

	// Manually construct the message and verify with stdlib
	msg := buildAdvertSignedMessage(pubKey, timestamp, nil)
	if !ed25519.Verify(kp.PublicKey, msg, sig[:]) {
		t.Error("signature does not verify with stdlib ed25519.Verify")
	}
}
