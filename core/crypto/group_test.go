package crypto

import (
	"bytes"
	"testing"
)

func TestComputeChannelHash(t *testing.T) {
	// The default channel key should produce a consistent hash
	hash := ComputeChannelHash(DefaultChannelKey)
	// Verify it's deterministic
	hash2 := ComputeChannelHash(DefaultChannelKey)
	if hash != hash2 {
		t.Errorf("ComputeChannelHash not deterministic: %02x != %02x", hash, hash2)
	}

	// Different keys should (usually) produce different hashes
	otherKey := make([]byte, 16)
	otherKey[0] = 0xFF
	otherHash := ComputeChannelHash(otherKey)
	if hash == otherHash {
		t.Log("Warning: hash collision (unlikely but possible)")
	}
}

func TestEncryptDecryptGroupMessage(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		message string
	}{
		{
			name:    "default key 16 bytes",
			key:     DefaultChannelKey,
			message: "Hello, MeshCore!",
		},
		{
			name:    "32 byte key",
			key:     make([]byte, 32),
			message: "Test with 32-byte key",
		},
		{
			name:    "exact block size message",
			key:     DefaultChannelKey,
			message: "16 bytes exact!", // 15 chars + we test block boundary
		},
		{
			name:    "empty message",
			key:     DefaultChannelKey,
			message: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := BuildGrpTxtPlaintext(1704067200, tt.message)

			encrypted, err := EncryptGroupMessage(plaintext, tt.key)
			if err != nil {
				t.Fatalf("EncryptGroupMessage() error = %v", err)
			}

			decrypted, err := DecryptGroupMessage(encrypted, tt.key)
			if err != nil {
				t.Fatalf("DecryptGroupMessage() error = %v", err)
			}

			// Parse both and compare
			origTS, origType, origMsg, err := ParseGrpTxtPlaintext(plaintext)
			if err != nil {
				t.Fatalf("ParseGrpTxtPlaintext(original) error = %v", err)
			}

			decTS, decType, decMsg, err := ParseGrpTxtPlaintext(decrypted)
			if err != nil {
				t.Fatalf("ParseGrpTxtPlaintext(decrypted) error = %v", err)
			}

			if origTS != decTS {
				t.Errorf("timestamp: got %d, want %d", decTS, origTS)
			}
			if origType != decType {
				t.Errorf("txtType: got %d, want %d", decType, origType)
			}
			if origMsg != decMsg {
				t.Errorf("message: got %q, want %q", decMsg, origMsg)
			}
		})
	}
}

func TestEncryptGroupMessageInvalidKey(t *testing.T) {
	_, err := EncryptGroupMessage([]byte("test"), []byte("short"))
	if err != ErrInvalidKeySize {
		t.Errorf("EncryptGroupMessage() error = %v, want %v", err, ErrInvalidKeySize)
	}
}

func TestDecryptGroupMessageInvalidKey(t *testing.T) {
	_, err := DecryptGroupMessage([]byte{0x00, 0x00, 0x01}, []byte("short"))
	if err != ErrInvalidKeySize {
		t.Errorf("DecryptGroupMessage() error = %v, want %v", err, ErrInvalidKeySize)
	}
}

func TestDecryptGroupMessageTooShort(t *testing.T) {
	_, err := DecryptGroupMessage([]byte{0x00, 0x00}, DefaultChannelKey)
	if err != ErrInvalidMACSize {
		t.Errorf("DecryptGroupMessage() error = %v, want %v", err, ErrInvalidMACSize)
	}
}

func TestDecryptGroupMessageBadMAC(t *testing.T) {
	plaintext := BuildGrpTxtPlaintext(1704067200, "test")
	encrypted, err := EncryptGroupMessage(plaintext, DefaultChannelKey)
	if err != nil {
		t.Fatalf("EncryptGroupMessage() error = %v", err)
	}

	// Corrupt the MAC
	encrypted[0] ^= 0xFF

	_, err = DecryptGroupMessage(encrypted, DefaultChannelKey)
	if err != ErrMACMismatch {
		t.Errorf("DecryptGroupMessage() error = %v, want %v", err, ErrMACMismatch)
	}
}

func TestBuildGrpTxtPlaintext(t *testing.T) {
	plaintext := BuildGrpTxtPlaintext(1704067200, "Hello")

	// Should be 5 + len("Hello") = 10 bytes
	if len(plaintext) != 10 {
		t.Errorf("plaintext length = %d, want 10", len(plaintext))
	}

	ts, txtType, msg, err := ParseGrpTxtPlaintext(plaintext)
	if err != nil {
		t.Fatalf("ParseGrpTxtPlaintext() error = %v", err)
	}

	if ts != 1704067200 {
		t.Errorf("timestamp = %d, want %d", ts, 1704067200)
	}
	if txtType != 0 {
		t.Errorf("txtType = %d, want 0", txtType)
	}
	if msg != "Hello" {
		t.Errorf("message = %q, want %q", msg, "Hello")
	}
}

func TestParseGrpTxtPlaintextWithNull(t *testing.T) {
	// Build plaintext with null terminator followed by padding
	plaintext := BuildGrpTxtPlaintext(1704067200, "Hi")
	// Add null terminator and padding
	plaintext = append(plaintext, 0x00, 0x00, 0x00)

	_, _, msg, err := ParseGrpTxtPlaintext(plaintext)
	if err != nil {
		t.Fatalf("ParseGrpTxtPlaintext() error = %v", err)
	}

	if msg != "Hi" {
		t.Errorf("message = %q, want %q", msg, "Hi")
	}
}

func TestParseGrpTxtPlaintextTooShort(t *testing.T) {
	_, _, _, err := ParseGrpTxtPlaintext([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("ParseGrpTxtPlaintext() should error on short input")
	}
}

func TestEncryptDecryptRoundTripWithDefaultKey(t *testing.T) {
	// Simulate a real group message flow
	message := "Hello from meshcore-go!"
	timestamp := uint32(1704067200)

	// Build plaintext
	plaintext := BuildGrpTxtPlaintext(timestamp, message)

	// Compute channel hash
	channelHash := ComputeChannelHash(DefaultChannelKey)
	if channelHash == 0 {
		t.Log("Channel hash is 0 (valid but unusual)")
	}

	// Encrypt
	encrypted, err := EncryptGroupMessage(plaintext, DefaultChannelKey)
	if err != nil {
		t.Fatalf("EncryptGroupMessage() error = %v", err)
	}

	// The encrypted data should be MAC(2) + ciphertext
	if len(encrypted) < CipherMACSize+CipherBlockSize {
		t.Fatalf("encrypted too short: %d bytes", len(encrypted))
	}

	// Encrypted data should differ from plaintext
	if bytes.Equal(encrypted[CipherMACSize:], plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	// Decrypt
	decrypted, err := DecryptGroupMessage(encrypted, DefaultChannelKey)
	if err != nil {
		t.Fatalf("DecryptGroupMessage() error = %v", err)
	}

	// Parse and verify
	ts, _, msg, err := ParseGrpTxtPlaintext(decrypted)
	if err != nil {
		t.Fatalf("ParseGrpTxtPlaintext() error = %v", err)
	}

	if ts != timestamp {
		t.Errorf("timestamp = %d, want %d", ts, timestamp)
	}
	if msg != message {
		t.Errorf("message = %q, want %q", msg, message)
	}
}
