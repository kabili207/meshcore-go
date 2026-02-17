package crypto

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// CipherKeySize is the AES-128 key size.
	CipherKeySize = 16
	// CipherBlockSize is the AES block size.
	CipherBlockSize = 16
	// CipherMACSize is the truncated HMAC-SHA256 size (2 bytes).
	CipherMACSize = 2
	// SecretSize is the full shared secret / HMAC key size (32 bytes).
	SecretSize = 32
)

var (
	ErrInvalidKeySize = errors.New("invalid key size: must be 16 or 32 bytes")
	ErrInvalidMACSize = errors.New("ciphertext too short for MAC")
	ErrMACMismatch    = errors.New("MAC verification failed")
)

// encryptThenMAC encrypts plaintext using AES-128 ECB, then computes an
// HMAC-SHA256 over the ciphertext (truncated to 2 bytes).
// Returns [MAC(2) || ciphertext]. This matches MeshCore's Utils::encryptThenMAC.
//
// Key usage:
//   - First 16 bytes → AES-128 cipher key
//   - Full key (zero-padded to 32 bytes) → HMAC key
func encryptThenMAC(secret, plaintext []byte) ([]byte, error) {
	// Pad plaintext to block size
	paddedLen := ((len(plaintext) + CipherBlockSize - 1) / CipherBlockSize) * CipherBlockSize
	if paddedLen == 0 {
		paddedLen = CipherBlockSize
	}
	padded := make([]byte, paddedLen)
	copy(padded, plaintext)

	// Encrypt using AES-128 ECB with first 16 bytes of key
	block, err := aes.NewCipher(secret[:CipherKeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext := make([]byte, paddedLen)
	for i := 0; i < paddedLen; i += CipherBlockSize {
		block.Encrypt(ciphertext[i:i+CipherBlockSize], padded[i:i+CipherBlockSize])
	}

	// Compute HMAC-SHA256 over ciphertext, using full 32-byte key
	hmacKey := make([]byte, SecretSize)
	copy(hmacKey, secret)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	macSum := mac.Sum(nil)

	// Prepend 2-byte MAC to ciphertext
	result := make([]byte, CipherMACSize+len(ciphertext))
	copy(result[:CipherMACSize], macSum[:CipherMACSize])
	copy(result[CipherMACSize:], ciphertext)

	return result, nil
}

// macThenDecrypt verifies the HMAC-SHA256 MAC and decrypts AES-128 ECB ciphertext.
// Expects input as [MAC(2) || ciphertext]. This matches MeshCore's Utils::MACThenDecrypt.
func macThenDecrypt(secret, data []byte) ([]byte, error) {
	if len(data) <= CipherMACSize {
		return nil, ErrInvalidMACSize
	}

	receivedMAC := data[:CipherMACSize]
	ciphertext := data[CipherMACSize:]

	// Verify HMAC-SHA256 using full 32-byte key
	hmacKey := make([]byte, SecretSize)
	copy(hmacKey, secret)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(ciphertext)
	computedMAC := mac.Sum(nil)

	if receivedMAC[0] != computedMAC[0] || receivedMAC[1] != computedMAC[1] {
		return nil, ErrMACMismatch
	}

	// Decrypt using AES-128 ECB with first 16 bytes of key
	block, err := aes.NewCipher(secret[:CipherKeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += CipherBlockSize {
		block.Decrypt(plaintext[i:i+CipherBlockSize], ciphertext[i:i+CipherBlockSize])
	}

	return plaintext, nil
}
