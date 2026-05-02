package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

var (
	// DefaultChannelKey is the default PSK for MeshCore's built-in "Public" group channel.
	// Base64: izOH6cXN6mrJ5e26oRXNcg==
	DefaultChannelKey = []byte{0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72}
)

// ComputeChannelHash computes the MeshCore channel hash from a shared key.
// The channel hash is the first byte of SHA256(key).
func ComputeChannelHash(sharedKey []byte) uint8 {
	hash := sha256.Sum256(sharedKey)
	return hash[0]
}

// EncryptGroupMessage encrypts plaintext for a MeshCore GRP_TXT message.
// Uses AES-128 ECB encryption followed by HMAC-SHA256 (truncated to 2 bytes).
// Returns ciphertext with MAC prepended. Key must be 16 or 32 bytes.
func EncryptGroupMessage(plaintext, sharedKey []byte) ([]byte, error) {
	if len(sharedKey) != 16 && len(sharedKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	return encryptThenMAC(sharedKey, plaintext)
}

// DecryptGroupMessage decrypts a MeshCore GRP_TXT message.
// Expects data with MAC prepended (MAC + ciphertext).
// Returns the decrypted plaintext (may have trailing zero padding).
// Key must be 16 or 32 bytes.
func DecryptGroupMessage(data, sharedKey []byte) ([]byte, error) {
	if len(sharedKey) != 16 && len(sharedKey) != 32 {
		return nil, ErrInvalidKeySize
	}
	return macThenDecrypt(sharedKey, data)
}

// BuildGrpTxtPlaintext builds the plaintext for a MeshCore GRP_TXT message.
// Format: timestamp(4) + type_attempt(1) + message
func BuildGrpTxtPlaintext(timestamp uint32, message string) []byte {
	msgBytes := []byte(message)
	plaintext := make([]byte, 5+len(msgBytes))

	binary.LittleEndian.PutUint32(plaintext[0:4], timestamp)
	plaintext[4] = 0 // TXT_TYPE_PLAIN (0) with attempt 0
	copy(plaintext[5:], msgBytes)

	return plaintext
}

// ParseGrpTxtPlaintext parses the decrypted plaintext of a GRP_TXT message.
// Returns timestamp, message type, and the message text.
func ParseGrpTxtPlaintext(plaintext []byte) (timestamp uint32, txtType uint8, message string, err error) {
	if len(plaintext) < 5 {
		return 0, 0, "", errors.New("plaintext too short")
	}

	timestamp = binary.LittleEndian.Uint32(plaintext[0:4])
	txtType = plaintext[4] >> 2 // Upper 6 bits

	// Find null terminator or use remaining bytes
	msgBytes := plaintext[5:]
	for i, b := range msgBytes {
		if b == 0 {
			msgBytes = msgBytes[:i]
			break
		}
	}
	message = string(msgBytes)

	return timestamp, txtType, message, nil
}

// GrpDataContent represents the decrypted content of a PAYLOAD_TYPE_GRP_DATA message.
// Format changed in firmware v1.15.0: removed timestamp, added explicit data_type and data_len.
type GrpDataContent struct {
	DataType uint16 // Application-defined data type identifier
	Data     []byte // Binary payload (length specified by data_len field)
}

// ParseGrpDataContent parses the decrypted plaintext of a PAYLOAD_TYPE_GRP_DATA message.
// Firmware v1.15.0+ format: data_type(2 bytes LE) + data_len(1 byte) + data(data_len bytes)
// Note: Pre-v1.15.0 format used: timestamp(4 bytes) + blob (variable)
func ParseGrpDataContent(plaintext []byte) (*GrpDataContent, error) {
	if len(plaintext) < 3 {
		return nil, errors.New("plaintext too short for GRP_DATA header")
	}

	dataType := binary.LittleEndian.Uint16(plaintext[0:2])
	dataLen := int(plaintext[2])

	if len(plaintext) < 3+dataLen {
		return nil, errors.New("plaintext shorter than declared data length")
	}

	data := make([]byte, dataLen)
	copy(data, plaintext[3:3+dataLen])

	return &GrpDataContent{
		DataType: dataType,
		Data:     data,
	}, nil
}

// BuildGrpDataPlaintext builds the plaintext for a PAYLOAD_TYPE_GRP_DATA message.
// Firmware v1.15.0+ format: data_type(2 bytes LE) + data_len(1 byte) + data
func BuildGrpDataPlaintext(dataType uint16, data []byte) []byte {
	plaintext := make([]byte, 3+len(data))
	binary.LittleEndian.PutUint16(plaintext[0:2], dataType)
	plaintext[2] = uint8(len(data))
	copy(plaintext[3:], data)
	return plaintext
}
