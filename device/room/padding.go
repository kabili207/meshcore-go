package room

import (
	"bytes"

	"github.com/kabili207/meshcore-go/core/codec"
)

// trimTxtMsgContent returns the plaintext trimmed to the actual content length,
// stripping AES-128 ECB block padding. The firmware computes ACK hashes using
// header + strlen(text), so we must match that exactly.
//
// For plain/CLI messages: 5 + len(message text before first null byte)
// For signed messages:    9 + len(message text before first null byte)
func trimTxtMsgContent(plaintext []byte, content *codec.TxtMsgContent) []byte {
	headerSize := 5
	if content.TxtType == codec.TxtTypeSigned {
		headerSize = 9
	}

	if len(plaintext) <= headerSize {
		return plaintext
	}

	// Find the text length by looking for the first null byte after the header,
	// matching the firmware's strlen() behavior.
	textBytes := plaintext[headerSize:]
	if idx := bytes.IndexByte(textBytes, 0); idx >= 0 {
		return plaintext[:headerSize+idx]
	}

	// No null byte found — use the full remaining data.
	return plaintext
}

// trimRequestContent returns the plaintext trimmed to the actual request content
// length, stripping AES-128 ECB block padding. The firmware computes ACK hashes
// using the exact known request size.
func trimRequestContent(plaintext []byte, content *codec.RequestContent) []byte {
	// Request layout: timestamp(4) + type(1) + request_data
	// The request data size depends on the type.
	switch content.RequestType {
	case codec.ReqTypeKeepalive:
		// timestamp(4) + type(1) + sync_since(4) = 9 bytes
		if len(plaintext) >= 9 {
			return plaintext[:9]
		}
	default:
		// For other request types, trim trailing zero padding.
		return bytes.TrimRight(plaintext, "\x00")
	}
	return plaintext
}
