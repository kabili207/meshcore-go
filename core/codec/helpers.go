package codec

import "bytes"

// NewPacket creates a packet with the header correctly constructed from
// the payload type and route type, avoiding manual bit shifting.
func NewPacket(payloadType, routeType uint8, payload []byte) *Packet {
	return &Packet{
		Header:  (payloadType << PHTypeShift) | (routeType & PHRouteMask),
		Payload: payload,
	}
}

// ReverseFloodPath extracts and reverses the flood path from a packet.
// The flood path lists relay hashes from sender → this node. Reversing it
// gives a direct route from this node → relays → sender.
// Returns nil if the packet has no path.
func ReverseFloodPath(pkt *Packet) []byte {
	if pkt == nil || pkt.PathLen == 0 {
		return nil
	}
	path := make([]byte, pkt.PathLen)
	for i := range pkt.PathLen {
		path[i] = pkt.Path[pkt.PathLen-1-i]
	}
	return path
}

// TrimTxtMsgContent returns the plaintext trimmed to the actual content length,
// stripping AES-128 ECB block padding. The firmware computes ACK hashes using
// header + strlen(text), so we must match that exactly.
//
// For plain/CLI messages: 5 + len(message text before first null byte)
// For signed messages:    9 + len(message text before first null byte)
func TrimTxtMsgContent(plaintext []byte, content *TxtMsgContent) []byte {
	headerSize := 5
	if content.TxtType == TxtTypeSigned {
		headerSize = 9
	}

	if len(plaintext) <= headerSize {
		return plaintext
	}

	textBytes := plaintext[headerSize:]
	if idx := bytes.IndexByte(textBytes, 0); idx >= 0 {
		return plaintext[:headerSize+idx]
	}

	return plaintext
}

// TrimRequestContent returns the plaintext trimmed to the actual request content
// length, stripping AES-128 ECB block padding.
func TrimRequestContent(plaintext []byte, content *RequestContent) []byte {
	switch content.RequestType {
	case ReqTypeKeepalive:
		// timestamp(4) + type(1) + sync_since(4) = 9 bytes
		if len(plaintext) >= 9 {
			return plaintext[:9]
		}
	default:
		return bytes.TrimRight(plaintext, "\x00")
	}
	return plaintext
}
