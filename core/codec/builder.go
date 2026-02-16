package codec

import (
	"encoding/binary"
	"math"
)

// -----------------------------------------------------------------------------
// ADVERT Builders
// -----------------------------------------------------------------------------

// BuildAdvertPayload builds a wire-format ADVERT payload.
// appData may be nil for a minimal advertisement (100 bytes).
func BuildAdvertPayload(pubKey [32]byte, timestamp uint32, signature [64]byte, appData *AdvertAppData) []byte {
	appDataBytes := BuildAdvertAppData(appData)

	size := AdvertMinSize + len(appDataBytes)
	data := make([]byte, size)

	copy(data[0:32], pubKey[:])
	binary.LittleEndian.PutUint32(data[32:36], timestamp)
	copy(data[36:100], signature[:])

	if len(appDataBytes) > 0 {
		copy(data[AdvertMinSize:], appDataBytes)
	}

	return data
}

// BuildAdvertAppData builds the optional application data portion of an ADVERT.
// Returns nil if appData is nil.
func BuildAdvertAppData(appData *AdvertAppData) []byte {
	if appData == nil {
		return nil
	}

	// Compute flags from the struct fields
	flags := appData.NodeType & 0x0F
	if appData.Lat != nil && appData.Lon != nil {
		flags |= FlagHasLocation
	}
	if appData.Feature1 != nil {
		flags |= FlagHasFeature1
	}
	if appData.Feature2 != nil {
		flags |= FlagHasFeature2
	}
	if appData.Name != "" {
		flags |= FlagHasName
	}

	// Calculate size
	size := 1 // flags byte
	if flags&FlagHasLocation != 0 {
		size += 8
	}
	if flags&FlagHasFeature1 != 0 {
		size += 2
	}
	if flags&FlagHasFeature2 != 0 {
		size += 2
	}
	if flags&FlagHasName != 0 {
		size += len(appData.Name)
	}

	data := make([]byte, size)
	data[0] = flags
	offset := 1

	if flags&FlagHasLocation != 0 {
		latRaw := int32(math.Round(*appData.Lat * CoordScale))
		lonRaw := int32(math.Round(*appData.Lon * CoordScale))
		binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(latRaw))
		binary.LittleEndian.PutUint32(data[offset+4:offset+8], uint32(lonRaw))
		offset += 8
	}

	if flags&FlagHasFeature1 != 0 {
		binary.LittleEndian.PutUint16(data[offset:offset+2], *appData.Feature1)
		offset += 2
	}

	if flags&FlagHasFeature2 != 0 {
		binary.LittleEndian.PutUint16(data[offset:offset+2], *appData.Feature2)
		offset += 2
	}

	if flags&FlagHasName != 0 {
		copy(data[offset:], appData.Name)
	}

	return data
}

// -----------------------------------------------------------------------------
// ACK Builder
// -----------------------------------------------------------------------------

// BuildAckPayload builds a wire-format ACK payload.
func BuildAckPayload(checksum uint32) []byte {
	data := make([]byte, AckSize)
	binary.LittleEndian.PutUint32(data, checksum)
	return data
}

// -----------------------------------------------------------------------------
// Addressed Payload Builder (TXT_MSG, REQ, RESPONSE, PATH)
// -----------------------------------------------------------------------------

// BuildAddressedPayload builds a wire-format addressed payload.
func BuildAddressedPayload(destHash, srcHash uint8, mac uint16, ciphertext []byte) []byte {
	data := make([]byte, AddressedHeaderSize+len(ciphertext))
	data[0] = destHash
	data[1] = srcHash
	binary.LittleEndian.PutUint16(data[2:4], mac)
	copy(data[AddressedHeaderSize:], ciphertext)
	return data
}

// -----------------------------------------------------------------------------
// Group Payload Builder (GRP_TXT, GRP_DATA)
// -----------------------------------------------------------------------------

// BuildGroupPayload builds a wire-format group payload.
func BuildGroupPayload(channelHash uint8, mac uint16, ciphertext []byte) []byte {
	data := make([]byte, GroupHeaderSize+len(ciphertext))
	data[0] = channelHash
	binary.LittleEndian.PutUint16(data[1:3], mac)
	copy(data[GroupHeaderSize:], ciphertext)
	return data
}

// -----------------------------------------------------------------------------
// Anonymous Request Builder
// -----------------------------------------------------------------------------

// BuildAnonReqPayload builds a wire-format anonymous request payload.
func BuildAnonReqPayload(destHash uint8, pubKey [32]byte, mac uint16, ciphertext []byte) []byte {
	data := make([]byte, AnonReqHeaderSize+len(ciphertext))
	data[0] = destHash
	copy(data[1:33], pubKey[:])
	binary.LittleEndian.PutUint16(data[33:35], mac)
	copy(data[AnonReqHeaderSize:], ciphertext)
	return data
}

// -----------------------------------------------------------------------------
// Control Payload Builder
// -----------------------------------------------------------------------------

// BuildControlPayload builds a wire-format control payload.
func BuildControlPayload(flags uint8, payload []byte) []byte {
	data := make([]byte, 1+len(payload))
	data[0] = flags
	copy(data[1:], payload)
	return data
}

// BuildDiscoverReqPayload builds a complete DISCOVER_REQ control payload
// (including the flags byte). Returns bytes suitable for use as a packet payload.
func BuildDiscoverReqPayload(prefixOnly bool, typeFilter uint8, tag uint32, since uint32) []byte {
	flags := uint8(ControlSubtypeDiscoverReq << 4)
	if prefixOnly {
		flags |= 0x01
	}

	size := 1 + 1 + 4 // flags + type_filter + tag
	if since != 0 {
		size += 4
	}

	data := make([]byte, size)
	data[0] = flags
	data[1] = typeFilter
	binary.LittleEndian.PutUint32(data[2:6], tag)

	if since != 0 {
		binary.LittleEndian.PutUint32(data[6:10], since)
	}

	return data
}

// BuildDiscoverRespPayload builds a complete DISCOVER_RESP control payload
// (including the flags byte). Returns bytes suitable for use as a packet payload.
func BuildDiscoverRespPayload(nodeType uint8, snr int8, tag uint32, pubKey []byte) []byte {
	flags := uint8(ControlSubtypeDiscoverResp<<4) | (nodeType & 0x0F)

	data := make([]byte, 1+1+4+len(pubKey))
	data[0] = flags
	data[1] = byte(snr)
	binary.LittleEndian.PutUint32(data[2:6], tag)
	copy(data[6:], pubKey)

	return data
}

// -----------------------------------------------------------------------------
// Content Builders (decrypted inner content)
// -----------------------------------------------------------------------------

// BuildTxtMsgContent builds decrypted text message content.
// For signed messages (txtType == TxtTypeSigned), senderPrefix must be 4 bytes.
func BuildTxtMsgContent(timestamp uint32, txtType, attempt uint8, message string, senderPrefix []byte) []byte {
	typeAttempt := (txtType << 2) | (attempt & 0x03)

	headerSize := 5 // timestamp(4) + type_attempt(1)
	if txtType == TxtTypeSigned {
		headerSize += 4 // sender pubkey prefix
	}

	msgBytes := []byte(message)
	data := make([]byte, headerSize+len(msgBytes))

	binary.LittleEndian.PutUint32(data[0:4], timestamp)
	data[4] = typeAttempt

	offset := 5
	if txtType == TxtTypeSigned && len(senderPrefix) >= 4 {
		copy(data[5:9], senderPrefix[:4])
		offset = 9
	}

	copy(data[offset:], msgBytes)

	return data
}

// BuildRequestContent builds decrypted request content.
func BuildRequestContent(timestamp uint32, requestType uint8, requestData []byte) []byte {
	data := make([]byte, 5+len(requestData))
	binary.LittleEndian.PutUint32(data[0:4], timestamp)
	data[4] = requestType
	copy(data[5:], requestData)
	return data
}

// BuildResponseContent builds decrypted response content.
func BuildResponseContent(tag uint32, content []byte) []byte {
	data := make([]byte, 4+len(content))
	binary.LittleEndian.PutUint32(data[0:4], tag)
	copy(data[4:], content)
	return data
}

// BuildPathContent builds decrypted path content.
func BuildPathContent(path []byte, extraType uint8, extra []byte) []byte {
	data := make([]byte, 1+len(path)+1+len(extra))
	data[0] = uint8(len(path))
	copy(data[1:1+len(path)], path)
	data[1+len(path)] = extraType
	copy(data[2+len(path):], extra)
	return data
}
