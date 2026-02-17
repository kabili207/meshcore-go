package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Advert payload sizes
	AdvertPubKeySize    = 32
	AdvertTimestampSize = 4
	AdvertSignatureSize = 64
	AdvertMinSize       = AdvertPubKeySize + AdvertTimestampSize + AdvertSignatureSize // 100 bytes

	// AppData flags - node types (lower 4 bits)
	NodeTypeChat     = 0x01
	NodeTypeRepeater = 0x02
	NodeTypeRoom     = 0x03
	NodeTypeSensor   = 0x04

	// AppData flags - presence flags (upper 4 bits)
	FlagHasLocation = 0x10
	FlagHasFeature1 = 0x20
	FlagHasFeature2 = 0x40
	FlagHasName     = 0x80

	// Coordinate scale factor (lat/lon stored as int32 * 1_000_000)
	CoordScale = 1_000_000.0

	// ACK payload size
	AckSize = 4

	// Addressed payload header size (TXT_MSG, REQ, RESPONSE, PATH)
	// dest_hash(1) + src_hash(1) + MAC(2) = 4 bytes
	AddressedHeaderSize = 4

	// Group payload header size (GRP_TXT, GRP_DATA)
	// channel_hash(1) + MAC(2) = 3 bytes
	GroupHeaderSize = 3

	// Anonymous request header size
	// dest_hash(1) + pubkey(32) + MAC(2) = 35 bytes
	AnonReqHeaderSize = 35

	// Control payload minimum size
	ControlMinSize = 1

	// Control subtypes (upper 4 bits of flags)
	ControlSubtypeDiscoverReq  = 0x08
	ControlSubtypeDiscoverResp = 0x09

	// Text message types (upper 6 bits of txt_type field)
	TxtTypePlain  = 0x00 // Plain text message
	TxtTypeCLI    = 0x01 // CLI command
	TxtTypeSigned = 0x02 // Signed plain text message

	// Request types
	ReqTypeGetStats       = 0x01
	ReqTypeKeepalive      = 0x02 // Deprecated
	ReqTypeGetTelemetry   = 0x03
	ReqTypeGetMinMaxAvg   = 0x04
	ReqTypeGetAccessList  = 0x05
	ReqTypeGetNeighbors   = 0x06
	ReqTypeGetOwnerInfo   = 0x07
)

var (
	ErrAdvertTooShort    = errors.New("advert payload too short")
	ErrAppDataTooShort   = errors.New("appdata too short")
	ErrInvalidNodeType   = errors.New("invalid node type")
	ErrAckTooShort       = errors.New("ack payload too short")
	ErrAddressedTooShort = errors.New("addressed payload too short")
	ErrGroupTooShort     = errors.New("group payload too short")
	ErrAnonReqTooShort   = errors.New("anonymous request payload too short")
	ErrControlTooShort   = errors.New("control payload too short")
	ErrTxtMsgTooShort    = errors.New("text message too short")
	ErrRequestTooShort   = errors.New("request payload too short")
)

// AdvertPayload represents a parsed node advertisement payload.
type AdvertPayload struct {
	PubKey    [32]byte
	Timestamp uint32
	Signature [64]byte
	AppData   *AdvertAppData
}

// AdvertAppData represents the optional application data in an advertisement.
type AdvertAppData struct {
	Flags    uint8
	NodeType uint8    // Lower 4 bits of flags: chat, repeater, room, sensor
	Name     string   // Node name (if FlagHasName set)
	Lat      *float64 // Latitude in decimal degrees (if FlagHasLocation set)
	Lon      *float64 // Longitude in decimal degrees (if FlagHasLocation set)
	Feature1 *uint16  // Reserved (if FlagHasFeature1 set)
	Feature2 *uint16  // Reserved (if FlagHasFeature2 set)
}

// ParseAdvertPayload parses an ADVERT payload into its components.
func ParseAdvertPayload(data []byte) (*AdvertPayload, error) {
	if len(data) < AdvertMinSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrAdvertTooShort, AdvertMinSize, len(data))
	}

	advert := &AdvertPayload{}

	// Public key (32 bytes)
	copy(advert.PubKey[:], data[0:32])

	// Timestamp (4 bytes, little endian per docs)
	advert.Timestamp = binary.LittleEndian.Uint32(data[32:36])

	// Signature (64 bytes)
	copy(advert.Signature[:], data[36:100])

	// Parse optional appdata if present
	if len(data) > AdvertMinSize {
		appData, err := ParseAdvertAppData(data[AdvertMinSize:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse appdata: %w", err)
		}
		advert.AppData = appData
	}

	return advert, nil
}

// ParseAdvertAppData parses the optional application data from an advertisement.
func ParseAdvertAppData(data []byte) (*AdvertAppData, error) {
	if len(data) < 1 {
		return nil, ErrAppDataTooShort
	}

	appData := &AdvertAppData{
		Flags:    data[0],
		NodeType: data[0] & 0x0F, // Lower 4 bits
	}

	offset := 1

	// Parse optional location (8 bytes: lat + lon as int32 little endian)
	if appData.Flags&FlagHasLocation != 0 {
		if len(data) < offset+8 {
			return nil, fmt.Errorf("%w: expected location data", ErrAppDataTooShort)
		}
		latRaw := int32(binary.LittleEndian.Uint32(data[offset : offset+4]))
		lonRaw := int32(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
		lat := float64(latRaw) / CoordScale
		lon := float64(lonRaw) / CoordScale
		appData.Lat = &lat
		appData.Lon = &lon
		offset += 8
	}

	// Parse optional feature1 (2 bytes, little endian)
	if appData.Flags&FlagHasFeature1 != 0 {
		if len(data) < offset+2 {
			return nil, fmt.Errorf("%w: expected feature1 data", ErrAppDataTooShort)
		}
		f1 := binary.LittleEndian.Uint16(data[offset : offset+2])
		appData.Feature1 = &f1
		offset += 2
	}

	// Parse optional feature2 (2 bytes, little endian)
	if appData.Flags&FlagHasFeature2 != 0 {
		if len(data) < offset+2 {
			return nil, fmt.Errorf("%w: expected feature2 data", ErrAppDataTooShort)
		}
		f2 := binary.LittleEndian.Uint16(data[offset : offset+2])
		appData.Feature2 = &f2
		offset += 2
	}

	// Parse optional name (remaining bytes if FlagHasName set)
	if appData.Flags&FlagHasName != 0 {
		if offset < len(data) {
			appData.Name = string(data[offset:])
		}
	}

	return appData, nil
}

// NodeTypeName returns a human-readable name for the node type.
func NodeTypeName(t uint8) string {
	switch t {
	case NodeTypeChat:
		return "chat"
	case NodeTypeRepeater:
		return "repeater"
	case NodeTypeRoom:
		return "room"
	case NodeTypeSensor:
		return "sensor"
	default:
		if t == 0 {
			return "unknown"
		}
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// HasLocation returns true if the appdata includes location information.
func (a *AdvertAppData) HasLocation() bool {
	return a.Lat != nil && a.Lon != nil
}

// GetNodeTypeName returns the human-readable node type name.
func (a *AdvertAppData) GetNodeTypeName() string {
	return NodeTypeName(a.NodeType)
}

// -----------------------------------------------------------------------------
// ACK Payload
// -----------------------------------------------------------------------------

// AckPayload represents an acknowledgment payload.
type AckPayload struct {
	Checksum uint32 // CRC checksum of message timestamp, text, and sender pubkey
}

// ParseAckPayload parses an ACK payload.
func ParseAckPayload(data []byte) (*AckPayload, error) {
	if len(data) < AckSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrAckTooShort, AckSize, len(data))
	}
	return &AckPayload{
		Checksum: binary.LittleEndian.Uint32(data[0:4]),
	}, nil
}

// -----------------------------------------------------------------------------
// Addressed Payload (TXT_MSG, REQ, RESPONSE, PATH)
// -----------------------------------------------------------------------------

// AddressedPayload represents payloads with dest/src hashes and encrypted content.
// Used for TXT_MSG, REQ, RESPONSE, and PATH payload types.
type AddressedPayload struct {
	DestHash   uint8  // First byte of destination node's public key
	SrcHash    uint8  // First byte of source node's public key
	MAC        uint16 // Message authentication code for ciphertext
	Ciphertext []byte // Encrypted content (format depends on payload type)
}

// ParseAddressedPayload parses the common header for addressed payloads.
func ParseAddressedPayload(data []byte) (*AddressedPayload, error) {
	if len(data) < AddressedHeaderSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrAddressedTooShort, AddressedHeaderSize, len(data))
	}
	return &AddressedPayload{
		DestHash:   data[0],
		SrcHash:    data[1],
		MAC:        binary.LittleEndian.Uint16(data[2:4]),
		Ciphertext: data[AddressedHeaderSize:],
	}, nil
}

// -----------------------------------------------------------------------------
// Decrypted Text Message Content
// -----------------------------------------------------------------------------

// TxtMsgContent represents the decrypted content of a TXT_MSG payload.
type TxtMsgContent struct {
	Timestamp uint32 // Send time (unix timestamp)
	TxtType   uint8  // Message type (upper 6 bits): plain, CLI, signed
	Attempt   uint8  // Attempt number (lower 2 bits): 0-3
	Message   string // Message content
	// For signed messages (TxtType == TxtTypeSigned)
	SenderPubKeyPrefix []byte // First 4 bytes of sender's public key (only for signed)
}

// ParseTxtMsgContent parses decrypted text message content.
func ParseTxtMsgContent(data []byte) (*TxtMsgContent, error) {
	if len(data) < 5 { // timestamp(4) + type/attempt(1)
		return nil, fmt.Errorf("%w: expected at least 5 bytes, got %d", ErrTxtMsgTooShort, len(data))
	}

	content := &TxtMsgContent{
		Timestamp: binary.LittleEndian.Uint32(data[0:4]),
		TxtType:   (data[4] >> 2) & 0x3F, // Upper 6 bits
		Attempt:   data[4] & 0x03,        // Lower 2 bits
	}

	messageStart := 5
	if content.TxtType == TxtTypeSigned {
		if len(data) < 9 { // Need 4 more bytes for pubkey prefix
			return nil, fmt.Errorf("%w: signed message needs pubkey prefix", ErrTxtMsgTooShort)
		}
		content.SenderPubKeyPrefix = data[5:9]
		messageStart = 9
	}

	if messageStart < len(data) {
		content.Message = string(data[messageStart:])
	}

	return content, nil
}

// TxtTypeName returns a human-readable name for the text type.
func TxtTypeName(t uint8) string {
	switch t {
	case TxtTypePlain:
		return "plain"
	case TxtTypeCLI:
		return "cli"
	case TxtTypeSigned:
		return "signed"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// -----------------------------------------------------------------------------
// Decrypted Request Content
// -----------------------------------------------------------------------------

// RequestContent represents the decrypted content of a REQ payload.
type RequestContent struct {
	Timestamp   uint32 // Send time (unix timestamp)
	RequestType uint8  // Type of request
	RequestData []byte // Request-specific data
}

// ParseRequestContent parses decrypted request content.
func ParseRequestContent(data []byte) (*RequestContent, error) {
	if len(data) < 5 { // timestamp(4) + type(1)
		return nil, fmt.Errorf("%w: expected at least 5 bytes, got %d", ErrRequestTooShort, len(data))
	}
	return &RequestContent{
		Timestamp:   binary.LittleEndian.Uint32(data[0:4]),
		RequestType: data[4],
		RequestData: data[5:],
	}, nil
}

// RequestTypeName returns a human-readable name for the request type.
func RequestTypeName(t uint8) string {
	switch t {
	case ReqTypeGetStats:
		return "get_stats"
	case ReqTypeKeepalive:
		return "keepalive"
	case ReqTypeGetTelemetry:
		return "get_telemetry"
	case ReqTypeGetMinMaxAvg:
		return "get_min_max_avg"
	case ReqTypeGetAccessList:
		return "get_access_list"
	case ReqTypeGetNeighbors:
		return "get_neighbors"
	case ReqTypeGetOwnerInfo:
		return "get_owner_info"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// -----------------------------------------------------------------------------
// Decrypted Response Content
// -----------------------------------------------------------------------------

// ResponseContent represents the decrypted content of a RESPONSE payload.
type ResponseContent struct {
	Tag     uint32 // Response tag
	Content []byte // Response content
}

// ParseResponseContent parses decrypted response content.
func ParseResponseContent(data []byte) (*ResponseContent, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("response content too short: expected at least 4 bytes, got %d", len(data))
	}
	return &ResponseContent{
		Tag:     binary.LittleEndian.Uint32(data[0:4]),
		Content: data[4:],
	}, nil
}

// -----------------------------------------------------------------------------
// Decrypted Path Content
// -----------------------------------------------------------------------------

// PathContent represents the decrypted content of a PATH payload.
type PathContent struct {
	PathLen   uint8  // Length of path
	Path      []byte // List of node hashes (1 byte each)
	ExtraType uint8  // Bundled payload type (e.g., ACK or RESPONSE)
	Extra     []byte // Bundled payload content
}

// ParsePathContent parses decrypted path (returned path) content.
func ParsePathContent(data []byte) (*PathContent, error) {
	if len(data) < 2 { // path_len(1) + extra_type(1) minimum
		return nil, fmt.Errorf("path content too short: expected at least 2 bytes, got %d", len(data))
	}

	pathLen := data[0]
	if len(data) < int(1+pathLen+1) { // path_len + path + extra_type
		return nil, fmt.Errorf("path content too short for path length %d", pathLen)
	}

	content := &PathContent{
		PathLen: pathLen,
		Path:    make([]byte, pathLen),
	}
	copy(content.Path, data[1:1+pathLen])

	extraTypeOffset := 1 + int(pathLen)
	content.ExtraType = data[extraTypeOffset]

	if extraTypeOffset+1 < len(data) {
		content.Extra = data[extraTypeOffset+1:]
	}

	return content, nil
}

// -----------------------------------------------------------------------------
// Group Payload (GRP_TXT, GRP_DATA)
// -----------------------------------------------------------------------------

// GroupPayload represents payloads for group messages (channels).
type GroupPayload struct {
	ChannelHash uint8  // First byte of SHA256 of channel's shared key
	MAC         uint16 // Message authentication code for ciphertext
	Ciphertext  []byte // Encrypted content (same format as TXT_MSG content)
}

// ParseGroupPayload parses the header for group payloads.
func ParseGroupPayload(data []byte) (*GroupPayload, error) {
	if len(data) < GroupHeaderSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrGroupTooShort, GroupHeaderSize, len(data))
	}
	return &GroupPayload{
		ChannelHash: data[0],
		MAC:         binary.LittleEndian.Uint16(data[1:3]),
		Ciphertext:  data[GroupHeaderSize:],
	}, nil
}

// -----------------------------------------------------------------------------
// Anonymous Request Payload
// -----------------------------------------------------------------------------

// AnonReqPayload represents an anonymous request payload.
type AnonReqPayload struct {
	DestHash   uint8    // First byte of destination node's public key
	PubKey     [32]byte // Sender's Ed25519 public key (ephemeral)
	MAC        uint16   // Message authentication code for ciphertext
	Ciphertext []byte   // Encrypted content
}

// ParseAnonReqPayload parses an anonymous request payload.
func ParseAnonReqPayload(data []byte) (*AnonReqPayload, error) {
	if len(data) < AnonReqHeaderSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrAnonReqTooShort, AnonReqHeaderSize, len(data))
	}

	payload := &AnonReqPayload{
		DestHash: data[0],
		MAC:      binary.LittleEndian.Uint16(data[33:35]),
	}
	copy(payload.PubKey[:], data[1:33])

	if len(data) > AnonReqHeaderSize {
		payload.Ciphertext = data[AnonReqHeaderSize:]
	}

	return payload, nil
}

// -----------------------------------------------------------------------------
// Control Payload
// -----------------------------------------------------------------------------

// ControlPayload represents a control/discovery payload.
type ControlPayload struct {
	Flags   uint8  // Upper 4 bits = subtype, lower 4 bits = type-specific
	Subtype uint8  // Extracted from upper 4 bits
	Data    []byte // Payload data (format depends on subtype)
}

// ParseControlPayload parses a control payload.
func ParseControlPayload(data []byte) (*ControlPayload, error) {
	if len(data) < ControlMinSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrControlTooShort, ControlMinSize, len(data))
	}
	return &ControlPayload{
		Flags:   data[0],
		Subtype: (data[0] >> 4) & 0x0F,
		Data:    data[1:],
	}, nil
}

// DiscoverReqPayload represents a DISCOVER_REQ control payload.
type DiscoverReqPayload struct {
	PrefixOnly bool   // If true, responses should only include pubkey prefix
	TypeFilter uint8  // Bit mask for ADV_TYPE_* filtering
	Tag        uint32 // Randomly generated by sender
	Since      uint32 // Optional: epoch timestamp (0 by default)
}

// ParseDiscoverReqPayload parses a DISCOVER_REQ from control data.
func ParseDiscoverReqPayload(data []byte) (*DiscoverReqPayload, error) {
	// data[0] was flags (already parsed), data starts at type_filter
	if len(data) < 5 { // type_filter(1) + tag(4)
		return nil, fmt.Errorf("discover request too short: expected at least 5 bytes, got %d", len(data))
	}

	payload := &DiscoverReqPayload{
		TypeFilter: data[0],
		Tag:        binary.LittleEndian.Uint32(data[1:5]),
	}

	// Optional since field
	if len(data) >= 9 {
		payload.Since = binary.LittleEndian.Uint32(data[5:9])
	}

	return payload, nil
}

// ParseDiscoverReqFromControl parses DISCOVER_REQ from a ControlPayload.
func ParseDiscoverReqFromControl(ctrl *ControlPayload) (*DiscoverReqPayload, error) {
	if ctrl.Subtype != ControlSubtypeDiscoverReq {
		return nil, fmt.Errorf("not a DISCOVER_REQ: subtype %d", ctrl.Subtype)
	}

	payload, err := ParseDiscoverReqPayload(ctrl.Data)
	if err != nil {
		return nil, err
	}
	payload.PrefixOnly = (ctrl.Flags & 0x01) != 0
	return payload, nil
}

// DiscoverRespPayload represents a DISCOVER_RESP control payload.
type DiscoverRespPayload struct {
	NodeType uint8  // Node type (lower 4 bits of flags)
	SNR      int8   // Signal-to-noise ratio (raw value, multiply by 0.25 for dB)
	Tag      uint32 // Reflected from DISCOVER_REQ
	PubKey   []byte // Node's ID (8 or 32 bytes depending on prefix_only)
}

// ParseDiscoverRespPayload parses a DISCOVER_RESP from control data.
func ParseDiscoverRespPayload(data []byte) (*DiscoverRespPayload, error) {
	// data[0] was flags (already parsed by ControlPayload), data starts at snr
	if len(data) < 5 { // snr(1) + tag(4)
		return nil, fmt.Errorf("discover response too short: expected at least 5 bytes, got %d", len(data))
	}

	payload := &DiscoverRespPayload{
		SNR: int8(data[0]),
		Tag: binary.LittleEndian.Uint32(data[1:5]),
	}

	// PubKey is remaining bytes (8 for prefix, 32 for full)
	if len(data) > 5 {
		payload.PubKey = data[5:]
	}

	return payload, nil
}

// ParseDiscoverRespFromControl parses DISCOVER_RESP from a ControlPayload.
func ParseDiscoverRespFromControl(ctrl *ControlPayload) (*DiscoverRespPayload, error) {
	if ctrl.Subtype != ControlSubtypeDiscoverResp {
		return nil, fmt.Errorf("not a DISCOVER_RESP: subtype %d", ctrl.Subtype)
	}

	payload, err := ParseDiscoverRespPayload(ctrl.Data)
	if err != nil {
		return nil, err
	}
	payload.NodeType = ctrl.Flags & 0x0F
	return payload, nil
}

// GetSNR returns the signal-to-noise ratio in dB.
func (d *DiscoverRespPayload) GetSNR() float32 {
	return float32(d.SNR) / 4.0
}

// -----------------------------------------------------------------------------
// Multipart Payload
// -----------------------------------------------------------------------------

// MultipartPayload represents a MULTIPART packet.
type MultipartPayload struct {
	Remaining uint8  // Number of packets still to follow (upper 4 bits)
	InnerType uint8  // Payload type of the inner content (lower 4 bits)
	Data      []byte // Inner payload data (header byte stripped)
}

// ParseMultipartPayload parses a MULTIPART payload.
// Format: [header_byte][inner_data...]
// header_byte: upper 4 bits = remaining count, lower 4 bits = inner payload type.
func ParseMultipartPayload(data []byte) (*MultipartPayload, error) {
	if len(data) < 1 {
		return nil, errors.New("multipart payload too short")
	}
	return &MultipartPayload{
		Remaining: (data[0] >> 4) & 0x0F,
		InnerType: data[0] & 0x0F,
		Data:      data[1:],
	}, nil
}

// ControlSubtypeName returns a human-readable name for the control subtype.
func ControlSubtypeName(t uint8) string {
	switch t {
	case ControlSubtypeDiscoverReq:
		return "DISCOVER_REQ"
	case ControlSubtypeDiscoverResp:
		return "DISCOVER_RESP"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
