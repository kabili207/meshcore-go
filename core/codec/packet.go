package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Header bit masks and shifts
	PHRouteMask = 0x03 // 2-bit route type
	PHTypeShift = 2
	PHTypeMask  = 0x0F // 4-bit payload type
	PHVerShift  = 6
	PHVerMask   = 0x03 // 2-bit version

	// Route types
	RouteTypeTransportFlood  = 0x00 // Flood mode + transport codes
	RouteTypeFlood           = 0x01 // Flood mode, path built up (max 64 bytes)
	RouteTypeDirect          = 0x02 // Direct route, path supplied
	RouteTypeTransportDirect = 0x03 // Direct route + transport codes

	// Payload types
	PayloadTypeReq        = 0x00 // Request (dest/src hashes, MAC, encrypted data)
	PayloadTypeResponse   = 0x01 // Response to REQ or ANON_REQ
	PayloadTypeTxtMsg     = 0x02 // Plain text message
	PayloadTypeAck        = 0x03 // Simple acknowledgment
	PayloadTypeAdvert     = 0x04 // Node advertising its identity
	PayloadTypeGrpTxt     = 0x05 // Group text message (unverified)
	PayloadTypeGrpData    = 0x06 // Group datagram (unverified)
	PayloadTypeAnonReq    = 0x07 // Anonymous request
	PayloadTypePath       = 0x08 // Returned path
	PayloadTypeTrace      = 0x09 // Trace path, collecting SNI for each hop
	PayloadTypeMultipart  = 0x0A // Packet is one of a set
	PayloadTypeControl    = 0x0B // Control/discovery packet
	PayloadTypeRawCustom  = 0x0F // Custom packet (raw bytes)

	// Payload versions
	PayloadVer1 = 0x00 // 1-byte src/dest hashes, 2-byte MAC
	PayloadVer2 = 0x01 // Future
	PayloadVer3 = 0x02 // Future
	PayloadVer4 = 0x03 // Future

	// Size limits
	MaxPathSize      = 64
	MaxPacketPayload = 184

	// HeaderDoNotRetransmit marks a packet that must not be forwarded by relays.
	HeaderDoNotRetransmit = 0xFF
)

var (
	ErrPacketTooShort  = errors.New("packet too short")
	ErrPathTooLong     = errors.New("path length exceeds maximum")
	ErrPayloadTooLong  = errors.New("payload length exceeds maximum")
	ErrInvalidEncoding = errors.New("invalid packet encoding")
)

// Packet represents a MeshCore packet.
type Packet struct {
	Header         uint8
	TransportCodes [2]uint16 // Only present if route type includes transport
	PathLen        uint8
	Path           []byte // Up to 64 bytes
	Payload        []byte // Up to 184 bytes
	SNR            int8   // Signal-to-noise ratio (raw value, multiply by 0.25 for dB)
}

// RouteType returns the routing type from the header (2-bit field).
func (p *Packet) RouteType() uint8 {
	return p.Header & PHRouteMask
}

// PayloadType returns the payload type from the header (4-bit field).
func (p *Packet) PayloadType() uint8 {
	return (p.Header >> PHTypeShift) & PHTypeMask
}

// PayloadVersion returns the payload version from the header (2-bit field).
func (p *Packet) PayloadVersion() uint8 {
	return (p.Header >> PHVerShift) & PHVerMask
}

// IsFlood returns true if the packet uses flood routing.
func (p *Packet) IsFlood() bool {
	rt := p.RouteType()
	return rt == RouteTypeFlood || rt == RouteTypeTransportFlood
}

// IsDirect returns true if the packet uses direct routing.
func (p *Packet) IsDirect() bool {
	rt := p.RouteType()
	return rt == RouteTypeDirect || rt == RouteTypeTransportDirect
}

// HasTransportCodes returns true if the packet includes transport codes.
func (p *Packet) HasTransportCodes() bool {
	rt := p.RouteType()
	return rt == RouteTypeTransportFlood || rt == RouteTypeTransportDirect
}

// MarkDoNotRetransmit marks the packet to not be forwarded by relays.
func (p *Packet) MarkDoNotRetransmit() {
	p.Header = HeaderDoNotRetransmit
}

// IsMarkedDoNotRetransmit returns true if the packet is marked to not be retransmitted.
func (p *Packet) IsMarkedDoNotRetransmit() bool {
	return p.Header == HeaderDoNotRetransmit
}

// GetSNR returns the signal-to-noise ratio in dB.
func (p *Packet) GetSNR() float32 {
	return float32(p.SNR) / 4.0
}

// Clone returns a deep copy of the packet.
func (p *Packet) Clone() *Packet {
	clone := &Packet{
		Header:         p.Header,
		TransportCodes: p.TransportCodes,
		PathLen:        p.PathLen,
		SNR:            p.SNR,
	}
	if len(p.Path) > 0 {
		clone.Path = make([]byte, len(p.Path))
		copy(clone.Path, p.Path)
	}
	if len(p.Payload) > 0 {
		clone.Payload = make([]byte, len(p.Payload))
		copy(clone.Payload, p.Payload)
	}
	return clone
}

// ReadFrom decodes a packet from raw bytes.
// The SNR field is not included in the wire format and must be set separately.
func (p *Packet) ReadFrom(data []byte) error {
	if len(data) < 2 {
		return ErrPacketTooShort
	}

	i := 0
	p.Header = data[i]
	i++

	// Read transport codes if present (little endian per MeshCore)
	if p.HasTransportCodes() {
		if len(data) < i+4 {
			return ErrPacketTooShort
		}
		p.TransportCodes[0] = binary.LittleEndian.Uint16(data[i : i+2])
		i += 2
		p.TransportCodes[1] = binary.LittleEndian.Uint16(data[i : i+2])
		i += 2
	} else {
		p.TransportCodes[0] = 0
		p.TransportCodes[1] = 0
	}

	// Read path length
	if len(data) < i+1 {
		return ErrPacketTooShort
	}
	p.PathLen = data[i]
	i++

	if p.PathLen > MaxPathSize {
		return fmt.Errorf("%w: %d bytes", ErrPathTooLong, p.PathLen)
	}

	// Read path
	if len(data) < i+int(p.PathLen) {
		return ErrPacketTooShort
	}
	p.Path = make([]byte, p.PathLen)
	copy(p.Path, data[i:i+int(p.PathLen)])
	i += int(p.PathLen)

	// Remaining bytes are payload
	if i >= len(data) {
		return ErrInvalidEncoding
	}
	payloadLen := len(data) - i
	if payloadLen > MaxPacketPayload {
		return fmt.Errorf("%w: %d bytes", ErrPayloadTooLong, payloadLen)
	}
	p.Payload = make([]byte, payloadLen)
	copy(p.Payload, data[i:])

	return nil
}

// WriteTo encodes the packet to raw bytes.
// The SNR field is not included in the wire format.
func (p *Packet) WriteTo() []byte {
	size := 1 + 1 + len(p.Path) + len(p.Payload) // header + pathLen + path + payload
	if p.HasTransportCodes() {
		size += 4 // 2 transport codes * 2 bytes each
	}

	data := make([]byte, size)
	i := 0

	data[i] = p.Header
	i++

	// Write transport codes if present (little endian)
	if p.HasTransportCodes() {
		binary.LittleEndian.PutUint16(data[i:], p.TransportCodes[0])
		i += 2
		binary.LittleEndian.PutUint16(data[i:], p.TransportCodes[1])
		i += 2
	}

	// Write path length and path
	data[i] = uint8(len(p.Path))
	i++
	copy(data[i:], p.Path)
	i += len(p.Path)

	// Write payload
	copy(data[i:], p.Payload)

	return data
}

// GetRawLength returns the wire format length of this packet.
func (p *Packet) GetRawLength() int {
	size := 2 + len(p.Path) + len(p.Payload) // header + pathLen + path + payload
	if p.HasTransportCodes() {
		size += 4
	}
	return size
}

// PayloadTypeName returns a human-readable name for the payload type.
func PayloadTypeName(t uint8) string {
	switch t {
	case PayloadTypeReq:
		return "REQ"
	case PayloadTypeResponse:
		return "RESPONSE"
	case PayloadTypeTxtMsg:
		return "TXT_MSG"
	case PayloadTypeAck:
		return "ACK"
	case PayloadTypeAdvert:
		return "ADVERT"
	case PayloadTypeGrpTxt:
		return "GRP_TXT"
	case PayloadTypeGrpData:
		return "GRP_DATA"
	case PayloadTypeAnonReq:
		return "ANON_REQ"
	case PayloadTypePath:
		return "PATH"
	case PayloadTypeTrace:
		return "TRACE"
	case PayloadTypeMultipart:
		return "MULTIPART"
	case PayloadTypeControl:
		return "CONTROL"
	case PayloadTypeRawCustom:
		return "RAW_CUSTOM"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// RouteTypeName returns a human-readable name for the route type.
func RouteTypeName(t uint8) string {
	switch t {
	case RouteTypeTransportFlood:
		return "TRANSPORT_FLOOD"
	case RouteTypeFlood:
		return "FLOOD"
	case RouteTypeDirect:
		return "DIRECT"
	case RouteTypeTransportDirect:
		return "TRANSPORT_DIRECT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}
