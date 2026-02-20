package codec

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// TraceHeaderSize is the fixed header size of a TRACE payload:
	// tag(4) + auth_code(4) + flags(1).
	TraceHeaderSize = 9

	// TraceFlagHashSizeMask extracts the hash size code from flags.
	// Hash size in bytes = 1 << (flags & TraceFlagHashSizeMask).
	TraceFlagHashSizeMask = 0x03
)

var (
	ErrTraceTooShort = errors.New("trace payload too short")
)

// TracePayload represents a parsed TRACE payload.
//
// TRACE packets use a unique layout: the packet's Path[] field stores per-hop
// SNR values (int8, SNR*4), while relay hashes are embedded in the payload
// after the 9-byte header. PathLen tracks the number of hops forwarded so far.
type TracePayload struct {
	Tag        uint32 // Random unique identifier set by the initiator
	AuthCode   uint32 // Authentication code
	Flags      uint8  // Lower 2 bits = hash size code
	HashSize   int    // Computed: 1 << (flags & 0x03) — bytes per relay hash
	PathHashes []byte // Relay hashes embedded in payload (N * HashSize bytes)
}

// ParseTracePayload parses a TRACE payload from raw bytes.
func ParseTracePayload(data []byte) (*TracePayload, error) {
	if len(data) < TraceHeaderSize {
		return nil, fmt.Errorf("%w: expected at least %d bytes, got %d",
			ErrTraceTooShort, TraceHeaderSize, len(data))
	}

	tp := &TracePayload{
		Tag:      binary.LittleEndian.Uint32(data[0:4]),
		AuthCode: binary.LittleEndian.Uint32(data[4:8]),
		Flags:    data[8],
	}
	tp.HashSize = 1 << (tp.Flags & TraceFlagHashSizeMask)

	if len(data) > TraceHeaderSize {
		tp.PathHashes = make([]byte, len(data)-TraceHeaderSize)
		copy(tp.PathHashes, data[TraceHeaderSize:])
	}

	return tp, nil
}

// HopCount returns the number of relay hops in the trace path.
func (tp *TracePayload) HopCount() int {
	if tp.HashSize == 0 || len(tp.PathHashes) == 0 {
		return 0
	}
	return len(tp.PathHashes) / tp.HashSize
}

// HashAt returns the hash bytes for hop index i, or nil if out of range.
func (tp *TracePayload) HashAt(i int) []byte {
	offset := i * tp.HashSize
	if offset+tp.HashSize > len(tp.PathHashes) {
		return nil
	}
	return tp.PathHashes[offset : offset+tp.HashSize]
}

// BuildTracePayload builds a wire-format TRACE payload.
// pathHashes contains the pre-computed relay hashes for the route.
func BuildTracePayload(tag, authCode uint32, flags uint8, pathHashes []byte) []byte {
	data := make([]byte, TraceHeaderSize+len(pathHashes))
	binary.LittleEndian.PutUint32(data[0:4], tag)
	binary.LittleEndian.PutUint32(data[4:8], authCode)
	data[8] = flags
	copy(data[TraceHeaderSize:], pathHashes)
	return data
}
