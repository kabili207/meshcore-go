// Package dedupe provides packet deduplication for MeshCore networks.
//
// It tracks recently seen packets using a circular buffer, matching the
// firmware's SimpleMeshTables implementation. Every packet, including ACKs, is
// identified by an 8-byte SHA256 hash of its payload type and payload content.
//
// Since firmware v1.16 ACKs are deduplicated through this same hash table rather
// than a separate checksum table. Plain text-message ACKs carry a trailing
// random byte (see codec.BuildAckPayloadExt) so distinct ACKs hash differently
// and are not falsely collapsed.
package dedupe

import (
	"crypto/sha256"

	"github.com/kabili207/meshcore-go/core/codec"
)

const (
	// DefaultMaxPacketHashes is the default capacity for the packet hash table.
	DefaultMaxPacketHashes = 160
	// PacketHashSize is the truncated SHA256 hash size for packet deduplication.
	PacketHashSize = 8
)

// PacketDeduplicator tracks recently seen packets to prevent processing duplicates.
type PacketDeduplicator struct {
	hashes    []byte // circular buffer of PacketHashSize-byte hashes
	maxHashes int
	nextHash  int
}

// New creates a new PacketDeduplicator with the default buffer size.
func New() *PacketDeduplicator {
	return NewWithCapacity(DefaultMaxPacketHashes)
}

// NewWithCapacity creates a new PacketDeduplicator with the specified hash table size.
func NewWithCapacity(maxHashes int) *PacketDeduplicator {
	return &PacketDeduplicator{
		hashes:    make([]byte, maxHashes*PacketHashSize),
		maxHashes: maxHashes,
	}
}

// HasSeen checks if a packet has been seen before. If not, it records the
// packet and returns false. If it has been seen, it returns true.
//
// All packets, including ACKs, are tracked by a truncated SHA256 hash of their
// content.
func (d *PacketDeduplicator) HasSeen(packet *codec.Packet) bool {
	hash := CalculatePacketHash(packet)

	for i := range d.maxHashes {
		offset := i * PacketHashSize
		if sliceEqual(hash[:], d.hashes[offset:offset+PacketHashSize]) {
			return true
		}
	}

	offset := d.nextHash * PacketHashSize
	copy(d.hashes[offset:offset+PacketHashSize], hash[:])
	d.nextHash = (d.nextHash + 1) % d.maxHashes
	return false
}

// Clear resets the deduplicator, forgetting all previously seen packets.
func (d *PacketDeduplicator) Clear() {
	clear(d.hashes)
	d.nextHash = 0
}

// CalculatePacketHash computes the 8-byte deduplication hash for a packet.
// The hash is SHA256(payloadType, [pathLen for TRACE], payload) truncated to 8 bytes.
func CalculatePacketHash(packet *codec.Packet) [PacketHashSize]byte {
	h := sha256.New()
	t := packet.PayloadType()
	h.Write([]byte{t})
	if t == codec.PayloadTypeTrace {
		h.Write([]byte{packet.PathLen})
	}
	h.Write(packet.Payload)
	sum := h.Sum(nil)
	var result [PacketHashSize]byte
	copy(result[:], sum[:PacketHashSize])
	return result
}

func sliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
