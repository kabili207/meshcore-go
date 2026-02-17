// Package dedupe provides packet deduplication for MeshCore networks.
//
// It tracks recently seen packets using circular buffers, matching the
// firmware's SimpleMeshTables implementation. Regular packets are identified
// by an 8-byte SHA256 hash of their payload type and payload content. ACK
// packets are tracked separately by their 4-byte checksum value.
package dedupe

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core/codec"
)

const (
	// DefaultMaxPacketHashes is the default capacity for the packet hash table.
	DefaultMaxPacketHashes = 128
	// DefaultMaxAckHashes is the default capacity for the ACK hash table.
	DefaultMaxAckHashes = 64
	// PacketHashSize is the truncated SHA256 hash size for packet deduplication.
	PacketHashSize = 8
)

// PacketDeduplicator tracks recently seen packets to prevent processing duplicates.
type PacketDeduplicator struct {
	hashes    []byte // circular buffer of PacketHashSize-byte hashes
	acks      []uint32
	maxHashes int
	maxAcks   int
	nextHash  int
	nextAck   int
}

// New creates a new PacketDeduplicator with default buffer sizes.
func New() *PacketDeduplicator {
	return NewWithCapacity(DefaultMaxPacketHashes, DefaultMaxAckHashes)
}

// NewWithCapacity creates a new PacketDeduplicator with the specified buffer sizes.
func NewWithCapacity(maxHashes, maxAcks int) *PacketDeduplicator {
	return &PacketDeduplicator{
		hashes:    make([]byte, maxHashes*PacketHashSize),
		acks:      make([]uint32, maxAcks),
		maxHashes: maxHashes,
		maxAcks:   maxAcks,
	}
}

// HasSeen checks if a packet has been seen before. If not, it records the
// packet and returns false. If it has been seen, it returns true.
//
// ACK packets are tracked by their 4-byte checksum value in a separate table.
// All other packets are tracked by a truncated SHA256 hash of their content.
func (d *PacketDeduplicator) HasSeen(packet *codec.Packet) bool {
	if packet.PayloadType() == codec.PayloadTypeAck && len(packet.Payload) >= 4 {
		return d.hasSeenAck(packet)
	}
	return d.hasSeenPacket(packet)
}

func (d *PacketDeduplicator) hasSeenAck(packet *codec.Packet) bool {
	ack := binary.LittleEndian.Uint32(packet.Payload[:4])

	for i := range d.maxAcks {
		if d.acks[i] == ack {
			return true
		}
	}

	d.acks[d.nextAck] = ack
	d.nextAck = (d.nextAck + 1) % d.maxAcks
	return false
}

func (d *PacketDeduplicator) hasSeenPacket(packet *codec.Packet) bool {
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
	clear(d.acks)
	d.nextHash = 0
	d.nextAck = 0
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
