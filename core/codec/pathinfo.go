package codec

// Path hash mode constants. The upper 2 bits of the path_len wire byte encode
// the hash size mode, and the lower 6 bits encode the hop count.
//
// Firmware v1.14.0 introduced variable-width path hashes. Mode 0 (1-byte)
// is backward-compatible with pre-1.14 firmware.
const (
	PathHashMode1Byte = 0 // 1-byte hashes (default, backward-compatible)
	PathHashMode2Byte = 1 // 2-byte hashes (65536 possible values)
	PathHashMode3Byte = 2 // 3-byte hashes (16M possible values)

	PathHashModeShift = 6    // Bit position of the mode field
	PathHashModeMask  = 0xC0 // Bits 7-6 of the path_len wire byte
	PathHopCountMask  = 0x3F // Bits 5-0 of the path_len wire byte
	MaxHopCount       = 63   // Maximum hop count (6-bit field)
)

// PathInfo encapsulates the variable-width path encoding introduced in
// firmware v1.14.0. It decodes the path_len wire byte into its two components:
// hash size (1, 2, or 3 bytes per hop) and hop count (0-63).
type PathInfo struct {
	HashSize uint8 // Bytes per path hash: 1, 2, or 3
	HopCount uint8 // Number of hops in the path: 0-63
}

// PathInfoFromWireByte decodes a path_len wire byte into a PathInfo.
func PathInfoFromWireByte(b uint8) PathInfo {
	mode := (b >> PathHashModeShift) & 0x03
	return PathInfo{
		HashSize: mode + 1,
		HopCount: b & PathHopCountMask,
	}
}

// ToWireByte encodes a PathInfo back to a path_len wire byte.
func (p PathInfo) ToWireByte() uint8 {
	return ((p.HashSize - 1) << PathHashModeShift) | (p.HopCount & PathHopCountMask)
}

// ByteLen returns the total number of path bytes on the wire.
func (p PathInfo) ByteLen() int {
	return int(p.HopCount) * int(p.HashSize)
}
