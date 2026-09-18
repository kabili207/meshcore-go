package codec

// Fletcher16 computes the Fletcher-16 checksum of the given data.
// This matches the implementation in MeshCore's BridgeBase.cpp.
//
// The sums are widened before the modulo. The firmware's uint8_t operands are
// promoted to int by C, so it never wraps at 256; uint8 arithmetic in Go would.
func Fletcher16(data []byte) uint16 {
	var sum1, sum2 uint16
	for _, b := range data {
		sum1 = (sum1 + uint16(b)) % 255
		sum2 = (sum2 + sum1) % 255
	}
	return sum2<<8 | sum1
}

// ValidateChecksum verifies that the calculated checksum matches the received checksum.
func ValidateChecksum(data []byte, received uint16) bool {
	return Fletcher16(data) == received
}
