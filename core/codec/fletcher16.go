package codec

// Fletcher16 computes the Fletcher-16 checksum of the given data.
// This matches the implementation in MeshCore's BridgeBase.cpp.
func Fletcher16(data []byte) uint16 {
	var sum1, sum2 uint8
	for _, b := range data {
		sum1 = (sum1 + b) % 255
		sum2 = (sum2 + sum1) % 255
	}
	return uint16(sum2)<<8 | uint16(sum1)
}

// ValidateChecksum verifies that the calculated checksum matches the received checksum.
func ValidateChecksum(data []byte, received uint16) bool {
	return Fletcher16(data) == received
}
