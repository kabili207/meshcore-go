package router

import "time"

// RadioParams are the LoRa settings of the mesh a node relays for. A
// transport-attached node has no radio of its own, but firmware scales its
// retransmit delays by each packet's airtime, so the router needs them to
// space its relays the same way.
type RadioParams struct {
	BandwidthKHz    float64 // e.g. 62.5
	SpreadingFactor uint8   // 5-12
	CodingRate      uint8   // 5-8, meaning 4/5 to 4/8
}

// DefaultRadioParams is firmware's documented default radio, 869.618,62.5,8,5
// (only bandwidth, spreading factor and coding rate affect airtime).
var DefaultRadioParams = RadioParams{BandwidthKHz: 62.5, SpreadingFactor: 8, CodingRate: 5}

// Airtime estimates how long a LoRa packet of n bytes spends on air, the value
// firmware's getEstAirtimeFor returns. It is ported from RadioLib 7.7.1's
// SX126x::calculateTimeOnAir with MeshCore's radio setup: a 16-symbol
// preamble, CRC on, an explicit header, and low data rate optimization
// switched on automatically once a symbol lasts 16 ms. Like firmware, the
// result is truncated to whole milliseconds.
func (p RadioParams) Airtime(n int) time.Duration {
	sf := uint32(p.SpreadingFactor)
	bw := float32(p.BandwidthKHz)
	if sf < 5 || sf > 12 || bw <= 0 || p.CodingRate < 5 || p.CodingRate > 8 {
		return 0
	}

	symbolUS := uint32(float32(uint32(10000)<<sf) / (bw * 10))
	coeff1x4, coeff2 := uint32(17), int32(8) // 4.25 symbols, x4
	if sf == 5 || sf == 6 {
		coeff1x4, coeff2 = 25, 0
	}
	divisor := int32(4 * sf)
	if float32(uint32(1)<<sf)/bw >= 16 { // low data rate optimization
		divisor = int32(4 * (sf - 2))
	}

	const crcBits, headerBits = 16, 20
	bits := 8*int32(n) + crcBits - 4*int32(sf) + coeff2 + headerBits
	if bits < 0 {
		bits = 0
	}
	coded := uint32((bits + divisor - 1) / divisor)
	symbolsX4 := (16+8)*4 + coeff1x4 + coded*uint32(p.CodingRate)*4

	us := symbolUS * symbolsX4 / 4
	return time.Duration(us/1000) * time.Millisecond
}
