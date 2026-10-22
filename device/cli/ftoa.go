package cli

import (
	"math"
	"strconv"
	"strings"
)

// Ftoa formats f the way firmware's StrHelper::ftoa does, so CLI replies match
// byte for byte. The value is taken as a float32 and truncated, not rounded, to
// 7 decimal places. Trailing zeros are dropped, but one decimal always stays:
// 915 is "915.0" and 869.618 is "869.6179809". Out-of-range values, which
// firmware flags as an error, give "0".
func Ftoa(f float32) string {
	if f == 0 {
		return "0.0"
	}
	bits := math.Float32bits(f)
	exp2 := int(uint8(bits>>23)) - 127
	mantissa := bits&0xFFFFFF | 0x800000

	var intPart, fracPart uint32
	switch {
	case exp2 >= 31 || exp2 < -23:
		return "0"
	case exp2 >= 23:
		intPart = mantissa << (exp2 - 23)
	case exp2 >= 0:
		intPart = mantissa >> (23 - exp2)
		fracPart = (mantissa << (exp2 + 1)) & 0xFFFFFF
	default:
		fracPart = (mantissa & 0xFFFFFF) >> -(exp2 + 1)
	}

	var b strings.Builder
	if bits>>31 != 0 {
		b.WriteByte('-')
	}
	b.WriteString(strconv.FormatUint(uint64(intPart), 10))
	b.WriteByte('.')
	if fracPart == 0 {
		b.WriteByte('0')
		return b.String()
	}
	var digits [7]byte
	for i := range digits {
		fracPart *= 10
		digits[i] = byte(fracPart>>24) + '0'
		fracPart &= 0xFFFFFF
	}
	frac := strings.TrimRight(string(digits[:]), "0")
	if frac == "" {
		frac = "0"
	}
	b.WriteString(frac)
	return b.String()
}
