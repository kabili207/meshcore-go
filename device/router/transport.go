package router

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/kabili207/meshcore-go/core/codec"
)

// TransportKey is a 16-byte key used for transport code computation.
// It enables network isolation: only packets with matching transport codes
// are forwarded by repeaters.
type TransportKey [16]byte

// TransportKeyFromRegion derives a transport key from a region name.
// The key is SHA256(regionName) truncated to 16 bytes. This matches the
// firmware's getAutoKeyFor() for hashtag regions.
func TransportKeyFromRegion(regionName string) TransportKey {
	hash := sha256.Sum256([]byte(regionName))
	var key TransportKey
	copy(key[:], hash[:16])
	return key
}

// CalcTransportCode computes the 2-byte transport code for a packet.
// The code is HMAC-SHA256(key, payloadType || payload)[0:2] as uint16 LE.
// Reserved values 0x0000 and 0xFFFF are bumped to 0x0001 and 0xFFFE.
//
// This matches the firmware's TransportKey::calcTransportCode().
func (k TransportKey) CalcTransportCode(pkt *codec.Packet) uint16 {
	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte{pkt.PayloadType()})
	mac.Write(pkt.Payload)
	sum := mac.Sum(nil)

	code := binary.LittleEndian.Uint16(sum[:2])
	if code == 0x0000 {
		code = 0x0001
	} else if code == 0xFFFF {
		code = 0xFFFE
	}
	return code
}

// IsNull returns true if the key is all zeros.
func (k TransportKey) IsNull() bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// TransportCodeValidator determines whether a packet with transport codes
// should be accepted. Return true to accept, false to drop.
type TransportCodeValidator func(pkt *codec.Packet) bool

// NewTransportCodeValidator creates a validator that checks the packet's
// TransportCodes[0] against a set of transport keys. If any key produces a
// matching code, the packet is accepted.
func NewTransportCodeValidator(keys []TransportKey) TransportCodeValidator {
	return func(pkt *codec.Packet) bool {
		for i := range keys {
			if keys[i].CalcTransportCode(pkt) == pkt.TransportCodes[0] {
				return true
			}
		}
		return false
	}
}
