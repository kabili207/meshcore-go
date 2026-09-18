package kiss

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrShortPayload is returned when a SetHardware payload is too short for the
// fields its sub-command declares. It corresponds to HWErrInvalidLength on the
// wire.
var ErrShortPayload = errors.New("kiss: payload too short")

// All multi-byte SetHardware fields are little-endian.

// RadioConfig is the LoRa configuration carried by SetRadio requests and Radio
// responses.
type RadioConfig struct {
	// FreqHz is the center frequency in hertz, e.g. 869618000.
	FreqHz uint32
	// BandwidthHz is the channel bandwidth in hertz, e.g. 62500.
	BandwidthHz uint32
	// SpreadingFactor is the LoRa spreading factor, 5-12.
	SpreadingFactor uint8
	// CodingRate is the LoRa coding rate denominator, 5-8.
	CodingRate uint8
}

// RadioConfigSize is the wire size of an encoded RadioConfig.
const RadioConfigSize = 10

// Encode serializes the config into its 10-byte wire form.
func (c RadioConfig) Encode() []byte {
	b := make([]byte, RadioConfigSize)
	binary.LittleEndian.PutUint32(b[0:4], c.FreqHz)
	binary.LittleEndian.PutUint32(b[4:8], c.BandwidthHz)
	b[8] = c.SpreadingFactor
	b[9] = c.CodingRate
	return b
}

// DecodeRadioConfig parses a SetRadio request or Radio response payload.
func DecodeRadioConfig(data []byte) (RadioConfig, error) {
	if len(data) < RadioConfigSize {
		return RadioConfig{}, fmt.Errorf("%w: radio config needs %d bytes, got %d", ErrShortPayload, RadioConfigSize, len(data))
	}
	return RadioConfig{
		FreqHz:          binary.LittleEndian.Uint32(data[0:4]),
		BandwidthHz:     binary.LittleEndian.Uint32(data[4:8]),
		SpreadingFactor: data[8],
		CodingRate:      data[9],
	}, nil
}

// Stats are the modem's lifetime packet counters.
type Stats struct {
	RxPackets uint32
	TxPackets uint32
	RxErrors  uint32
}

// StatsSize is the wire size of encoded Stats.
const StatsSize = 12

// Encode serializes the counters into their 12-byte wire form.
func (s Stats) Encode() []byte {
	b := make([]byte, StatsSize)
	binary.LittleEndian.PutUint32(b[0:4], s.RxPackets)
	binary.LittleEndian.PutUint32(b[4:8], s.TxPackets)
	binary.LittleEndian.PutUint32(b[8:12], s.RxErrors)
	return b
}

// DecodeStats parses a Stats response payload.
func DecodeStats(data []byte) (Stats, error) {
	if len(data) < StatsSize {
		return Stats{}, fmt.Errorf("%w: stats needs %d bytes, got %d", ErrShortPayload, StatsSize, len(data))
	}
	return Stats{
		RxPackets: binary.LittleEndian.Uint32(data[0:4]),
		TxPackets: binary.LittleEndian.Uint32(data[4:8]),
		RxErrors:  binary.LittleEndian.Uint32(data[8:12]),
	}, nil
}

// RxMeta is the signal report the modem sends immediately after each data
// frame, when signal reporting is enabled.
type RxMeta struct {
	// SNRQuarterDB is the signal-to-noise ratio in quarter-decibel steps, so
	// the value on the wire is four times the dB figure.
	SNRQuarterDB int8
	// RSSI is the received signal strength in dBm.
	RSSI int8
}

// RxMetaSize is the wire size of an encoded RxMeta.
const RxMetaSize = 2

// SNR returns the signal-to-noise ratio in decibels.
func (m RxMeta) SNR() float32 { return float32(m.SNRQuarterDB) / 4 }

// Encode serializes the signal report into its 2-byte wire form.
func (m RxMeta) Encode() []byte { return []byte{byte(m.SNRQuarterDB), byte(m.RSSI)} }

// DecodeRxMeta parses an RxMeta notification payload.
func DecodeRxMeta(data []byte) (RxMeta, error) {
	if len(data) < RxMetaSize {
		return RxMeta{}, fmt.Errorf("%w: rx meta needs %d bytes, got %d", ErrShortPayload, RxMetaSize, len(data))
	}
	return RxMeta{SNRQuarterDB: int8(data[0]), RSSI: int8(data[1])}, nil
}

// Composite crypto payloads. Each request concatenates fixed-size fields with a
// trailing variable-length remainder, so the split is by offset.

// BuildVerifyRequest builds a VerifySignature request payload.
func BuildVerifyRequest(pubKey, signature, message []byte) ([]byte, error) {
	if len(pubKey) != PubKeySize {
		return nil, fmt.Errorf("kiss: public key must be %d bytes, got %d", PubKeySize, len(pubKey))
	}
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("kiss: signature must be %d bytes, got %d", SignatureSize, len(signature))
	}
	b := make([]byte, 0, PubKeySize+SignatureSize+len(message))
	b = append(b, pubKey...)
	b = append(b, signature...)
	return append(b, message...), nil
}

// ParseVerifyRequest splits a VerifySignature request payload. The returned
// slices alias data.
func ParseVerifyRequest(data []byte) (pubKey, signature, message []byte, err error) {
	// The firmware requires at least one message byte, so the minimum is
	// one past the fixed fields.
	if len(data) < PubKeySize+SignatureSize+1 {
		return nil, nil, nil, fmt.Errorf("%w: verify needs at least %d bytes, got %d", ErrShortPayload, PubKeySize+SignatureSize+1, len(data))
	}
	return data[:PubKeySize], data[PubKeySize : PubKeySize+SignatureSize], data[PubKeySize+SignatureSize:], nil
}

// BuildEncryptRequest builds an EncryptData request payload. sharedSecret is
// the 32-byte secret whose first 16 bytes key the AES-128 cipher and whose full
// length keys the HMAC.
func BuildEncryptRequest(sharedSecret, plaintext []byte) ([]byte, error) {
	if len(sharedSecret) != PubKeySize {
		return nil, fmt.Errorf("kiss: shared secret must be %d bytes, got %d", PubKeySize, len(sharedSecret))
	}
	b := make([]byte, 0, PubKeySize+len(plaintext))
	b = append(b, sharedSecret...)
	return append(b, plaintext...), nil
}

// ParseEncryptRequest splits an EncryptData request payload. The returned
// slices alias data.
func ParseEncryptRequest(data []byte) (sharedSecret, plaintext []byte, err error) {
	if len(data) < PubKeySize+1 {
		return nil, nil, fmt.Errorf("%w: encrypt needs at least %d bytes, got %d", ErrShortPayload, PubKeySize+1, len(data))
	}
	return data[:PubKeySize], data[PubKeySize:], nil
}

// BuildDecryptRequest builds a DecryptData request payload. sealed is the MAC
// and ciphertext exactly as an Encrypted response returned them.
func BuildDecryptRequest(sharedSecret, sealed []byte) ([]byte, error) {
	if len(sharedSecret) != PubKeySize {
		return nil, fmt.Errorf("kiss: shared secret must be %d bytes, got %d", PubKeySize, len(sharedSecret))
	}
	b := make([]byte, 0, PubKeySize+len(sealed))
	b = append(b, sharedSecret...)
	return append(b, sealed...), nil
}

// ParseDecryptRequest splits a DecryptData request payload into the shared
// secret and the MAC-prefixed ciphertext. The returned slices alias data.
func ParseDecryptRequest(data []byte) (sharedSecret, sealed []byte, err error) {
	if len(data) < PubKeySize+CipherMACSize+1 {
		return nil, nil, fmt.Errorf("%w: decrypt needs at least %d bytes, got %d", ErrShortPayload, PubKeySize+CipherMACSize+1, len(data))
	}
	return data[:PubKeySize], data[PubKeySize:], nil
}

// HardwareError is an HWRespError frame received from the modem.
type HardwareError struct {
	Code uint8
}

func (e *HardwareError) Error() string {
	return "kiss: modem error: " + hardwareErrorText(e.Code)
}

func hardwareErrorText(code uint8) string {
	switch code {
	case HWErrInvalidLength:
		return "invalid length"
	case HWErrInvalidParam:
		return "invalid parameter"
	case HWErrNoCallback:
		return "feature not available"
	case HWErrMacFailed:
		return "MAC verification failed"
	case HWErrUnknownCmd:
		return "unknown sub-command"
	case HWErrEncryptFailed:
		return "encryption failed"
	case HWErrTxBusy:
		return "transmitter busy"
	default:
		return fmt.Sprintf("unknown error code 0x%02X", code)
	}
}
