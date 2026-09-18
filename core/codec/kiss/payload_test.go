package kiss

import (
	"bytes"
	"errors"
	"testing"
)

func TestRadioConfigRoundTrip(t *testing.T) {
	cfg := RadioConfig{FreqHz: 869618000, BandwidthHz: 62500, SpreadingFactor: 11, CodingRate: 5}
	enc := cfg.Encode()

	want := []byte{0x50, 0x51, 0xD5, 0x33, 0x24, 0xF4, 0x00, 0x00, 11, 5}
	if !bytes.Equal(enc, want) {
		t.Errorf("Encode = %x, want %x", enc, want)
	}

	got, err := DecodeRadioConfig(enc)
	if err != nil {
		t.Fatalf("DecodeRadioConfig: %v", err)
	}
	if got != cfg {
		t.Errorf("DecodeRadioConfig = %+v, want %+v", got, cfg)
	}
}

func TestDecodeRadioConfigShort(t *testing.T) {
	if _, err := DecodeRadioConfig(make([]byte, RadioConfigSize-1)); !errors.Is(err, ErrShortPayload) {
		t.Errorf("error = %v, want ErrShortPayload", err)
	}
}

func TestStatsRoundTrip(t *testing.T) {
	s := Stats{RxPackets: 1, TxPackets: 0x0102, RxErrors: 0xDEADBEEF}
	got, err := DecodeStats(s.Encode())
	if err != nil {
		t.Fatalf("DecodeStats: %v", err)
	}
	if got != s {
		t.Errorf("DecodeStats = %+v, want %+v", got, s)
	}
	if _, err := DecodeStats(make([]byte, StatsSize-1)); !errors.Is(err, ErrShortPayload) {
		t.Errorf("short stats error = %v, want ErrShortPayload", err)
	}
}

func TestRxMeta(t *testing.T) {
	m := RxMeta{SNRQuarterDB: -30, RSSI: -101}
	enc := m.Encode()
	if !bytes.Equal(enc, []byte{0xE2, 0x9B}) {
		t.Errorf("Encode = %x, want e29b", enc)
	}

	got, err := DecodeRxMeta(enc)
	if err != nil {
		t.Fatalf("DecodeRxMeta: %v", err)
	}
	if got != m {
		t.Errorf("DecodeRxMeta = %+v, want %+v", got, m)
	}
	if got.SNR() != -7.5 {
		t.Errorf("SNR() = %v, want -7.5", got.SNR())
	}
}

func TestVerifyRequestRoundTrip(t *testing.T) {
	pub := bytes.Repeat([]byte{0xAA}, PubKeySize)
	sig := bytes.Repeat([]byte{0xBB}, SignatureSize)
	msg := []byte("hello")

	payload, err := BuildVerifyRequest(pub, sig, msg)
	if err != nil {
		t.Fatalf("BuildVerifyRequest: %v", err)
	}

	gotPub, gotSig, gotMsg, err := ParseVerifyRequest(payload)
	if err != nil {
		t.Fatalf("ParseVerifyRequest: %v", err)
	}
	if !bytes.Equal(gotPub, pub) || !bytes.Equal(gotSig, sig) || !bytes.Equal(gotMsg, msg) {
		t.Errorf("round trip mismatch: pub %x sig %x msg %q", gotPub, gotSig, gotMsg)
	}
}

func TestBuildVerifyRequestRejectsWrongSizes(t *testing.T) {
	sig := bytes.Repeat([]byte{0xBB}, SignatureSize)
	if _, err := BuildVerifyRequest(make([]byte, 31), sig, []byte("x")); err == nil {
		t.Error("expected error for short public key")
	}
	pub := bytes.Repeat([]byte{0xAA}, PubKeySize)
	if _, err := BuildVerifyRequest(pub, make([]byte, 63), []byte("x")); err == nil {
		t.Error("expected error for short signature")
	}
}

func TestParseVerifyRequestShort(t *testing.T) {
	// Exactly the fixed fields with no message is one byte short, matching the
	// firmware's minimum.
	if _, _, _, err := ParseVerifyRequest(make([]byte, PubKeySize+SignatureSize)); !errors.Is(err, ErrShortPayload) {
		t.Errorf("error = %v, want ErrShortPayload", err)
	}
}

func TestEncryptDecryptRequestSplit(t *testing.T) {
	secret := bytes.Repeat([]byte{0x11}, PubKeySize)

	encReq, err := BuildEncryptRequest(secret, []byte("plain"))
	if err != nil {
		t.Fatalf("BuildEncryptRequest: %v", err)
	}
	gotSecret, gotPlain, err := ParseEncryptRequest(encReq)
	if err != nil {
		t.Fatalf("ParseEncryptRequest: %v", err)
	}
	if !bytes.Equal(gotSecret, secret) || string(gotPlain) != "plain" {
		t.Errorf("encrypt split = %x / %q", gotSecret, gotPlain)
	}

	sealed := []byte{0xAB, 0xCD, 1, 2, 3}
	decReq, err := BuildDecryptRequest(secret, sealed)
	if err != nil {
		t.Fatalf("BuildDecryptRequest: %v", err)
	}
	gotSecret, gotSealed, err := ParseDecryptRequest(decReq)
	if err != nil {
		t.Fatalf("ParseDecryptRequest: %v", err)
	}
	if !bytes.Equal(gotSecret, secret) || !bytes.Equal(gotSealed, sealed) {
		t.Errorf("decrypt split = %x / %x", gotSecret, gotSealed)
	}
}

func TestParseDecryptRequestShort(t *testing.T) {
	// Secret plus a MAC but no ciphertext byte.
	if _, _, err := ParseDecryptRequest(make([]byte, PubKeySize+CipherMACSize)); !errors.Is(err, ErrShortPayload) {
		t.Errorf("error = %v, want ErrShortPayload", err)
	}
}

func TestHardwareErrorMessages(t *testing.T) {
	err := &HardwareError{Code: HWErrTxBusy}
	if err.Error() != "kiss: modem error: transmitter busy" {
		t.Errorf("Error() = %q", err.Error())
	}
	unknown := &HardwareError{Code: 0x7F}
	if unknown.Error() != "kiss: modem error: unknown error code 0x7F" {
		t.Errorf("Error() = %q", unknown.Error())
	}
}
