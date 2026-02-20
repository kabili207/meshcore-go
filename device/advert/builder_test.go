package advert

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

func generateTestKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	return kp
}

func makeSelfAdvertConfig(t *testing.T, name string, nodeType uint8) (*SelfAdvertConfig, *crypto.KeyPair) {
	t.Helper()
	kp := generateTestKeyPair(t)
	clk := clock.New()

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)

	cfg := &SelfAdvertConfig{
		PrivateKey: kp.PrivateKey,
		PublicKey:  pubKey,
		Clock:     clk,
		AppData: &codec.AdvertAppData{
			NodeType: nodeType,
			Name:     name,
		},
	}
	return cfg, kp
}

func TestBuildSelfAdvert(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "TestNode", codec.NodeTypeChat)

	pkt, err := BuildSelfAdvert(cfg)
	if err != nil {
		t.Fatalf("BuildSelfAdvert failed: %v", err)
	}

	// Verify packet header
	if pkt.PayloadType() != codec.PayloadTypeAdvert {
		t.Errorf("payload type = %d, want %d (ADVERT)", pkt.PayloadType(), codec.PayloadTypeAdvert)
	}

	// Verify the payload can be parsed
	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload failed: %v", err)
	}

	if advert.PubKey != cfg.PublicKey {
		t.Error("pubkey mismatch")
	}
	if advert.Timestamp == 0 {
		t.Error("timestamp should not be zero")
	}
	if advert.AppData == nil {
		t.Fatal("appdata should not be nil")
	}
	if advert.AppData.Name != "TestNode" {
		t.Errorf("name = %q, want %q", advert.AppData.Name, "TestNode")
	}
	if advert.AppData.NodeType != codec.NodeTypeChat {
		t.Errorf("nodeType = %d, want %d", advert.AppData.NodeType, codec.NodeTypeChat)
	}

	// Verify signature
	if !crypto.VerifyAdvert(advert) {
		t.Error("ADVERT signature should verify")
	}
}

func TestBuildSelfAdvert_WithLocation(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "GpsNode", codec.NodeTypeRepeater)
	lat := 37.7749
	lon := -122.4194
	cfg.AppData.Lat = &lat
	cfg.AppData.Lon = &lon

	pkt, err := BuildSelfAdvert(cfg)
	if err != nil {
		t.Fatalf("BuildSelfAdvert failed: %v", err)
	}

	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload failed: %v", err)
	}

	if !advert.AppData.HasLocation() {
		t.Error("expected location in appdata")
	}
	if !crypto.VerifyAdvert(advert) {
		t.Error("ADVERT with location should verify")
	}
}

func TestBuildSelfAdvert_Minimal(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "Min", codec.NodeTypeSensor)

	pkt, err := BuildSelfAdvert(cfg)
	if err != nil {
		t.Fatalf("BuildSelfAdvert failed: %v", err)
	}

	advert, err := codec.ParseAdvertPayload(pkt.Payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload failed: %v", err)
	}

	if advert.AppData.HasLocation() {
		t.Error("minimal advert should not have location")
	}
	if !crypto.VerifyAdvert(advert) {
		t.Error("minimal ADVERT should verify")
	}
}

func TestBuildSelfAdvert_PacketFormat(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "Node", codec.NodeTypeChat)

	pkt, err := BuildSelfAdvert(cfg)
	if err != nil {
		t.Fatalf("BuildSelfAdvert failed: %v", err)
	}

	// Header should have ADVERT type and version 0
	expectedHeader := uint8(codec.PayloadTypeAdvert << codec.PHTypeShift)
	if pkt.Header != expectedHeader {
		t.Errorf("header = 0x%02X, want 0x%02X", pkt.Header, expectedHeader)
	}

	// Path should be empty
	if pkt.PathLen != 0 {
		t.Errorf("PathLen = %d, want 0", pkt.PathLen)
	}

	// Payload should be at least AdvertMinSize
	if len(pkt.Payload) < codec.AdvertMinSize {
		t.Errorf("payload len = %d, want >= %d", len(pkt.Payload), codec.AdvertMinSize)
	}
}

func TestNewSelfAdvertBuilder(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "Builder", codec.NodeTypeChat)

	// Use a controllable clock to verify advancing timestamps
	clk := clock.New()
	clk.SetCurrentTime(1000)
	cfg.Clock = clk

	builder := NewSelfAdvertBuilder(cfg)

	pkt1 := builder()
	if pkt1 == nil {
		t.Fatal("builder returned nil")
	}

	advert1, _ := codec.ParseAdvertPayload(pkt1.Payload)

	// Advance the clock
	clk.SetCurrentTime(2000)

	pkt2 := builder()
	if pkt2 == nil {
		t.Fatal("builder returned nil on second call")
	}

	advert2, _ := codec.ParseAdvertPayload(pkt2.Payload)

	if advert2.Timestamp <= advert1.Timestamp {
		t.Errorf("second timestamp (%d) should be > first (%d)", advert2.Timestamp, advert1.Timestamp)
	}
}

func TestBuildSelfAdvert_RoundTrip(t *testing.T) {
	cfg, _ := makeSelfAdvertConfig(t, "RoundTrip", codec.NodeTypeRoom)
	lat := -33.8688
	lon := 151.2093
	cfg.AppData.Lat = &lat
	cfg.AppData.Lon = &lon

	pkt, err := BuildSelfAdvert(cfg)
	if err != nil {
		t.Fatalf("BuildSelfAdvert failed: %v", err)
	}

	// Serialize and re-parse
	raw := pkt.WriteTo()
	var parsed codec.Packet
	if err := parsed.ReadFrom(raw); err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}

	advert, err := codec.ParseAdvertPayload(parsed.Payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload failed: %v", err)
	}

	if advert.PubKey != cfg.PublicKey {
		t.Error("pubkey mismatch after round-trip")
	}
	if !crypto.VerifyAdvert(advert) {
		t.Error("signature invalid after round-trip")
	}
	if advert.AppData.Name != "RoundTrip" {
		t.Errorf("name = %q, want %q", advert.AppData.Name, "RoundTrip")
	}
}
