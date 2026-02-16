package codec

import (
	"encoding/binary"
	"testing"
)

func TestParseAdvertPayload(t *testing.T) {
	// Build a minimal valid ADVERT payload
	payload := make([]byte, AdvertMinSize)

	// Set public key (32 bytes)
	for i := 0; i < 32; i++ {
		payload[i] = byte(i)
	}

	// Set timestamp (little endian)
	binary.LittleEndian.PutUint32(payload[32:36], 1704067200) // 2024-01-01 00:00:00 UTC

	// Set signature (64 bytes)
	for i := 0; i < 64; i++ {
		payload[36+i] = byte(i + 100)
	}

	advert, err := ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	// Verify public key
	for i := 0; i < 32; i++ {
		if advert.PubKey[i] != byte(i) {
			t.Errorf("PubKey[%d] = %d, want %d", i, advert.PubKey[i], i)
		}
	}

	// Verify timestamp
	if advert.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", advert.Timestamp, 1704067200)
	}

	// Verify signature
	for i := 0; i < 64; i++ {
		if advert.Signature[i] != byte(i+100) {
			t.Errorf("Signature[%d] = %d, want %d", i, advert.Signature[i], i+100)
		}
	}

	// No appdata
	if advert.AppData != nil {
		t.Error("AppData should be nil for minimal payload")
	}
}

func TestParseAdvertPayloadWithAppData(t *testing.T) {
	// Build ADVERT payload with appdata
	payload := make([]byte, AdvertMinSize+1+4+4+len("TestNode"))

	// Set minimal pubkey/timestamp/signature
	for i := 0; i < 32; i++ {
		payload[i] = byte(i)
	}
	binary.LittleEndian.PutUint32(payload[32:36], 1704067200)
	for i := 0; i < 64; i++ {
		payload[36+i] = 0xAA
	}

	// AppData: flags (chat node + has location + has name)
	offset := AdvertMinSize
	payload[offset] = NodeTypeChat | FlagHasLocation | FlagHasName
	offset++

	// Latitude: 37.7749 * 1_000_000 = 37774900
	binary.LittleEndian.PutUint32(payload[offset:offset+4], 37774900)
	offset += 4

	// Longitude: -122.4194 * 1_000_000 = -122419400
	lonRaw := int32(-122419400)
	binary.LittleEndian.PutUint32(payload[offset:offset+4], uint32(lonRaw))
	offset += 4

	// Name
	copy(payload[offset:], "TestNode")

	advert, err := ParseAdvertPayload(payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if advert.AppData == nil {
		t.Fatal("AppData should not be nil")
	}

	// Check node type
	if advert.AppData.NodeType != NodeTypeChat {
		t.Errorf("NodeType = %d, want %d", advert.AppData.NodeType, NodeTypeChat)
	}

	// Check name
	if advert.AppData.Name != "TestNode" {
		t.Errorf("Name = %s, want TestNode", advert.AppData.Name)
	}

	// Check location
	if advert.AppData.Lat == nil || advert.AppData.Lon == nil {
		t.Fatal("Location should not be nil")
	}

	// Allow small floating point error
	expectedLat := 37.7749
	expectedLon := -122.4194
	if *advert.AppData.Lat < expectedLat-0.0001 || *advert.AppData.Lat > expectedLat+0.0001 {
		t.Errorf("Lat = %f, want ~%f", *advert.AppData.Lat, expectedLat)
	}
	if *advert.AppData.Lon < expectedLon-0.0001 || *advert.AppData.Lon > expectedLon+0.0001 {
		t.Errorf("Lon = %f, want ~%f", *advert.AppData.Lon, expectedLon)
	}
}

func TestParseAdvertPayloadTooShort(t *testing.T) {
	payload := make([]byte, AdvertMinSize-1)
	_, err := ParseAdvertPayload(payload)
	if err == nil {
		t.Error("ParseAdvertPayload() should error on short payload")
	}
}

func TestParseAdvertAppData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		wantType    uint8
		wantName    string
		wantHasLoc  bool
		wantLat     float64
		wantLon     float64
		wantFeature1 *uint16
		wantFeature2 *uint16
	}{
		{
			name:     "chat node, name only",
			data:     append([]byte{NodeTypeChat | FlagHasName}, []byte("Alice")...),
			wantType: NodeTypeChat,
			wantName: "Alice",
		},
		{
			name:     "repeater, no extras",
			data:     []byte{NodeTypeRepeater},
			wantType: NodeTypeRepeater,
			wantName: "",
		},
		{
			name:       "room with location",
			data:       buildAppDataWithLocation(NodeTypeRoom, 40000000, -74000000),
			wantType:   NodeTypeRoom,
			wantHasLoc: true,
			wantLat:    40.0,
			wantLon:    -74.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appData, err := ParseAdvertAppData(tt.data)
			if err != nil {
				t.Fatalf("ParseAdvertAppData() error = %v", err)
			}

			if appData.NodeType != tt.wantType {
				t.Errorf("NodeType = %d, want %d", appData.NodeType, tt.wantType)
			}
			if appData.Name != tt.wantName {
				t.Errorf("Name = %s, want %s", appData.Name, tt.wantName)
			}
			if appData.HasLocation() != tt.wantHasLoc {
				t.Errorf("HasLocation() = %v, want %v", appData.HasLocation(), tt.wantHasLoc)
			}
			if tt.wantHasLoc {
				if *appData.Lat != tt.wantLat {
					t.Errorf("Lat = %f, want %f", *appData.Lat, tt.wantLat)
				}
				if *appData.Lon != tt.wantLon {
					t.Errorf("Lon = %f, want %f", *appData.Lon, tt.wantLon)
				}
			}
		})
	}
}

func buildAppDataWithLocation(nodeType uint8, lat, lon int32) []byte {
	data := make([]byte, 1+8)
	data[0] = nodeType | FlagHasLocation
	binary.LittleEndian.PutUint32(data[1:5], uint32(lat))
	binary.LittleEndian.PutUint32(data[5:9], uint32(lon))
	return data
}

func TestNodeTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{NodeTypeChat, "chat"},
		{NodeTypeRepeater, "repeater"},
		{NodeTypeRoom, "room"},
		{NodeTypeSensor, "sensor"},
		{0, "unknown"},
		{5, "unknown(5)"},
	}

	for _, tt := range tests {
		if got := NodeTypeName(tt.typ); got != tt.want {
			t.Errorf("NodeTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// ACK Payload Tests
// -----------------------------------------------------------------------------

func TestParseAckPayload(t *testing.T) {
	// Build a valid ACK payload
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 0xDEADBEEF)

	ack, err := ParseAckPayload(data)
	if err != nil {
		t.Fatalf("ParseAckPayload() error = %v", err)
	}

	if ack.Checksum != 0xDEADBEEF {
		t.Errorf("Checksum = %08x, want %08x", ack.Checksum, 0xDEADBEEF)
	}
}

func TestParseAckPayloadTooShort(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03} // Only 3 bytes
	_, err := ParseAckPayload(data)
	if err == nil {
		t.Error("ParseAckPayload() should error on short payload")
	}
}

// -----------------------------------------------------------------------------
// Addressed Payload Tests
// -----------------------------------------------------------------------------

func TestParseAddressedPayload(t *testing.T) {
	data := []byte{
		0xAA,       // dest_hash
		0xBB,       // src_hash
		0x34, 0x12, // MAC (little endian: 0x1234)
		0xDE, 0xAD, 0xBE, 0xEF, // ciphertext
	}

	addr, err := ParseAddressedPayload(data)
	if err != nil {
		t.Fatalf("ParseAddressedPayload() error = %v", err)
	}

	if addr.DestHash != 0xAA {
		t.Errorf("DestHash = %02x, want %02x", addr.DestHash, 0xAA)
	}
	if addr.SrcHash != 0xBB {
		t.Errorf("SrcHash = %02x, want %02x", addr.SrcHash, 0xBB)
	}
	if addr.MAC != 0x1234 {
		t.Errorf("MAC = %04x, want %04x", addr.MAC, 0x1234)
	}
	if len(addr.Ciphertext) != 4 {
		t.Errorf("Ciphertext length = %d, want 4", len(addr.Ciphertext))
	}
}

func TestParseAddressedPayloadTooShort(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0x12} // Only 3 bytes
	_, err := ParseAddressedPayload(data)
	if err == nil {
		t.Error("ParseAddressedPayload() should error on short payload")
	}
}

// -----------------------------------------------------------------------------
// Text Message Content Tests
// -----------------------------------------------------------------------------

func TestParseTxtMsgContent(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		wantType   uint8
		wantAttempt uint8
		wantMsg    string
	}{
		{
			name: "plain text message",
			data: func() []byte {
				d := make([]byte, 5+len("Hello"))
				binary.LittleEndian.PutUint32(d, 1704067200)
				d[4] = TxtTypePlain << 2 // type in upper 6 bits
				copy(d[5:], "Hello")
				return d
			}(),
			wantType:   TxtTypePlain,
			wantAttempt: 0,
			wantMsg:    "Hello",
		},
		{
			name: "CLI command with attempt",
			data: func() []byte {
				d := make([]byte, 5+len("/help"))
				binary.LittleEndian.PutUint32(d, 1704067200)
				d[4] = (TxtTypeCLI << 2) | 0x02 // type + attempt 2
				copy(d[5:], "/help")
				return d
			}(),
			wantType:   TxtTypeCLI,
			wantAttempt: 2,
			wantMsg:    "/help",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content, err := ParseTxtMsgContent(tt.data)
			if err != nil {
				t.Fatalf("ParseTxtMsgContent() error = %v", err)
			}

			if content.TxtType != tt.wantType {
				t.Errorf("TxtType = %d, want %d", content.TxtType, tt.wantType)
			}
			if content.Attempt != tt.wantAttempt {
				t.Errorf("Attempt = %d, want %d", content.Attempt, tt.wantAttempt)
			}
			if content.Message != tt.wantMsg {
				t.Errorf("Message = %s, want %s", content.Message, tt.wantMsg)
			}
		})
	}
}

func TestParseTxtMsgContentSigned(t *testing.T) {
	data := make([]byte, 9+len("Signed msg"))
	binary.LittleEndian.PutUint32(data, 1704067200)
	data[4] = TxtTypeSigned << 2
	// Pubkey prefix
	data[5] = 0xAA
	data[6] = 0xBB
	data[7] = 0xCC
	data[8] = 0xDD
	copy(data[9:], "Signed msg")

	content, err := ParseTxtMsgContent(data)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if content.TxtType != TxtTypeSigned {
		t.Errorf("TxtType = %d, want %d", content.TxtType, TxtTypeSigned)
	}
	if len(content.SenderPubKeyPrefix) != 4 {
		t.Fatalf("SenderPubKeyPrefix length = %d, want 4", len(content.SenderPubKeyPrefix))
	}
	if content.SenderPubKeyPrefix[0] != 0xAA || content.SenderPubKeyPrefix[3] != 0xDD {
		t.Errorf("SenderPubKeyPrefix = %v, want [AA BB CC DD]", content.SenderPubKeyPrefix)
	}
	if content.Message != "Signed msg" {
		t.Errorf("Message = %s, want 'Signed msg'", content.Message)
	}
}

// -----------------------------------------------------------------------------
// Request Content Tests
// -----------------------------------------------------------------------------

func TestParseRequestContent(t *testing.T) {
	data := make([]byte, 5+3)
	binary.LittleEndian.PutUint32(data, 1704067200)
	data[4] = ReqTypeGetStats
	data[5] = 0x01
	data[6] = 0x02
	data[7] = 0x03

	req, err := ParseRequestContent(data)
	if err != nil {
		t.Fatalf("ParseRequestContent() error = %v", err)
	}

	if req.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", req.Timestamp, 1704067200)
	}
	if req.RequestType != ReqTypeGetStats {
		t.Errorf("RequestType = %d, want %d", req.RequestType, ReqTypeGetStats)
	}
	if len(req.RequestData) != 3 {
		t.Errorf("RequestData length = %d, want 3", len(req.RequestData))
	}
}

func TestRequestTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{ReqTypeGetStats, "get_stats"},
		{ReqTypeKeepalive, "keepalive"},
		{ReqTypeGetTelemetry, "get_telemetry"},
		{ReqTypeGetNeighbors, "get_neighbors"},
		{0xFF, "unknown(255)"},
	}

	for _, tt := range tests {
		if got := RequestTypeName(tt.typ); got != tt.want {
			t.Errorf("RequestTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Group Payload Tests
// -----------------------------------------------------------------------------

func TestParseGroupPayload(t *testing.T) {
	data := []byte{
		0xCC,       // channel_hash
		0x78, 0x56, // MAC (little endian: 0x5678)
		0x11, 0x22, 0x33, // ciphertext
	}

	grp, err := ParseGroupPayload(data)
	if err != nil {
		t.Fatalf("ParseGroupPayload() error = %v", err)
	}

	if grp.ChannelHash != 0xCC {
		t.Errorf("ChannelHash = %02x, want %02x", grp.ChannelHash, 0xCC)
	}
	if grp.MAC != 0x5678 {
		t.Errorf("MAC = %04x, want %04x", grp.MAC, 0x5678)
	}
	if len(grp.Ciphertext) != 3 {
		t.Errorf("Ciphertext length = %d, want 3", len(grp.Ciphertext))
	}
}

func TestParseGroupPayloadTooShort(t *testing.T) {
	data := []byte{0xCC, 0x78} // Only 2 bytes
	_, err := ParseGroupPayload(data)
	if err == nil {
		t.Error("ParseGroupPayload() should error on short payload")
	}
}

// -----------------------------------------------------------------------------
// Anonymous Request Payload Tests
// -----------------------------------------------------------------------------

func TestParseAnonReqPayload(t *testing.T) {
	data := make([]byte, AnonReqHeaderSize+4)
	data[0] = 0xDD // dest_hash
	for i := 0; i < 32; i++ {
		data[1+i] = byte(i) // pubkey
	}
	binary.LittleEndian.PutUint16(data[33:35], 0xABCD) // MAC
	// ciphertext
	data[35] = 0xEE
	data[36] = 0xFF
	data[37] = 0x00
	data[38] = 0x11

	anon, err := ParseAnonReqPayload(data)
	if err != nil {
		t.Fatalf("ParseAnonReqPayload() error = %v", err)
	}

	if anon.DestHash != 0xDD {
		t.Errorf("DestHash = %02x, want %02x", anon.DestHash, 0xDD)
	}
	if anon.PubKey[0] != 0x00 || anon.PubKey[31] != 31 {
		t.Errorf("PubKey not correctly parsed")
	}
	if anon.MAC != 0xABCD {
		t.Errorf("MAC = %04x, want %04x", anon.MAC, 0xABCD)
	}
	if len(anon.Ciphertext) != 4 {
		t.Errorf("Ciphertext length = %d, want 4", len(anon.Ciphertext))
	}
}

func TestParseAnonReqPayloadTooShort(t *testing.T) {
	data := make([]byte, AnonReqHeaderSize-1)
	_, err := ParseAnonReqPayload(data)
	if err == nil {
		t.Error("ParseAnonReqPayload() should error on short payload")
	}
}

// -----------------------------------------------------------------------------
// Control Payload Tests
// -----------------------------------------------------------------------------

func TestParseControlPayload(t *testing.T) {
	data := []byte{
		0x82, // flags: subtype=8 (DISCOVER_REQ), lower bits=2
		0x0F, // type_filter
		0x12, 0x34, 0x56, 0x78, // tag
	}

	ctrl, err := ParseControlPayload(data)
	if err != nil {
		t.Fatalf("ParseControlPayload() error = %v", err)
	}

	if ctrl.Flags != 0x82 {
		t.Errorf("Flags = %02x, want %02x", ctrl.Flags, 0x82)
	}
	if ctrl.Subtype != 0x08 {
		t.Errorf("Subtype = %02x, want %02x", ctrl.Subtype, 0x08)
	}
	if len(ctrl.Data) != 5 {
		t.Errorf("Data length = %d, want 5", len(ctrl.Data))
	}
}

func TestParseDiscoverReqFromControl(t *testing.T) {
	// Build DISCOVER_REQ control payload
	data := []byte{
		0x81, // flags: subtype=8, prefix_only=1
		0x0F, // type_filter (all types)
		0x12, 0x34, 0x56, 0x78, // tag
		0x00, 0x00, 0x00, 0x00, // since (optional)
	}

	ctrl, err := ParseControlPayload(data)
	if err != nil {
		t.Fatalf("ParseControlPayload() error = %v", err)
	}

	discReq, err := ParseDiscoverReqFromControl(ctrl)
	if err != nil {
		t.Fatalf("ParseDiscoverReqFromControl() error = %v", err)
	}

	if !discReq.PrefixOnly {
		t.Error("PrefixOnly = false, want true")
	}
	if discReq.TypeFilter != 0x0F {
		t.Errorf("TypeFilter = %02x, want %02x", discReq.TypeFilter, 0x0F)
	}
	if discReq.Tag != 0x78563412 {
		t.Errorf("Tag = %08x, want %08x", discReq.Tag, 0x78563412)
	}
}

func TestParseDiscoverRespFromControl(t *testing.T) {
	// Build DISCOVER_RESP control payload
	pubkey := make([]byte, 8) // prefix only
	for i := range pubkey {
		pubkey[i] = byte(i + 0xA0)
	}

	data := make([]byte, 1+1+4+len(pubkey))
	data[0] = 0x91                                    // flags: subtype=9, node_type=1 (chat)
	data[1] = 40                                      // SNR = 10.0 dB (40/4)
	binary.LittleEndian.PutUint32(data[2:6], 0x12345678) // tag
	copy(data[6:], pubkey)

	ctrl, err := ParseControlPayload(data)
	if err != nil {
		t.Fatalf("ParseControlPayload() error = %v", err)
	}

	discResp, err := ParseDiscoverRespFromControl(ctrl)
	if err != nil {
		t.Fatalf("ParseDiscoverRespFromControl() error = %v", err)
	}

	if discResp.NodeType != NodeTypeChat {
		t.Errorf("NodeType = %d, want %d", discResp.NodeType, NodeTypeChat)
	}
	if discResp.GetSNR() != 10.0 {
		t.Errorf("GetSNR() = %f, want 10.0", discResp.GetSNR())
	}
	if discResp.Tag != 0x12345678 {
		t.Errorf("Tag = %08x, want %08x", discResp.Tag, 0x12345678)
	}
	if len(discResp.PubKey) != 8 {
		t.Errorf("PubKey length = %d, want 8", len(discResp.PubKey))
	}
}

func TestControlSubtypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{ControlSubtypeDiscoverReq, "DISCOVER_REQ"},
		{ControlSubtypeDiscoverResp, "DISCOVER_RESP"},
		{0x0A, "UNKNOWN(10)"},
	}

	for _, tt := range tests {
		if got := ControlSubtypeName(tt.typ); got != tt.want {
			t.Errorf("ControlSubtypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

func TestTxtTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{TxtTypePlain, "plain"},
		{TxtTypeCLI, "cli"},
		{TxtTypeSigned, "signed"},
		{0x0F, "unknown(15)"},
	}

	for _, tt := range tests {
		if got := TxtTypeName(tt.typ); got != tt.want {
			t.Errorf("TxtTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}
