package codec

import (
	"bytes"
	"testing"
)

// -----------------------------------------------------------------------------
// ADVERT Builder Tests
// -----------------------------------------------------------------------------

func TestBuildAdvertPayloadMinimal(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	var sig [64]byte
	for i := range sig {
		sig[i] = byte(i + 100)
	}

	data := BuildAdvertPayload(pubKey, 1704067200, sig, nil)

	if len(data) != AdvertMinSize {
		t.Fatalf("length = %d, want %d", len(data), AdvertMinSize)
	}

	// Round-trip
	parsed, err := ParseAdvertPayload(data)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if parsed.PubKey != pubKey {
		t.Errorf("PubKey mismatch")
	}
	if parsed.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", parsed.Timestamp, 1704067200)
	}
	if parsed.Signature != sig {
		t.Errorf("Signature mismatch")
	}
	if parsed.AppData != nil {
		t.Errorf("AppData should be nil")
	}
}

func TestBuildAdvertPayloadWithAppData(t *testing.T) {
	var pubKey [32]byte
	var sig [64]byte

	lat := 37.7749
	lon := -122.4194
	f1 := uint16(0x1234)

	appData := &AdvertAppData{
		NodeType: NodeTypeChat,
		Name:     "TestNode",
		Lat:      &lat,
		Lon:      &lon,
		Feature1: &f1,
	}

	data := BuildAdvertPayload(pubKey, 1704067200, sig, appData)

	parsed, err := ParseAdvertPayload(data)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if parsed.AppData == nil {
		t.Fatal("AppData should not be nil")
	}
	if parsed.AppData.NodeType != NodeTypeChat {
		t.Errorf("NodeType = %d, want %d", parsed.AppData.NodeType, NodeTypeChat)
	}
	if parsed.AppData.Name != "TestNode" {
		t.Errorf("Name = %q, want %q", parsed.AppData.Name, "TestNode")
	}
	if parsed.AppData.Lat == nil || parsed.AppData.Lon == nil {
		t.Fatal("Location should not be nil")
	}
	// Floating point: allow small error from int32 round-trip
	if *parsed.AppData.Lat < 37.7748 || *parsed.AppData.Lat > 37.7750 {
		t.Errorf("Lat = %f, want ~37.7749", *parsed.AppData.Lat)
	}
	if *parsed.AppData.Lon < -122.4195 || *parsed.AppData.Lon > -122.4193 {
		t.Errorf("Lon = %f, want ~-122.4194", *parsed.AppData.Lon)
	}
	if parsed.AppData.Feature1 == nil || *parsed.AppData.Feature1 != 0x1234 {
		t.Errorf("Feature1 = %v, want 0x1234", parsed.AppData.Feature1)
	}
	if parsed.AppData.Feature2 != nil {
		t.Errorf("Feature2 should be nil")
	}
}

func TestBuildAdvertAppDataAllFields(t *testing.T) {
	lat := 40.0
	lon := -74.0
	f1 := uint16(0xAAAA)
	f2 := uint16(0xBBBB)

	appData := &AdvertAppData{
		NodeType: NodeTypeRoom,
		Name:     "AllFields",
		Lat:      &lat,
		Lon:      &lon,
		Feature1: &f1,
		Feature2: &f2,
	}

	data := BuildAdvertAppData(appData)
	parsed, err := ParseAdvertAppData(data)
	if err != nil {
		t.Fatalf("ParseAdvertAppData() error = %v", err)
	}

	if parsed.NodeType != NodeTypeRoom {
		t.Errorf("NodeType = %d, want %d", parsed.NodeType, NodeTypeRoom)
	}
	if parsed.Name != "AllFields" {
		t.Errorf("Name = %q, want %q", parsed.Name, "AllFields")
	}
	if *parsed.Lat != 40.0 {
		t.Errorf("Lat = %f, want 40.0", *parsed.Lat)
	}
	if *parsed.Lon != -74.0 {
		t.Errorf("Lon = %f, want -74.0", *parsed.Lon)
	}
	if *parsed.Feature1 != 0xAAAA {
		t.Errorf("Feature1 = %04x, want AAAA", *parsed.Feature1)
	}
	if *parsed.Feature2 != 0xBBBB {
		t.Errorf("Feature2 = %04x, want BBBB", *parsed.Feature2)
	}
}

func TestBuildAdvertAppDataNil(t *testing.T) {
	data := BuildAdvertAppData(nil)
	if data != nil {
		t.Errorf("BuildAdvertAppData(nil) = %v, want nil", data)
	}
}

func TestBuildAdvertAppDataNameOnly(t *testing.T) {
	appData := &AdvertAppData{
		NodeType: NodeTypeRepeater,
		Name:     "Relay1",
	}

	data := BuildAdvertAppData(appData)
	parsed, err := ParseAdvertAppData(data)
	if err != nil {
		t.Fatalf("ParseAdvertAppData() error = %v", err)
	}

	if parsed.NodeType != NodeTypeRepeater {
		t.Errorf("NodeType = %d, want %d", parsed.NodeType, NodeTypeRepeater)
	}
	if parsed.Name != "Relay1" {
		t.Errorf("Name = %q, want %q", parsed.Name, "Relay1")
	}
	if parsed.Lat != nil || parsed.Lon != nil {
		t.Errorf("Location should be nil")
	}
}

// -----------------------------------------------------------------------------
// ACK Builder Tests
// -----------------------------------------------------------------------------

func TestBuildAckPayloadRoundTrip(t *testing.T) {
	checksum := uint32(0xDEADBEEF)
	data := BuildAckPayload(checksum)

	parsed, err := ParseAckPayload(data)
	if err != nil {
		t.Fatalf("ParseAckPayload() error = %v", err)
	}

	if parsed.Checksum != checksum {
		t.Errorf("Checksum = %08x, want %08x", parsed.Checksum, checksum)
	}
}

// -----------------------------------------------------------------------------
// Addressed Payload Builder Tests
// -----------------------------------------------------------------------------

func TestBuildAddressedPayloadRoundTrip(t *testing.T) {
	ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	data := BuildAddressedPayload(0xAA, 0xBB, 0x1234, ciphertext)

	parsed, err := ParseAddressedPayload(data)
	if err != nil {
		t.Fatalf("ParseAddressedPayload() error = %v", err)
	}

	if parsed.DestHash != 0xAA {
		t.Errorf("DestHash = %02x, want AA", parsed.DestHash)
	}
	if parsed.SrcHash != 0xBB {
		t.Errorf("SrcHash = %02x, want BB", parsed.SrcHash)
	}
	if parsed.MAC != 0x1234 {
		t.Errorf("MAC = %04x, want 1234", parsed.MAC)
	}
	if !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Errorf("Ciphertext = %v, want %v", parsed.Ciphertext, ciphertext)
	}
}

func TestBuildAddressedPayloadEmpty(t *testing.T) {
	data := BuildAddressedPayload(0x01, 0x02, 0x0000, nil)

	if len(data) != AddressedHeaderSize {
		t.Errorf("length = %d, want %d", len(data), AddressedHeaderSize)
	}

	parsed, err := ParseAddressedPayload(data)
	if err != nil {
		t.Fatalf("ParseAddressedPayload() error = %v", err)
	}
	if len(parsed.Ciphertext) != 0 {
		t.Errorf("Ciphertext length = %d, want 0", len(parsed.Ciphertext))
	}
}

// -----------------------------------------------------------------------------
// Group Payload Builder Tests
// -----------------------------------------------------------------------------

func TestBuildGroupPayloadRoundTrip(t *testing.T) {
	ciphertext := []byte{0x11, 0x22, 0x33, 0x44}
	data := BuildGroupPayload(0xCC, 0x5678, ciphertext)

	parsed, err := ParseGroupPayload(data)
	if err != nil {
		t.Fatalf("ParseGroupPayload() error = %v", err)
	}

	if parsed.ChannelHash != 0xCC {
		t.Errorf("ChannelHash = %02x, want CC", parsed.ChannelHash)
	}
	if parsed.MAC != 0x5678 {
		t.Errorf("MAC = %04x, want 5678", parsed.MAC)
	}
	if !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Errorf("Ciphertext = %v, want %v", parsed.Ciphertext, ciphertext)
	}
}

// -----------------------------------------------------------------------------
// Anonymous Request Builder Tests
// -----------------------------------------------------------------------------

func TestBuildAnonReqPayloadRoundTrip(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	ciphertext := []byte{0xEE, 0xFF, 0x00, 0x11}

	data := BuildAnonReqPayload(0xDD, pubKey, 0xABCD, ciphertext)

	parsed, err := ParseAnonReqPayload(data)
	if err != nil {
		t.Fatalf("ParseAnonReqPayload() error = %v", err)
	}

	if parsed.DestHash != 0xDD {
		t.Errorf("DestHash = %02x, want DD", parsed.DestHash)
	}
	if parsed.PubKey != pubKey {
		t.Errorf("PubKey mismatch")
	}
	if parsed.MAC != 0xABCD {
		t.Errorf("MAC = %04x, want ABCD", parsed.MAC)
	}
	if !bytes.Equal(parsed.Ciphertext, ciphertext) {
		t.Errorf("Ciphertext = %v, want %v", parsed.Ciphertext, ciphertext)
	}
}

func TestBuildAnonReqPayloadNoCiphertext(t *testing.T) {
	var pubKey [32]byte
	data := BuildAnonReqPayload(0x01, pubKey, 0x0000, nil)

	if len(data) != AnonReqHeaderSize {
		t.Errorf("length = %d, want %d", len(data), AnonReqHeaderSize)
	}

	parsed, err := ParseAnonReqPayload(data)
	if err != nil {
		t.Fatalf("ParseAnonReqPayload() error = %v", err)
	}
	if parsed.Ciphertext != nil {
		t.Errorf("Ciphertext should be nil, got %v", parsed.Ciphertext)
	}
}

// -----------------------------------------------------------------------------
// Control Payload Builder Tests
// -----------------------------------------------------------------------------

func TestBuildControlPayloadRoundTrip(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	data := BuildControlPayload(0x82, payload)

	parsed, err := ParseControlPayload(data)
	if err != nil {
		t.Fatalf("ParseControlPayload() error = %v", err)
	}

	if parsed.Flags != 0x82 {
		t.Errorf("Flags = %02x, want 82", parsed.Flags)
	}
	if parsed.Subtype != 0x08 {
		t.Errorf("Subtype = %02x, want 08", parsed.Subtype)
	}
	if !bytes.Equal(parsed.Data, payload) {
		t.Errorf("Data = %v, want %v", parsed.Data, payload)
	}
}

func TestBuildDiscoverReqPayloadRoundTrip(t *testing.T) {
	data := BuildDiscoverReqPayload(true, 0x0F, 0x78563412, 1704067200)

	// Parse as control first
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
		t.Errorf("TypeFilter = %02x, want 0F", discReq.TypeFilter)
	}
	if discReq.Tag != 0x78563412 {
		t.Errorf("Tag = %08x, want 78563412", discReq.Tag)
	}
	if discReq.Since != 1704067200 {
		t.Errorf("Since = %d, want %d", discReq.Since, 1704067200)
	}
}

func TestBuildDiscoverReqPayloadNoSince(t *testing.T) {
	data := BuildDiscoverReqPayload(false, 0x03, 0x12345678, 0)

	// Should be shorter (no since field)
	expectedLen := 1 + 1 + 4 // flags + type_filter + tag
	if len(data) != expectedLen {
		t.Errorf("length = %d, want %d", len(data), expectedLen)
	}

	ctrl, err := ParseControlPayload(data)
	if err != nil {
		t.Fatalf("ParseControlPayload() error = %v", err)
	}

	discReq, err := ParseDiscoverReqFromControl(ctrl)
	if err != nil {
		t.Fatalf("ParseDiscoverReqFromControl() error = %v", err)
	}

	if discReq.PrefixOnly {
		t.Error("PrefixOnly = true, want false")
	}
	if discReq.Tag != 0x12345678 {
		t.Errorf("Tag = %08x, want 12345678", discReq.Tag)
	}
	if discReq.Since != 0 {
		t.Errorf("Since = %d, want 0", discReq.Since)
	}
}

func TestBuildDiscoverRespPayloadRoundTrip(t *testing.T) {
	pubKey := []byte{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7}

	data := BuildDiscoverRespPayload(NodeTypeChat, 40, 0x12345678, pubKey)

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
		t.Errorf("Tag = %08x, want 12345678", discResp.Tag)
	}
	if !bytes.Equal(discResp.PubKey, pubKey) {
		t.Errorf("PubKey = %v, want %v", discResp.PubKey, pubKey)
	}
}

// -----------------------------------------------------------------------------
// Content Builder Tests
// -----------------------------------------------------------------------------

func TestBuildTxtMsgContentPlainRoundTrip(t *testing.T) {
	data := BuildTxtMsgContent(1704067200, TxtTypePlain, 0, "Hello!", nil)

	parsed, err := ParseTxtMsgContent(data)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if parsed.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", parsed.Timestamp, 1704067200)
	}
	if parsed.TxtType != TxtTypePlain {
		t.Errorf("TxtType = %d, want %d", parsed.TxtType, TxtTypePlain)
	}
	if parsed.Attempt != 0 {
		t.Errorf("Attempt = %d, want 0", parsed.Attempt)
	}
	if parsed.Message != "Hello!" {
		t.Errorf("Message = %q, want %q", parsed.Message, "Hello!")
	}
}

func TestBuildTxtMsgContentCLIWithAttempt(t *testing.T) {
	data := BuildTxtMsgContent(1704067200, TxtTypeCLI, 2, "/help", nil)

	parsed, err := ParseTxtMsgContent(data)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if parsed.TxtType != TxtTypeCLI {
		t.Errorf("TxtType = %d, want %d", parsed.TxtType, TxtTypeCLI)
	}
	if parsed.Attempt != 2 {
		t.Errorf("Attempt = %d, want 2", parsed.Attempt)
	}
	if parsed.Message != "/help" {
		t.Errorf("Message = %q, want %q", parsed.Message, "/help")
	}
}

func TestBuildTxtMsgContentSignedRoundTrip(t *testing.T) {
	prefix := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	data := BuildTxtMsgContent(1704067200, TxtTypeSigned, 0, "Signed msg", prefix)

	parsed, err := ParseTxtMsgContent(data)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if parsed.TxtType != TxtTypeSigned {
		t.Errorf("TxtType = %d, want %d", parsed.TxtType, TxtTypeSigned)
	}
	if !bytes.Equal(parsed.SenderPubKeyPrefix, prefix) {
		t.Errorf("SenderPubKeyPrefix = %v, want %v", parsed.SenderPubKeyPrefix, prefix)
	}
	if parsed.Message != "Signed msg" {
		t.Errorf("Message = %q, want %q", parsed.Message, "Signed msg")
	}
}

func TestBuildTxtMsgContentEmptyMessage(t *testing.T) {
	data := BuildTxtMsgContent(1704067200, TxtTypePlain, 0, "", nil)

	parsed, err := ParseTxtMsgContent(data)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if parsed.Message != "" {
		t.Errorf("Message = %q, want empty", parsed.Message)
	}
}

func TestBuildRequestContentRoundTrip(t *testing.T) {
	reqData := []byte{0x01, 0x02, 0x03}
	data := BuildRequestContent(1704067200, ReqTypeGetStats, reqData)

	parsed, err := ParseRequestContent(data)
	if err != nil {
		t.Fatalf("ParseRequestContent() error = %v", err)
	}

	if parsed.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", parsed.Timestamp, 1704067200)
	}
	if parsed.RequestType != ReqTypeGetStats {
		t.Errorf("RequestType = %d, want %d", parsed.RequestType, ReqTypeGetStats)
	}
	if !bytes.Equal(parsed.RequestData, reqData) {
		t.Errorf("RequestData = %v, want %v", parsed.RequestData, reqData)
	}
}

func TestBuildRequestContentNoData(t *testing.T) {
	data := BuildRequestContent(1704067200, ReqTypeGetNeighbors, nil)

	parsed, err := ParseRequestContent(data)
	if err != nil {
		t.Fatalf("ParseRequestContent() error = %v", err)
	}

	if parsed.RequestType != ReqTypeGetNeighbors {
		t.Errorf("RequestType = %d, want %d", parsed.RequestType, ReqTypeGetNeighbors)
	}
	if len(parsed.RequestData) != 0 {
		t.Errorf("RequestData length = %d, want 0", len(parsed.RequestData))
	}
}

func TestBuildResponseContentRoundTrip(t *testing.T) {
	content := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	data := BuildResponseContent(0x12345678, content)

	parsed, err := ParseResponseContent(data)
	if err != nil {
		t.Fatalf("ParseResponseContent() error = %v", err)
	}

	if parsed.Tag != 0x12345678 {
		t.Errorf("Tag = %08x, want 12345678", parsed.Tag)
	}
	if !bytes.Equal(parsed.Content, content) {
		t.Errorf("Content = %v, want %v", parsed.Content, content)
	}
}

func TestBuildResponseContentEmpty(t *testing.T) {
	data := BuildResponseContent(0xAABBCCDD, nil)

	parsed, err := ParseResponseContent(data)
	if err != nil {
		t.Fatalf("ParseResponseContent() error = %v", err)
	}

	if parsed.Tag != 0xAABBCCDD {
		t.Errorf("Tag = %08x, want AABBCCDD", parsed.Tag)
	}
	if len(parsed.Content) != 0 {
		t.Errorf("Content length = %d, want 0", len(parsed.Content))
	}
}

func TestBuildPathContentRoundTrip(t *testing.T) {
	path := []byte{0xAA, 0xBB, 0xCC}
	extra := []byte{0x01, 0x02, 0x03, 0x04}

	data := BuildPathContent(path, PayloadTypeAck, extra)

	parsed, err := ParsePathContent(data)
	if err != nil {
		t.Fatalf("ParsePathContent() error = %v", err)
	}

	if parsed.PathLen != 3 {
		t.Errorf("PathLen = %d, want 3", parsed.PathLen)
	}
	if !bytes.Equal(parsed.Path, path) {
		t.Errorf("Path = %v, want %v", parsed.Path, path)
	}
	if parsed.ExtraType != PayloadTypeAck {
		t.Errorf("ExtraType = %d, want %d", parsed.ExtraType, PayloadTypeAck)
	}
	if !bytes.Equal(parsed.Extra, extra) {
		t.Errorf("Extra = %v, want %v", parsed.Extra, extra)
	}
}

func TestBuildPathContentNoExtra(t *testing.T) {
	path := []byte{0xAA}

	data := BuildPathContent(path, PayloadTypeResponse, nil)

	parsed, err := ParsePathContent(data)
	if err != nil {
		t.Fatalf("ParsePathContent() error = %v", err)
	}

	if parsed.PathLen != 1 {
		t.Errorf("PathLen = %d, want 1", parsed.PathLen)
	}
	if !bytes.Equal(parsed.Path, path) {
		t.Errorf("Path = %v, want %v", parsed.Path, path)
	}
	if parsed.ExtraType != PayloadTypeResponse {
		t.Errorf("ExtraType = %d, want %d", parsed.ExtraType, PayloadTypeResponse)
	}
	if parsed.Extra != nil {
		t.Errorf("Extra should be nil, got %v", parsed.Extra)
	}
}

// -----------------------------------------------------------------------------
// Full-stack round-trip: build → write packet → read packet → parse
// -----------------------------------------------------------------------------

func TestFullStackGroupMessageRoundTrip(t *testing.T) {
	// Build a GRP_TXT payload
	ciphertext := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	groupPayload := BuildGroupPayload(0xCC, 0x5678, ciphertext)

	// Build a packet around it
	pkt := &Packet{
		Header:  (PayloadTypeGrpTxt << PHTypeShift) | RouteTypeFlood,
		PathLen: 2,
		Path:    []byte{0xAA, 0xBB},
		Payload: groupPayload,
	}

	// Encode to wire
	wire := pkt.WriteTo()

	// Decode from wire
	var decoded Packet
	if err := decoded.ReadFrom(wire); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	if decoded.PayloadType() != PayloadTypeGrpTxt {
		t.Errorf("PayloadType() = %d, want %d", decoded.PayloadType(), PayloadTypeGrpTxt)
	}

	// Parse the group payload
	grp, err := ParseGroupPayload(decoded.Payload)
	if err != nil {
		t.Fatalf("ParseGroupPayload() error = %v", err)
	}

	if grp.ChannelHash != 0xCC {
		t.Errorf("ChannelHash = %02x, want CC", grp.ChannelHash)
	}
	if grp.MAC != 0x5678 {
		t.Errorf("MAC = %04x, want 5678", grp.MAC)
	}
	if !bytes.Equal(grp.Ciphertext, ciphertext) {
		t.Errorf("Ciphertext = %v, want %v", grp.Ciphertext, ciphertext)
	}
}

func TestFullStackAddressedMessageRoundTrip(t *testing.T) {
	// Build content
	content := BuildTxtMsgContent(1704067200, TxtTypePlain, 1, "Test message", nil)

	// Build addressed payload
	addrPayload := BuildAddressedPayload(0xAA, 0xBB, 0x1234, content)

	// Build a packet
	pkt := &Packet{
		Header:  (PayloadTypeTxtMsg << PHTypeShift) | RouteTypeDirect,
		PathLen: 1,
		Path:    []byte{0xCC},
		Payload: addrPayload,
	}

	wire := pkt.WriteTo()

	var decoded Packet
	if err := decoded.ReadFrom(wire); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	addr, err := ParseAddressedPayload(decoded.Payload)
	if err != nil {
		t.Fatalf("ParseAddressedPayload() error = %v", err)
	}

	if addr.DestHash != 0xAA || addr.SrcHash != 0xBB || addr.MAC != 0x1234 {
		t.Errorf("Addressed header mismatch: dest=%02x src=%02x mac=%04x",
			addr.DestHash, addr.SrcHash, addr.MAC)
	}

	// Parse the inner content (would be decrypted ciphertext in real use)
	txt, err := ParseTxtMsgContent(addr.Ciphertext)
	if err != nil {
		t.Fatalf("ParseTxtMsgContent() error = %v", err)
	}

	if txt.Message != "Test message" {
		t.Errorf("Message = %q, want %q", txt.Message, "Test message")
	}
	if txt.Attempt != 1 {
		t.Errorf("Attempt = %d, want 1", txt.Attempt)
	}
}

func TestFullStackAdvertRoundTrip(t *testing.T) {
	var pubKey [32]byte
	for i := range pubKey {
		pubKey[i] = byte(i)
	}
	var sig [64]byte
	for i := range sig {
		sig[i] = byte(i + 50)
	}

	lat := 51.5074
	lon := -0.1278
	appData := &AdvertAppData{
		NodeType: NodeTypeSensor,
		Name:     "Weather-1",
		Lat:      &lat,
		Lon:      &lon,
	}

	advertPayload := BuildAdvertPayload(pubKey, 1704067200, sig, appData)

	pkt := &Packet{
		Header:  (PayloadTypeAdvert << PHTypeShift) | RouteTypeFlood,
		PathLen: 0,
		Path:    []byte{},
		Payload: advertPayload,
	}

	wire := pkt.WriteTo()

	var decoded Packet
	if err := decoded.ReadFrom(wire); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	advert, err := ParseAdvertPayload(decoded.Payload)
	if err != nil {
		t.Fatalf("ParseAdvertPayload() error = %v", err)
	}

	if advert.PubKey != pubKey {
		t.Errorf("PubKey mismatch")
	}
	if advert.Timestamp != 1704067200 {
		t.Errorf("Timestamp = %d, want %d", advert.Timestamp, 1704067200)
	}
	if advert.AppData == nil {
		t.Fatal("AppData should not be nil")
	}
	if advert.AppData.NodeType != NodeTypeSensor {
		t.Errorf("NodeType = %d, want %d", advert.AppData.NodeType, NodeTypeSensor)
	}
	if advert.AppData.Name != "Weather-1" {
		t.Errorf("Name = %q, want %q", advert.AppData.Name, "Weather-1")
	}
}

func TestFullStackControlDiscoverRoundTrip(t *testing.T) {
	// Build a DISCOVER_REQ control payload
	discReqPayload := BuildDiscoverReqPayload(true, 0x0F, 0xAABBCCDD, 0)

	pkt := &Packet{
		Header:  (PayloadTypeControl << PHTypeShift) | RouteTypeFlood,
		PathLen: 0,
		Path:    []byte{},
		Payload: discReqPayload,
	}

	wire := pkt.WriteTo()

	var decoded Packet
	if err := decoded.ReadFrom(wire); err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}

	ctrl, err := ParseControlPayload(decoded.Payload)
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
		t.Errorf("TypeFilter = %02x, want 0F", discReq.TypeFilter)
	}
	if discReq.Tag != 0xAABBCCDD {
		t.Errorf("Tag = %08x, want AABBCCDD", discReq.Tag)
	}
}
