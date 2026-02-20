package contact

import (
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// makeSignedAdvert creates a valid signed ADVERT payload for testing.
func makeSignedAdvert(t *testing.T, kp *crypto.KeyPair, name string, nodeType uint8, timestamp uint32) *codec.AdvertPayload {
	t.Helper()

	appData := &codec.AdvertAppData{
		NodeType: nodeType,
		Name:     name,
	}
	appDataBytes := codec.BuildAdvertAppData(appData)

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)

	sig, err := crypto.SignAdvert(kp.PrivateKey, pubKey, timestamp, appDataBytes)
	if err != nil {
		t.Fatalf("SignAdvert failed: %v", err)
	}

	return &codec.AdvertPayload{
		PubKey:    pubKey,
		Timestamp: timestamp,
		Signature: sig,
		AppData:   appData,
	}
}

func makeSignedAdvertWithLocation(t *testing.T, kp *crypto.KeyPair, name string, nodeType uint8, timestamp uint32, lat, lon float64) *codec.AdvertPayload {
	t.Helper()

	appData := &codec.AdvertAppData{
		NodeType: nodeType,
		Name:     name,
		Lat:      &lat,
		Lon:      &lon,
	}
	appDataBytes := codec.BuildAdvertAppData(appData)

	var pubKey [32]byte
	copy(pubKey[:], kp.PublicKey)

	sig, err := crypto.SignAdvert(kp.PrivateKey, pubKey, timestamp, appDataBytes)
	if err != nil {
		t.Fatalf("SignAdvert failed: %v", err)
	}

	return &codec.AdvertPayload{
		PubKey:    pubKey,
		Timestamp: timestamp,
		Signature: sig,
		AppData:   appData,
	}
}

func TestProcessAdvert_NewContact(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "PeerNode", codec.NodeTypeChat, 1000)

	result := m.ProcessAdvert(advert, 5000, true)

	if result.Rejected {
		t.Fatalf("advert rejected: %s", result.RejectReason)
	}
	if !result.IsNew {
		t.Error("expected IsNew = true")
	}
	if result.Contact == nil {
		t.Fatal("expected non-nil contact")
	}
	if result.Contact.Name != "PeerNode" {
		t.Errorf("name = %q, want %q", result.Contact.Name, "PeerNode")
	}
	if result.Contact.Type != codec.NodeTypeChat {
		t.Errorf("type = %d, want %d", result.Contact.Type, codec.NodeTypeChat)
	}
	if result.Contact.LastAdvertTimestamp != 1000 {
		t.Errorf("LastAdvertTimestamp = %d, want 1000", result.Contact.LastAdvertTimestamp)
	}
	if result.Contact.LastMod != 5000 {
		t.Errorf("LastMod = %d, want 5000", result.Contact.LastMod)
	}
	if result.Contact.OutPathLen != PathUnknown {
		t.Errorf("OutPathLen = %d, want %d (PathUnknown)", result.Contact.OutPathLen, PathUnknown)
	}

	// Should be stored in the manager
	if m.Count() != 1 {
		t.Errorf("Count() = %d, want 1", m.Count())
	}
}

func TestProcessAdvert_UpdateExisting(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	// First advert
	advert1 := makeSignedAdvert(t, peerKP, "OldName", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert1, 5000, true)

	// Second advert with newer timestamp
	advert2 := makeSignedAdvertWithLocation(t, peerKP, "NewName", codec.NodeTypeRepeater, 2000, 37.7749, -122.4194)
	result := m.ProcessAdvert(advert2, 6000, true)

	if result.Rejected {
		t.Fatalf("update rejected: %s", result.RejectReason)
	}
	if result.IsNew {
		t.Error("expected IsNew = false for update")
	}
	if result.Contact.Name != "NewName" {
		t.Errorf("name = %q, want %q", result.Contact.Name, "NewName")
	}
	if result.Contact.Type != codec.NodeTypeRepeater {
		t.Errorf("type = %d, want %d", result.Contact.Type, codec.NodeTypeRepeater)
	}
	if result.Contact.LastAdvertTimestamp != 2000 {
		t.Errorf("LastAdvertTimestamp = %d, want 2000", result.Contact.LastAdvertTimestamp)
	}
	if result.Contact.LastMod != 6000 {
		t.Errorf("LastMod = %d, want 6000", result.Contact.LastMod)
	}
	if result.Contact.GPSLat == 0 {
		t.Error("expected GPS latitude to be set")
	}

	// Should still be one contact
	if m.Count() != 1 {
		t.Errorf("Count() = %d, want 1", m.Count())
	}
}

func TestProcessAdvert_ReplayRejected(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	// Initial advert at timestamp 2000
	advert1 := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 2000)
	m.ProcessAdvert(advert1, 5000, true)

	// Replay with same timestamp
	advert2 := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 2000)
	result := m.ProcessAdvert(advert2, 5001, true)

	if !result.Rejected {
		t.Error("same timestamp should be rejected as replay")
	}
	if result.RejectReason != "possible replay" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "possible replay")
	}

	// Replay with older timestamp
	advert3 := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1999)
	result = m.ProcessAdvert(advert3, 5002, true)

	if !result.Rejected {
		t.Error("older timestamp should be rejected as replay")
	}
}

func TestProcessAdvert_InvalidSignature(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	// Corrupt the signature
	advert.Signature[0] ^= 0xFF

	result := m.ProcessAdvert(advert, 5000, true)

	if !result.Rejected {
		t.Error("invalid signature should be rejected")
	}
	if result.RejectReason != "invalid signature" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "invalid signature")
	}
}

func TestProcessAdvert_NoName(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	// Create advert with empty name
	advert := makeSignedAdvert(t, peerKP, "", codec.NodeTypeChat, 1000)
	// The signature is for empty name appdata, but we set name to empty
	advert.AppData.Name = ""

	result := m.ProcessAdvert(advert, 5000, true)

	if !result.Rejected {
		t.Error("advert without name should be rejected")
	}
	if result.RejectReason != "advert missing name" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "advert missing name")
	}
}

func TestProcessAdvert_NoAppData(t *testing.T) {
	m := newTestManager(t, 10, false)

	advert := &codec.AdvertPayload{
		Timestamp: 1000,
		AppData:   nil,
	}

	result := m.ProcessAdvert(advert, 5000, true)

	if !result.Rejected {
		t.Error("advert without appdata should be rejected")
	}
	if result.RejectReason != "advert missing name" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "advert missing name")
	}
}

func TestProcessAdvert_AutoAddDisabled(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)

	result := m.ProcessAdvert(advert, 5000, false) // autoAdd = false

	if !result.Rejected {
		t.Error("expected rejected with autoAdd disabled")
	}
	if result.RejectReason != "auto-add disabled" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "auto-add disabled")
	}
	// Should still provide a temporary contact for inspection
	if result.Contact == nil {
		t.Error("expected temporary contact even when rejected")
	}
	if result.Contact.Name != "Node" {
		t.Errorf("temp contact name = %q, want %q", result.Contact.Name, "Node")
	}

	// Should NOT be stored
	if m.Count() != 0 {
		t.Errorf("Count() = %d, want 0", m.Count())
	}
}

func TestProcessAdvert_ContactsFull(t *testing.T) {
	m := newTestManager(t, 1, false) // only 1 slot, no overwrite
	existingKP := generateTestKeyPair(t)
	newKP := generateTestKeyPair(t)

	// Fill the single slot
	advert1 := makeSignedAdvert(t, existingKP, "Existing", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert1, 5000, true)

	// Try to add another
	advert2 := makeSignedAdvert(t, newKP, "New", codec.NodeTypeChat, 1000)
	result := m.ProcessAdvert(advert2, 5001, true)

	if !result.Rejected {
		t.Error("expected rejected when contacts full")
	}
	if result.RejectReason != "contacts full" {
		t.Errorf("reason = %q, want %q", result.RejectReason, "contacts full")
	}
}

func TestProcessAdvert_OverwriteWhenFull(t *testing.T) {
	localKP := generateTestKeyPair(t)
	m := NewManager(localKP.PrivateKey, ManagerConfig{
		MaxContacts:       1,
		OverwriteWhenFull: true,
	})

	existingKP := generateTestKeyPair(t)
	newKP := generateTestKeyPair(t)

	// Fill the single slot
	advert1 := makeSignedAdvert(t, existingKP, "Old", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert1, 5000, true)

	// Should evict the old one
	advert2 := makeSignedAdvert(t, newKP, "New", codec.NodeTypeChat, 1000)
	result := m.ProcessAdvert(advert2, 5001, true)

	if result.Rejected {
		t.Fatalf("should not be rejected with overwrite: %s", result.RejectReason)
	}
	if !result.IsNew {
		t.Error("expected IsNew = true")
	}
	if result.Contact.Name != "New" {
		t.Errorf("name = %q, want %q", result.Contact.Name, "New")
	}
	if m.Count() != 1 {
		t.Errorf("Count() = %d, want 1", m.Count())
	}
}

func TestProcessAdvert_WithLocation(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	lat := 37.7749
	lon := -122.4194
	advert := makeSignedAdvertWithLocation(t, peerKP, "Node", codec.NodeTypeChat, 1000, lat, lon)

	result := m.ProcessAdvert(advert, 5000, true)

	if result.Rejected {
		t.Fatalf("rejected: %s", result.RejectReason)
	}

	// Verify GPS stored as integer × 1,000,000
	expectedLat := int32(37774900)
	expectedLon := int32(-122419400)
	if result.Contact.GPSLat != expectedLat {
		t.Errorf("GPSLat = %d, want %d", result.Contact.GPSLat, expectedLat)
	}
	if result.Contact.GPSLon != expectedLon {
		t.Errorf("GPSLon = %d, want %d", result.Contact.GPSLon, expectedLon)
	}
}

func TestProcessAdvert_CallbackFires(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	var callbackContact *ContactInfo
	var callbackIsNew bool
	m.SetOnContactAdded(func(contact *ContactInfo, isNew bool) {
		callbackContact = contact
		callbackIsNew = isNew
	})

	// New contact
	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert, 5000, true)

	if callbackContact == nil {
		t.Fatal("callback should fire for new contact")
	}
	if !callbackIsNew {
		t.Error("expected isNew = true")
	}

	// Update existing contact
	callbackContact = nil
	advert2 := makeSignedAdvert(t, peerKP, "Updated", codec.NodeTypeChat, 2000)
	m.ProcessAdvert(advert2, 6000, true)

	if callbackContact == nil {
		t.Fatal("callback should fire for update")
	}
	if callbackIsNew {
		t.Error("expected isNew = false for update")
	}
}

// --- ProcessPath tests ---

func TestProcessPath_UpdatesRoute(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	// First add the contact via ADVERT
	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert, 5000, true)

	var senderID core.MeshCoreID
	copy(senderID[:], peerKP.PublicKey)

	pathContent := &codec.PathContent{
		PathLen:   3,
		Path:      []byte{0xAA, 0xBB, 0xCC},
		ExtraType: 0,
		Extra:     nil,
	}

	contact, _, _, err := m.ProcessPath(senderID, pathContent, 6000)
	if err != nil {
		t.Fatalf("ProcessPath failed: %v", err)
	}

	if contact.OutPathLen != 3 {
		t.Errorf("OutPathLen = %d, want 3", contact.OutPathLen)
	}
	if len(contact.OutPath) != 3 {
		t.Fatalf("OutPath len = %d, want 3", len(contact.OutPath))
	}
	if contact.OutPath[0] != 0xAA || contact.OutPath[1] != 0xBB || contact.OutPath[2] != 0xCC {
		t.Error("OutPath bytes don't match")
	}
	if contact.LastMod != 6000 {
		t.Errorf("LastMod = %d, want 6000", contact.LastMod)
	}
	if !contact.HasDirectPath() {
		t.Error("should have direct path after ProcessPath")
	}
}

func TestProcessPath_ZeroLengthPath(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert, 5000, true)

	var senderID core.MeshCoreID
	copy(senderID[:], peerKP.PublicKey)

	pathContent := &codec.PathContent{
		PathLen:   0,
		Path:      nil,
		ExtraType: 0,
	}

	contact, _, _, err := m.ProcessPath(senderID, pathContent, 6000)
	if err != nil {
		t.Fatalf("ProcessPath failed: %v", err)
	}

	if contact.OutPathLen != 0 {
		t.Errorf("OutPathLen = %d, want 0", contact.OutPathLen)
	}
	if contact.HasDirectPath() != true {
		t.Error("OutPathLen 0 (zero-hop) should be HasDirectPath == true")
	}
}

func TestProcessPath_ExtraACK(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert, 5000, true)

	var senderID core.MeshCoreID
	copy(senderID[:], peerKP.PublicKey)

	ackData := []byte{0x01, 0x02, 0x03, 0x04}
	pathContent := &codec.PathContent{
		PathLen:   1,
		Path:      []byte{0xAA},
		ExtraType: codec.PayloadTypeAck,
		Extra:     ackData,
	}

	_, extraType, extraData, err := m.ProcessPath(senderID, pathContent, 6000)
	if err != nil {
		t.Fatalf("ProcessPath failed: %v", err)
	}

	if extraType != codec.PayloadTypeAck {
		t.Errorf("extraType = %d, want %d (ACK)", extraType, codec.PayloadTypeAck)
	}
	if len(extraData) != 4 {
		t.Fatalf("extraData len = %d, want 4", len(extraData))
	}
	if extraData[0] != 0x01 || extraData[3] != 0x04 {
		t.Error("extraData bytes don't match")
	}
}

func TestProcessPath_ExtraResponse(t *testing.T) {
	m := newTestManager(t, 10, false)
	peerKP := generateTestKeyPair(t)

	advert := makeSignedAdvert(t, peerKP, "Node", codec.NodeTypeChat, 1000)
	m.ProcessAdvert(advert, 5000, true)

	var senderID core.MeshCoreID
	copy(senderID[:], peerKP.PublicKey)

	respData := []byte{0xDE, 0xAD}
	pathContent := &codec.PathContent{
		PathLen:   2,
		Path:      []byte{0xAA, 0xBB},
		ExtraType: codec.PayloadTypeResponse,
		Extra:     respData,
	}

	_, extraType, extraData, err := m.ProcessPath(senderID, pathContent, 6000)
	if err != nil {
		t.Fatalf("ProcessPath failed: %v", err)
	}

	if extraType != codec.PayloadTypeResponse {
		t.Errorf("extraType = %d, want %d (RESPONSE)", extraType, codec.PayloadTypeResponse)
	}
	if string(extraData) != string(respData) {
		t.Error("extraData doesn't match")
	}
}

func TestProcessPath_UnknownSender(t *testing.T) {
	m := newTestManager(t, 10, false)

	unknownID := makeIDWithHash(0xFF)
	pathContent := &codec.PathContent{
		PathLen: 1,
		Path:    []byte{0xAA},
	}

	_, _, _, err := m.ProcessPath(unknownID, pathContent, 6000)
	if err != ErrContactNotFound {
		t.Errorf("expected ErrContactNotFound, got %v", err)
	}
}
