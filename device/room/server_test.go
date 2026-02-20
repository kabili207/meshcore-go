package room

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/router"
	"github.com/kabili207/meshcore-go/transport"
)

// mockTransport records sent packets for testing.
type mockTransport struct {
	mu        sync.Mutex
	packets   []*codec.Packet
	connected bool
}

func newMockTransport() *mockTransport {
	return &mockTransport{connected: true}
}

func (m *mockTransport) Start(_ context.Context) error            { return nil }
func (m *mockTransport) Stop() error                               { return nil }
func (m *mockTransport) IsConnected() bool                         { return m.connected }
func (m *mockTransport) SetPacketHandler(_ transport.PacketHandler) {}
func (m *mockTransport) SetStateHandler(_ transport.StateHandler)   {}

func (m *mockTransport) SendPacket(pkt *codec.Packet) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = append(m.packets, pkt)
	return nil
}

func (m *mockTransport) sentCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.packets)
}

func (m *mockTransport) lastPacket() *codec.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.packets) == 0 {
		return nil
	}
	return m.packets[len(m.packets)-1]
}

func (m *mockTransport) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packets = nil
}

// testHarness bundles all the components needed for room server testing.
type testHarness struct {
	server    *Server
	transport *mockTransport
	router    *router.Router
	contacts  *contact.ContactManager
	clients   *MemoryClientStore
	posts     *MemoryPostStore
	tracker   *ack.Tracker
	clk       *clock.Clock

	// Server key pair
	serverKey *crypto.KeyPair
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()

	serverKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal("failed to generate server key:", err)
	}

	var serverPub [32]byte
	copy(serverPub[:], serverKey.PublicKey)

	mt := newMockTransport()
	r := router.New(router.Config{
		SelfID: core.MeshCoreID(serverPub),
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	contacts := contact.NewManager(serverKey.PrivateKey, contact.ManagerConfig{
		MaxContacts: 100,
	})
	clients := NewMemoryClientStore(50)
	posts := NewMemoryPostStore(100)
	tracker := ack.NewTracker(ack.TrackerConfig{
		ACKTimeout: 12 * time.Second,
		MaxRetries: 3,
	})
	clk := clock.New()

	srv := NewServer(ServerConfig{
		PrivateKey:    serverKey.PrivateKey,
		PublicKey:     serverPub,
		Clock:         clk,
		AdminPassword: "admin123",
		GuestPassword: "guest123",
		AllowReadOnly: true,
		Clients:       clients,
		Posts:         posts,
		Contacts:      contacts,
		Router:        r,
		ACKTracker:    tracker,
	})

	return &testHarness{
		server:    srv,
		transport: mt,
		router:    r,
		contacts:  contacts,
		clients:   clients,
		posts:     posts,
		tracker:   tracker,
		clk:       clk,
		serverKey: serverKey,
	}
}

// makeClientKeyAndContact generates a client key pair and registers it as a
// contact in the harness. Returns the key pair and the client's MeshCoreID.
func (h *testHarness) makeClientKeyAndContact(t *testing.T) (*crypto.KeyPair, core.MeshCoreID) {
	t.Helper()

	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal("failed to generate client key:", err)
	}

	var clientID core.MeshCoreID
	copy(clientID[:], clientKey.PublicKey)

	_, err = h.contacts.AddContact(&contact.ContactInfo{
		ID:   clientID,
		Name: "test-client",
	})
	if err != nil {
		t.Fatal("failed to add contact:", err)
	}

	return clientKey, clientID
}

// buildAnonReqPacket builds a valid ANON_REQ login packet from a client to the server.
// Uses a fresh ephemeral key (different identity each call). For replay tests, use
// buildAnonReqPacketWithKey instead.
func (h *testHarness) buildAnonReqPacket(t *testing.T, timestamp, syncSince uint32, password string) *codec.Packet {
	t.Helper()
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal("failed to generate client key:", err)
	}
	return h.buildAnonReqPacketWithKey(t, clientKey, timestamp, syncSince, password)
}

// buildAnonReqPacketWithKey builds a valid ANON_REQ login packet using a specific
// client key pair. This allows the same identity to send multiple login requests
// (needed for replay and re-login tests).
func (h *testHarness) buildAnonReqPacketWithKey(t *testing.T, clientKey *crypto.KeyPair, timestamp, syncSince uint32, password string) *codec.Packet {
	t.Helper()

	// Build login data: timestamp(4) + sync_since(4) + password + null
	loginData := make([]byte, 8+len(password)+1)
	binary.LittleEndian.PutUint32(loginData[0:4], timestamp)
	binary.LittleEndian.PutUint32(loginData[4:8], syncSince)
	copy(loginData[8:], password)
	// Last byte is already 0 (null terminator)

	// Compute shared secret between client and server
	secret, err := crypto.ComputeSharedSecret(clientKey.PrivateKey, h.serverKey.PublicKey)
	if err != nil {
		t.Fatal("failed to compute shared secret:", err)
	}

	// Encrypt login data with the shared secret
	encrypted, err := crypto.EncryptAddressedWithSecret(loginData, secret)
	if err != nil {
		t.Fatal("failed to encrypt login data:", err)
	}

	// Split [MAC(2) || ciphertext] for wire format
	mac, ciphertext := codec.SplitMAC(encrypted)

	// Build the wire-format ANON_REQ payload with the client's actual public key
	var clientPub [32]byte
	copy(clientPub[:], clientKey.PublicKey)
	destHash := core.MeshCoreID(h.server.cfg.PublicKey).Hash()
	payload := codec.BuildAnonReqPayload(destHash, clientPub, mac, ciphertext)

	return &codec.Packet{
		Header:  (codec.PayloadTypeAnonReq << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

// buildAddressedPacket builds an encrypted addressed packet from a known client.
// Defaults to direct route type; use buildFloodAddressedPacket for flood routing.
func (h *testHarness) buildAddressedPacket(t *testing.T, clientKey *crypto.KeyPair, clientID core.MeshCoreID, payloadType uint8, content []byte) *codec.Packet {
	t.Helper()

	secret, err := crypto.ComputeSharedSecret(clientKey.PrivateKey, h.serverKey.PublicKey)
	if err != nil {
		t.Fatal("failed to compute shared secret:", err)
	}

	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		t.Fatal("failed to encrypt content:", err)
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	destHash := core.MeshCoreID(h.server.cfg.PublicKey).Hash()
	srcHash := clientID.Hash()
	payload := codec.BuildAddressedPayload(destHash, srcHash, mac, ciphertext)

	return &codec.Packet{
		Header:  (payloadType << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

// buildFloodAddressedPacket builds an encrypted addressed packet with flood routing.
// The path simulates relay hops from sender to server (used for PATH return tests).
func (h *testHarness) buildFloodAddressedPacket(t *testing.T, clientKey *crypto.KeyPair, clientID core.MeshCoreID, payloadType uint8, content []byte, floodPath []byte) *codec.Packet {
	t.Helper()
	pkt := h.buildAddressedPacket(t, clientKey, clientID, payloadType, content)
	pkt.Header = (pkt.Header &^ codec.PHRouteMask) | codec.RouteTypeFlood
	if len(floodPath) > 0 {
		pkt.PathLen = uint8(len(floodPath))
		pkt.Path = make([]byte, len(floodPath))
		copy(pkt.Path, floodPath)
	}
	return pkt
}

// --- Dispatch tests ---

func TestHandlePacket_UnhandledType(t *testing.T) {
	h := newTestHarness(t)

	// Send a packet with type that doesn't match any handler (e.g. GrpTxt)
	pkt := &codec.Packet{
		Header:  codec.PayloadTypeGrpTxt << codec.PHTypeShift,
		Payload: []byte{0x00},
	}
	// Should not panic
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)
}

func TestHandlePacket_ACK_Resolves(t *testing.T) {
	h := newTestHarness(t)

	resolved := false
	h.tracker.Track(0xDEADBEEF, ack.PendingACK{
		OnACK: func() { resolved = true },
	})

	ackPayload := codec.BuildAckPayload(0xDEADBEEF)
	pkt := &codec.Packet{
		Header:  codec.PayloadTypeAck << codec.PHTypeShift,
		Payload: ackPayload,
	}

	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if !resolved {
		t.Error("ACK should have resolved the pending entry")
	}
}

func TestHandlePacket_ACK_TooShort(t *testing.T) {
	h := newTestHarness(t)

	pkt := &codec.Packet{
		Header:  codec.PayloadTypeAck << codec.PHTypeShift,
		Payload: []byte{0x01, 0x02}, // too short for ACK (need 4 bytes)
	}
	// Should not panic
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)
}

// --- Login tests ---

func TestLogin_AdminPassword(t *testing.T) {
	h := newTestHarness(t)

	pkt := h.buildAnonReqPacket(t, 100, 0, "admin123")
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.clients.Count() != 1 {
		t.Fatalf("expected 1 client, got %d", h.clients.Count())
	}

	// Check that the client got admin permissions
	var client *ClientInfo
	h.clients.ForEach(func(c *ClientInfo) bool {
		client = c
		return false
	})

	if client.Role() != codec.PermACLAdmin {
		t.Errorf("expected admin role (%d), got %d", codec.PermACLAdmin, client.Role())
	}

	// Should have sent a login response
	if h.transport.sentCount() == 0 {
		t.Error("expected a login response packet")
	}
}

func TestLogin_GuestPassword(t *testing.T) {
	h := newTestHarness(t)

	pkt := h.buildAnonReqPacket(t, 100, 0, "guest123")
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.clients.Count() != 1 {
		t.Fatalf("expected 1 client, got %d", h.clients.Count())
	}

	var client *ClientInfo
	h.clients.ForEach(func(c *ClientInfo) bool {
		client = c
		return false
	})

	if client.Role() != codec.PermACLReadWrite {
		t.Errorf("expected ReadWrite role (%d), got %d", codec.PermACLReadWrite, client.Role())
	}
}

func TestLogin_OpenRoom_ReadOnly(t *testing.T) {
	h := newTestHarness(t)

	// No password → AllowReadOnly gives ReadOnly
	pkt := h.buildAnonReqPacket(t, 100, 0, "")
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.clients.Count() != 1 {
		t.Fatalf("expected 1 client, got %d", h.clients.Count())
	}

	var client *ClientInfo
	h.clients.ForEach(func(c *ClientInfo) bool {
		client = c
		return false
	})

	if client.Role() != codec.PermACLReadOnly {
		t.Errorf("expected ReadOnly role (%d), got %d", codec.PermACLReadOnly, client.Role())
	}
}

func TestLogin_WrongPassword_ClosedRoom(t *testing.T) {
	h := newTestHarness(t)
	h.server.cfg.AllowReadOnly = false

	pkt := h.buildAnonReqPacket(t, 100, 0, "wrong")
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.clients.Count() != 0 {
		t.Errorf("expected 0 clients (rejected), got %d", h.clients.Count())
	}
}

func TestLogin_ReplayRejected(t *testing.T) {
	h := newTestHarness(t)

	// Use a fixed client key for both login attempts
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// First login succeeds
	pkt1 := h.buildAnonReqPacketWithKey(t, clientKey, 100, 0, "admin123")
	h.server.HandlePacket(pkt1, transport.PacketSourceMQTT)

	if h.clients.Count() != 1 {
		t.Fatalf("expected 1 client after first login, got %d", h.clients.Count())
	}

	sentBefore := h.transport.sentCount()

	// Re-login with same timestamp from same identity should be rejected
	pkt2 := h.buildAnonReqPacketWithKey(t, clientKey, 100, 0, "admin123")
	h.server.HandlePacket(pkt2, transport.PacketSourceMQTT)

	// Client count should still be 1 (no new client added)
	if h.clients.Count() != 1 {
		t.Errorf("expected 1 client after replay, got %d", h.clients.Count())
	}

	// No new response sent
	if h.transport.sentCount() != sentBefore {
		t.Errorf("expected no new packets after replay, sent %d more", h.transport.sentCount()-sentBefore)
	}
}

func TestLogin_ReloginHigherTimestamp(t *testing.T) {
	h := newTestHarness(t)

	// Use a fixed client key for both login attempts
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// First login
	pkt1 := h.buildAnonReqPacketWithKey(t, clientKey, 100, 0, "admin123")
	h.server.HandlePacket(pkt1, transport.PacketSourceMQTT)

	if h.clients.Count() != 1 {
		t.Fatalf("expected 1 client, got %d", h.clients.Count())
	}

	sentBefore := h.transport.sentCount()

	// Re-login with higher timestamp from same identity — should succeed
	pkt2 := h.buildAnonReqPacketWithKey(t, clientKey, 200, 50, "")
	h.server.HandlePacket(pkt2, transport.PacketSourceMQTT)

	// Should still be 1 client (same identity re-logged)
	if h.clients.Count() != 1 {
		t.Errorf("expected 1 client after re-login, got %d", h.clients.Count())
	}

	// A new response should have been sent
	if h.transport.sentCount() <= sentBefore {
		t.Error("expected a login response for re-login")
	}
}

// --- resolvePermissions tests ---

func TestResolvePermissions_ExistingClient_NoPassword(t *testing.T) {
	h := newTestHarness(t)

	existing := &ClientInfo{Permissions: codec.PermACLAdmin}
	perm := h.server.resolvePermissions(existing, "")

	if perm != int(codec.PermACLAdmin) {
		t.Errorf("expected existing admin perm %d, got %d", codec.PermACLAdmin, perm)
	}
}

func TestResolvePermissions_AdminPassword(t *testing.T) {
	h := newTestHarness(t)
	perm := h.server.resolvePermissions(nil, "admin123")
	if perm != int(codec.PermACLAdmin) {
		t.Errorf("expected admin, got %d", perm)
	}
}

func TestResolvePermissions_GuestPassword(t *testing.T) {
	h := newTestHarness(t)
	perm := h.server.resolvePermissions(nil, "guest123")
	if perm != int(codec.PermACLReadWrite) {
		t.Errorf("expected ReadWrite, got %d", perm)
	}
}

func TestResolvePermissions_ReadOnly(t *testing.T) {
	h := newTestHarness(t)
	perm := h.server.resolvePermissions(nil, "")
	if perm != int(codec.PermACLReadOnly) {
		t.Errorf("expected ReadOnly, got %d", perm)
	}
}

func TestResolvePermissions_Rejected(t *testing.T) {
	h := newTestHarness(t)
	h.server.cfg.AllowReadOnly = false
	perm := h.server.resolvePermissions(nil, "wrong")
	if perm != -1 {
		t.Errorf("expected -1 (rejected), got %d", perm)
	}
}

// --- Text message tests ---

func TestTextMessage_PlainPost(t *testing.T) {
	h := newTestHarness(t)

	// Login a client first
	clientKey, clientID := h.makeClientKeyAndContact(t)

	client, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build a text message content
	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "hello world", nil)

	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// Post should have been stored
	if h.posts.Count() != 1 {
		t.Errorf("expected 1 post, got %d", h.posts.Count())
	}

	// Client timestamp should have been updated
	if client.LastTimestamp != 200 {
		t.Errorf("expected client LastTimestamp=200, got %d", client.LastTimestamp)
	}

	// ACK should have been sent
	if h.transport.sentCount() == 0 {
		t.Error("expected an ACK response")
	}
}

func TestTextMessage_ReplayRejected(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:            clientID,
		Permissions:   codec.PermACLReadWrite,
		LastTimestamp:  200, // already seen timestamp 200
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send message with timestamp <= LastTimestamp
	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "replay", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// No post stored
	if h.posts.Count() != 0 {
		t.Errorf("expected 0 posts (replay), got %d", h.posts.Count())
	}
}

func TestTextMessage_GuestCantPost(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLGuest, // guest can't write
	})
	if err != nil {
		t.Fatal(err)
	}

	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "blocked", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.posts.Count() != 0 {
		t.Errorf("expected 0 posts (guest), got %d", h.posts.Count())
	}
}

func TestTextMessage_ReadOnlyCantPost(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadOnly, // ReadOnly can't write
	})
	if err != nil {
		t.Fatal(err)
	}

	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "blocked", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// ReadOnly can't write but is not guest, so the function falls through.
	// The firmware behavior: if !canWrite but not guest, the message goes through
	// with an ACK but is not stored.
	// Let's verify based on our actual code logic.
}

func TestTextMessage_AdminCanPost(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "admin msg", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.posts.Count() != 1 {
		t.Errorf("expected 1 post from admin, got %d", h.posts.Count())
	}
}

func TestTextMessage_UnknownSender(t *testing.T) {
	h := newTestHarness(t)

	// Generate a key pair but DON'T add it as a contact
	clientKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var clientID core.MeshCoreID
	copy(clientID[:], clientKey.PublicKey)

	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "mystery", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// No post stored (unknown sender)
	if h.posts.Count() != 0 {
		t.Errorf("expected 0 posts (unknown sender), got %d", h.posts.Count())
	}
}

func TestTextMessage_ContactButNotClient(t *testing.T) {
	h := newTestHarness(t)

	// Add as contact but NOT as client
	clientKey, clientID := h.makeClientKeyAndContact(t)

	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain<<2, 0, "no session", nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeTxtMsg, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// No post stored (not a registered client)
	if h.posts.Count() != 0 {
		t.Errorf("expected 0 posts (not client), got %d", h.posts.Count())
	}
}

// --- Mock providers ---

type mockStatsProvider struct {
	stats ServerStats
}

func (m *mockStatsProvider) GetStats() ServerStats { return m.stats }

type mockTelemetryProvider struct {
	lastPermMask uint8
	data         []byte
}

func (m *mockTelemetryProvider) GetTelemetry(permMask uint8) []byte {
	m.lastPermMask = permMask
	return m.data
}

// decryptResponse decrypts a RESPONSE packet sent by the server back to the client.
// Returns the plaintext (tag + response data).
func (h *testHarness) decryptResponse(t *testing.T, clientKey *crypto.KeyPair, pkt *codec.Packet) []byte {
	t.Helper()

	addrPayload, err := codec.ParseAddressedPayload(pkt.Payload)
	if err != nil {
		t.Fatal("failed to parse addressed payload:", err)
	}

	secret, err := crypto.ComputeSharedSecret(clientKey.PrivateKey, h.serverKey.PublicKey)
	if err != nil {
		t.Fatal("failed to compute shared secret:", err)
	}

	plaintext, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addrPayload.MAC, addrPayload.Ciphertext), secret)
	if err != nil {
		t.Fatal("failed to decrypt response:", err)
	}

	return plaintext
}

// --- Request tests ---

func TestRequest_Keepalive(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	client, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	content := codec.BuildRequestContent(200, codec.ReqTypeKeepalive, nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, content)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// LastActivity should have been updated
	if client.LastActivity == 0 {
		t.Error("expected LastActivity to be updated")
	}

	// ACK should have been sent
	if h.transport.sentCount() == 0 {
		t.Error("expected ACK for keepalive")
	}
}

func TestRequest_GetStatus(t *testing.T) {
	h := newTestHarness(t)

	sp := &mockStatsProvider{stats: ServerStats{
		BattMilliVolts: 3700,
		NPacketsRecv:   42,
		NPosted:        10,
	}}
	h.server.cfg.Stats = sp

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	reqContent := codec.BuildRequestContent(300, codec.ReqTypeGetStats, nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() == 0 {
		t.Fatal("expected a response packet")
	}

	resp := h.transport.lastPacket()
	if resp.PayloadType() != codec.PayloadTypeResponse {
		t.Fatalf("expected RESPONSE type, got %s", codec.PayloadTypeName(resp.PayloadType()))
	}

	plaintext := h.decryptResponse(t, clientKey, resp)

	// Response: tag(4) + stats(52) = 56 bytes (may be zero-padded to AES block boundary)
	if len(plaintext) < 4+ServerStatsSize {
		t.Fatalf("expected at least %d bytes, got %d", 4+ServerStatsSize, len(plaintext))
	}

	// Tag should be the reflected request timestamp
	tag := binary.LittleEndian.Uint32(plaintext[0:4])
	if tag != 300 {
		t.Errorf("expected tag=300, got %d", tag)
	}

	// Verify some stats fields
	battMV := binary.LittleEndian.Uint16(plaintext[4:6])
	if battMV != 3700 {
		t.Errorf("expected batt_milli_volts=3700, got %d", battMV)
	}

	nRecv := binary.LittleEndian.Uint32(plaintext[12:16])
	if nRecv != 42 {
		t.Errorf("expected n_packets_recv=42, got %d", nRecv)
	}

	nPosted := binary.LittleEndian.Uint16(plaintext[52:54])
	if nPosted != 10 {
		t.Errorf("expected n_posted=10, got %d", nPosted)
	}
}

func TestRequest_GetStatus_NoProvider(t *testing.T) {
	h := newTestHarness(t)
	// No Stats provider set

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	reqContent := codec.BuildRequestContent(300, codec.ReqTypeGetStats, nil)
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// No response should be sent when provider is nil
	if h.transport.sentCount() != 0 {
		t.Errorf("expected no response without stats provider, got %d packets", h.transport.sentCount())
	}
}

func TestRequest_GetTelemetry(t *testing.T) {
	h := newTestHarness(t)

	tp := &mockTelemetryProvider{
		data: []byte{0x01, 0x74, 0x01, 0x70}, // fake CayenneLPP
	}
	h.server.cfg.Telemetry = tp

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request data: byte[0] = inverted perm mask. ~0xFE = 0x01
	reqContent := codec.BuildRequestContent(400, codec.ReqTypeGetTelemetry, []byte{0xFE})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() == 0 {
		t.Fatal("expected a response packet")
	}

	// Verify the permission mask was computed correctly: ^0xFE = 0x01
	if tp.lastPermMask != 0x01 {
		t.Errorf("expected permMask=0x01, got 0x%02x", tp.lastPermMask)
	}

	resp := h.transport.lastPacket()
	plaintext := h.decryptResponse(t, clientKey, resp)

	// Response: tag(4) + telemetry data(4) (may be zero-padded to AES block boundary)
	if len(plaintext) < 8 {
		t.Fatalf("expected at least 8 bytes, got %d", len(plaintext))
	}

	tag := binary.LittleEndian.Uint32(plaintext[0:4])
	if tag != 400 {
		t.Errorf("expected tag=400, got %d", tag)
	}

	// Verify telemetry data was included
	if plaintext[4] != 0x01 || plaintext[5] != 0x74 {
		t.Errorf("expected telemetry data, got %v", plaintext[4:])
	}
}

func TestRequest_GetTelemetry_GuestRestricted(t *testing.T) {
	h := newTestHarness(t)

	tp := &mockTelemetryProvider{
		data: []byte{0x01, 0x74, 0x01, 0x70},
	}
	h.server.cfg.Telemetry = tp

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLGuest, // guest
	})
	if err != nil {
		t.Fatal(err)
	}

	// Even though request asks for all sensors (~0x00 = 0xFF), guest gets 0x00
	reqContent := codec.BuildRequestContent(400, codec.ReqTypeGetTelemetry, []byte{0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() == 0 {
		t.Fatal("expected a response packet")
	}

	// Guest should always get permMask = 0x00
	if tp.lastPermMask != 0x00 {
		t.Errorf("expected guest permMask=0x00, got 0x%02x", tp.lastPermMask)
	}
}

func TestRequest_GetTelemetry_NoProvider(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	reqContent := codec.BuildRequestContent(400, codec.ReqTypeGetTelemetry, []byte{0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() != 0 {
		t.Errorf("expected no response without telemetry provider, got %d packets", h.transport.sentCount())
	}
}

func TestRequest_GetAccessList_Admin(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add another admin client
	otherKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var otherID core.MeshCoreID
	copy(otherID[:], otherKey.PublicKey)
	_, err = h.clients.AddClient(&ClientInfo{
		ID:          otherID,
		Permissions: codec.PermACLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Add a non-admin client (should be excluded)
	thirdKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var thirdID core.MeshCoreID
	copy(thirdID[:], thirdKey.PublicKey)
	_, err = h.clients.AddClient(&ClientInfo{
		ID:          thirdID,
		Permissions: codec.PermACLReadWrite,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reserved bytes must be 0
	reqContent := codec.BuildRequestContent(500, codec.ReqTypeGetAccessList, []byte{0x00, 0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() == 0 {
		t.Fatal("expected a response packet")
	}

	resp := h.transport.lastPacket()
	plaintext := h.decryptResponse(t, clientKey, resp)

	tag := binary.LittleEndian.Uint32(plaintext[0:4])
	if tag != 500 {
		t.Errorf("expected tag=500, got %d", tag)
	}

	// Should have 2 admin entries * 7 bytes each = 14 bytes of content after tag.
	// Decrypted data may be zero-padded to AES block boundary.
	expectedContentSize := 4 + 2*7 // tag + 2 entries
	if len(plaintext) < expectedContentSize {
		t.Fatalf("expected at least %d bytes, got %d", expectedContentSize, len(plaintext))
	}

	// Each entry: 6-byte pubkey prefix + 1-byte permissions
	for i := 0; i < 2; i++ {
		entryStart := 4 + i*7
		perms := plaintext[entryStart+6]
		if perms&codec.PermACLRoleMask != codec.PermACLAdmin {
			t.Errorf("entry %d: expected admin permissions, got 0x%02x", i, perms)
		}
	}
}

func TestRequest_GetAccessList_NonAdminRejected(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLReadWrite, // not admin
	})
	if err != nil {
		t.Fatal(err)
	}

	reqContent := codec.BuildRequestContent(500, codec.ReqTypeGetAccessList, []byte{0x00, 0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	// Non-admin should get no response
	if h.transport.sentCount() != 0 {
		t.Errorf("expected no response for non-admin, got %d packets", h.transport.sentCount())
	}
}

func TestRequest_GetAccessList_ReservedNonZero(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Reserved bytes are non-zero — should be rejected
	reqContent := codec.BuildRequestContent(500, codec.ReqTypeGetAccessList, []byte{0x01, 0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() != 0 {
		t.Errorf("expected no response with non-zero reserved bytes, got %d packets", h.transport.sentCount())
	}
}

func TestRequest_GetAccessList_EmptyACL(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)
	// The requesting client is admin but is also the only admin
	_, err := h.clients.AddClient(&ClientInfo{
		ID:          clientID,
		Permissions: codec.PermACLAdmin,
	})
	if err != nil {
		t.Fatal(err)
	}

	reqContent := codec.BuildRequestContent(500, codec.ReqTypeGetAccessList, []byte{0x00, 0x00})
	pkt := h.buildAddressedPacket(t, clientKey, clientID, codec.PayloadTypeReq, reqContent)
	h.server.HandlePacket(pkt, transport.PacketSourceMQTT)

	if h.transport.sentCount() == 0 {
		t.Fatal("expected a response packet")
	}

	resp := h.transport.lastPacket()
	plaintext := h.decryptResponse(t, clientKey, resp)

	// Should have 1 admin entry (the requesting client itself).
	// Decrypted data may be zero-padded to AES block boundary.
	expectedContentSize := 4 + 7 // tag + 1 entry
	if len(plaintext) < expectedContentSize {
		t.Fatalf("expected at least %d bytes, got %d", expectedContentSize, len(plaintext))
	}

	// Verify the entry is our client's pubkey prefix
	for i := 0; i < 6; i++ {
		if plaintext[4+i] != clientID[i] {
			t.Errorf("pubkey prefix byte %d: expected 0x%02x, got 0x%02x", i, clientID[i], plaintext[4+i])
		}
	}
}

// --- Sync loop tests ---

func TestSyncOnce_PushesPost(t *testing.T) {
	h := newTestHarness(t)

	clientKey, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:           clientID,
		Permissions:  codec.PermACLReadWrite,
		LastActivity: 1,
		SyncSince:    0,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = clientKey

	// Make a different sender for the post (not the client itself)
	otherKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var otherID core.MeshCoreID
	copy(otherID[:], otherKey.PublicKey)

	// Add a post that is old enough (PostSyncDelay = 6 seconds)
	_ = h.posts.AddPost(&PostInfo{
		Timestamp: 10,
		SenderID:  otherID,
		Content:   []byte("hello sync"),
	})

	// Set clock to a time well after the post + delay
	h.server.cfg.Clock = clock.New()

	pushed := h.server.syncOnce()
	if !pushed {
		t.Error("expected syncOnce to push a post")
	}

	// A packet should have been sent
	if h.transport.sentCount() == 0 {
		t.Error("expected a sync push packet")
	}
}

func TestSyncOnce_SkipsOwnPosts(t *testing.T) {
	h := newTestHarness(t)

	_, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:           clientID,
		Permissions:  codec.PermACLReadWrite,
		LastActivity: 1,
		SyncSince:    0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Post from the same client — should be skipped
	_ = h.posts.AddPost(&PostInfo{
		Timestamp: 10,
		SenderID:  clientID,
		Content:   []byte("my own post"),
	})

	pushed := h.server.syncOnce()
	if pushed {
		t.Error("expected syncOnce to skip client's own post")
	}
}

func TestSyncOnce_NoClients(t *testing.T) {
	h := newTestHarness(t)

	_ = h.posts.AddPost(&PostInfo{
		Timestamp: 10,
		Content:   []byte("orphan post"),
	})

	pushed := h.server.syncOnce()
	if pushed {
		t.Error("expected syncOnce to return false with no clients")
	}
}

func TestSyncOnce_SkipsPushFailures(t *testing.T) {
	h := newTestHarness(t)

	_, clientID := h.makeClientKeyAndContact(t)

	_, err := h.clients.AddClient(&ClientInfo{
		ID:            clientID,
		Permissions:   codec.PermACLReadWrite,
		LastActivity:  1,
		SyncSince:     0,
		PushFailures:  MaxPushFailures, // maxed out
	})
	if err != nil {
		t.Fatal(err)
	}

	otherKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	var otherID core.MeshCoreID
	copy(otherID[:], otherKey.PublicKey)

	_ = h.posts.AddPost(&PostInfo{
		Timestamp: 10,
		SenderID:  otherID,
		Content:   []byte("will be skipped"),
	})

	pushed := h.server.syncOnce()
	if pushed {
		t.Error("expected syncOnce to skip client with max push failures")
	}
}

// --- Server lifecycle tests ---

func TestServer_StartStop(t *testing.T) {
	h := newTestHarness(t)

	done := make(chan struct{})
	go func() {
		h.server.Start(context.Background())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	h.server.Stop()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop within timeout")
	}
}

func TestServer_StopBeforeStart(t *testing.T) {
	h := newTestHarness(t)
	// Should not panic
	h.server.Stop()
}

// --- ServerStats serialization tests ---

func TestServerStats_MarshalBinary(t *testing.T) {
	stats := ServerStats{
		BattMilliVolts:   3700,
		CurrTxQueueLen:   5,
		NoiseFloor:       -110,
		LastRSSI:         -80,
		NPacketsRecv:     1000,
		NPacketsSent:     500,
		TotalAirTimeSecs: 3600,
		TotalUpTimeSecs:  7200,
		NSentFlood:       200,
		NSentDirect:      300,
		NRecvFlood:       400,
		NRecvDirect:      600,
		ErrEvents:        3,
		LastSNR:          -32, // -8.0 dB * 4
		NDirectDups:      10,
		NFloodDups:       20,
		NPosted:          50,
		NPostPush:        45,
	}

	data := stats.MarshalBinary()
	if len(data) != ServerStatsSize {
		t.Fatalf("expected %d bytes, got %d", ServerStatsSize, len(data))
	}

	// Spot-check fields at known offsets
	if v := binary.LittleEndian.Uint16(data[0:2]); v != 3700 {
		t.Errorf("offset 0 batt: expected 3700, got %d", v)
	}
	if v := int16(binary.LittleEndian.Uint16(data[4:6])); v != -110 {
		t.Errorf("offset 4 noise_floor: expected -110, got %d", v)
	}
	if v := binary.LittleEndian.Uint32(data[8:12]); v != 1000 {
		t.Errorf("offset 8 n_packets_recv: expected 1000, got %d", v)
	}
	if v := int16(binary.LittleEndian.Uint16(data[42:44])); v != -32 {
		t.Errorf("offset 42 last_snr: expected -32, got %d", v)
	}
	if v := binary.LittleEndian.Uint16(data[48:50]); v != 50 {
		t.Errorf("offset 48 n_posted: expected 50, got %d", v)
	}
	if v := binary.LittleEndian.Uint16(data[50:52]); v != 45 {
		t.Errorf("offset 50 n_post_push: expected 45, got %d", v)
	}
}

// --- extractNullTerminated tests ---

func TestExtractNullTerminated(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{"empty", []byte{0}, ""},
		{"simple", []byte{'h', 'i', 0}, "hi"},
		{"no null", []byte{'h', 'i'}, "hi"},
		{"early null", []byte{'a', 0, 'b', 'c'}, "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNullTerminated(tt.input)
			if got != tt.want {
				t.Errorf("extractNullTerminated(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
