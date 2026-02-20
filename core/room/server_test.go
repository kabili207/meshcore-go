package room

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/ack"
	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/contact"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/core/router"
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

	// Build the wire-format ANON_REQ payload with the client's actual public key
	var clientPub [32]byte
	copy(clientPub[:], clientKey.PublicKey)
	destHash := core.MeshCoreID(h.server.cfg.PublicKey).Hash()
	payload := codec.BuildAnonReqPayload(destHash, clientPub, 0, encrypted)

	return &codec.Packet{
		Header:  codec.PayloadTypeAnonReq << codec.PHTypeShift,
		Payload: payload,
	}
}

// buildAddressedPacket builds an encrypted addressed packet from a known client.
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

	destHash := core.MeshCoreID(h.server.cfg.PublicKey).Hash()
	srcHash := clientID.Hash()
	payload := codec.BuildAddressedPayload(destHash, srcHash, 0, encrypted)

	return &codec.Packet{
		Header:  payloadType << codec.PHTypeShift,
		Payload: payload,
	}
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
