package node

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// testNode creates a BaseNode with a fresh keypair, contact manager, and
// an event collector for testing.
func testNode(t *testing.T) (*BaseNode, *eventCollector) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	contacts := contact.NewManager(kp.PrivateKey, contact.ManagerConfig{
		MaxContacts:       32,
		OverwriteWhenFull: true,
	})

	tracker := ack.NewTracker(ack.TrackerConfig{
		ACKTimeout: 5 * time.Second,
		MaxRetries: 0,
	})

	collector := &eventCollector{}

	node, err := NewBase(BaseConfig{
		PrivateKey:    kp.PrivateKey,
		Contacts:      contacts,
		ACKTracker:    tracker,
		EventHandlers: []event.Handler{collector.handler},
	})
	if err != nil {
		t.Fatalf("new base node: %v", err)
	}

	return node, collector
}

// captureTransport records packets the node sends, so tests can inspect ACKs.
type captureTransport struct {
	sent []*codec.Packet
}

func (c *captureTransport) Start(context.Context) error                { return nil }
func (c *captureTransport) Stop() error                                { return nil }
func (c *captureTransport) IsConnected() bool                          { return true }
func (c *captureTransport) SetPacketHandler(_ transport.PacketHandler) {}
func (c *captureTransport) SetStateHandler(_ transport.StateHandler)   {}
func (c *captureTransport) SendPacket(pkt *codec.Packet) error {
	c.sent = append(c.sent, pkt)
	return nil
}

// peerKeyPair generates a separate keypair for simulating a remote peer.
func peerKeyPair(t *testing.T) *crypto.KeyPair {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate peer keypair: %v", err)
	}
	return kp
}

// eventCollector records events for assertion.
type eventCollector struct {
	mu     sync.Mutex
	events []any
}

func (c *eventCollector) handler(evt any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, evt)
}

func (c *eventCollector) get() []any {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]any, len(c.events))
	copy(result, c.events)
	return result
}

func (c *eventCollector) last() any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return nil
	}
	return c.events[len(c.events)-1]
}

func TestHandleAdvert(t *testing.T) {
	node, collector := testNode(t)
	peer := peerKeyPair(t)

	// Build a signed advert
	var pubKey [32]byte
	copy(pubKey[:], peer.PublicKey)
	ts := uint32(time.Now().Unix())
	appData := &codec.AdvertAppData{
		NodeType: codec.NodeTypeChat,
		Name:     "TestPeer",
	}
	appDataBytes := codec.BuildAdvertAppData(appData)
	sig, err := crypto.SignAdvert(peer.PrivateKey, pubKey, ts, appDataBytes)
	if err != nil {
		t.Fatalf("sign advert: %v", err)
	}
	payload := codec.BuildAdvertPayload(pubKey, ts, sig, appData)
	pkt := codec.NewPacket(codec.PayloadTypeAdvert, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	adv, ok := events[0].(*event.AdvertReceived)
	if !ok {
		t.Fatalf("expected AdvertReceived, got %T", events[0])
	}
	if adv.Advert.AppData.Name != "TestPeer" {
		t.Errorf("expected name TestPeer, got %s", adv.Advert.AppData.Name)
	}
	if !adv.IsNew {
		t.Error("expected IsNew=true for first advert")
	}
	if adv.Contact == nil {
		t.Error("expected Contact to be non-nil")
	}

	// Verify contact was stored
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	ct := node.contacts.GetByPubKey(peerID)
	if ct == nil {
		t.Error("contact not found in store after advert")
	}
}

func TestHandleAdvert_Replay(t *testing.T) {
	node, collector := testNode(t)
	peer := peerKeyPair(t)

	var pubKey [32]byte
	copy(pubKey[:], peer.PublicKey)
	ts := uint32(time.Now().Unix())
	appData := &codec.AdvertAppData{NodeType: codec.NodeTypeChat, Name: "Peer"}
	appDataBytes := codec.BuildAdvertAppData(appData)
	sig, _ := crypto.SignAdvert(peer.PrivateKey, pubKey, ts, appDataBytes)
	payload := codec.BuildAdvertPayload(pubKey, ts, sig, appData)
	pkt := codec.NewPacket(codec.PayloadTypeAdvert, codec.RouteTypeFlood, payload)

	// First advert succeeds
	node.processPacket(pkt, transport.PacketSourceMQTT)
	if len(collector.get()) != 1 {
		t.Fatal("expected 1 event from first advert")
	}

	// Replay with same timestamp is rejected (no new event)
	node.processPacket(pkt, transport.PacketSourceMQTT)
	if len(collector.get()) != 1 {
		t.Fatal("expected replay to be rejected (still 1 event)")
	}
}

// TestHandleAdvert_ForgedSignatureNotForwarded verifies that an advert with an
// invalid signature is dropped without being processed and, critically, is
// marked do-not-retransmit so the router will not re-flood it (matching the
// firmware, which verifies before forwarding).
func TestHandleAdvert_ForgedSignatureNotForwarded(t *testing.T) {
	node, collector := testNode(t)
	peer := peerKeyPair(t)

	var pubKey [32]byte
	copy(pubKey[:], peer.PublicKey)
	ts := uint32(time.Now().Unix())
	appData := &codec.AdvertAppData{NodeType: codec.NodeTypeChat, Name: "Forged"}
	appDataBytes := codec.BuildAdvertAppData(appData)
	sig, err := crypto.SignAdvert(peer.PrivateKey, pubKey, ts, appDataBytes)
	if err != nil {
		t.Fatalf("sign advert: %v", err)
	}
	sig[0] ^= 0xFF // corrupt the signature

	payload := codec.BuildAdvertPayload(pubKey, ts, sig, appData)
	pkt := codec.NewPacket(codec.PayloadTypeAdvert, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	if got := len(collector.get()); got != 0 {
		t.Fatalf("expected 0 events for forged advert, got %d", got)
	}
	if !pkt.IsMarkedDoNotRetransmit() {
		t.Error("expected forged advert to be marked do-not-retransmit")
	}

	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	if node.contacts.GetByPubKey(peerID) != nil {
		t.Error("forged advert should not have created a contact")
	}
}

func TestHandleTxtMsg(t *testing.T) {
	node, collector := testNode(t)
	peer := peerKeyPair(t)

	// Pre-seed contact so decryption works
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	_, err := node.contacts.AddContact(&contact.ContactInfo{
		ID:         peerID,
		Name:       "Sender",
		OutPathLen: contact.PathUnknown,
	})
	if err != nil {
		t.Fatalf("add contact: %v", err)
	}

	// Compute shared secret (peer's perspective)
	secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	if err != nil {
		t.Fatalf("compute shared secret: %v", err)
	}

	// Build encrypted text message
	plaintext := codec.BuildTxtMsgContent(uint32(time.Now().Unix()), codec.TxtTypePlain, 0, "Hello BBS!", nil)
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(node.id.Hash(), peerID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	msg, ok := events[0].(*event.TextMessageReceived)
	if !ok {
		t.Fatalf("expected TextMessageReceived, got %T", events[0])
	}
	if msg.Message != "Hello BBS!" {
		t.Errorf("expected message 'Hello BBS!', got %q", msg.Message)
	}
	if msg.TxtType != codec.TxtTypePlain {
		t.Errorf("expected TxtTypePlain, got %d", msg.TxtType)
	}
	if msg.From != peerID {
		t.Error("expected From to be peer ID")
	}
	if len(msg.Reply.SharedSecret) == 0 {
		t.Error("expected ReplyContext to have SharedSecret")
	}
}

// TestHandleTxtMsg_SignedAutoACK verifies that a signed message (as a room server
// pushes for a post) is auto-ACKed with a 4-byte hash keyed by the receiver's own
// pubkey — exactly what the server computes as its expected push ACK.
func TestHandleTxtMsg_SignedAutoACK(t *testing.T) {
	node, _ := testNode(t)
	ct := &captureTransport{}
	node.Router.AddTransport(ct, transport.PacketSourceMQTT)

	peer := peerKeyPair(t)
	var peerID core.MeshCoreID
	copy(peerID[:], peer.PublicKey)
	if _, err := node.contacts.AddContact(&contact.ContactInfo{
		ID:         peerID,
		Name:       "Server",
		OutPathLen: contact.PathUnknown,
	}); err != nil {
		t.Fatalf("add contact: %v", err)
	}

	secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, node.publicKey[:])
	if err != nil {
		t.Fatalf("compute shared secret: %v", err)
	}

	// A SIGNED_PLAIN message carrying an author pubkey prefix.
	author := []byte{0x01, 0x02, 0x03, 0x04}
	plaintext := codec.BuildTxtMsgContent(1234, codec.TxtTypeSigned, 0, "posted!", author)
	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(node.id.Hash(), peerID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	var ackPkt *codec.Packet
	for _, p := range ct.sent {
		if p.PayloadType() == codec.PayloadTypeAck {
			ackPkt = p
		}
	}
	if ackPkt == nil {
		t.Fatal("expected an auto-ACK for the signed message")
	}
	if len(ackPkt.Payload) != codec.AckSize {
		t.Errorf("signed ACK payload len = %d, want %d (4-byte form)", len(ackPkt.Payload), codec.AckSize)
	}
	parsedAck, err := codec.ParseAckPayload(ackPkt.Payload)
	if err != nil {
		t.Fatalf("ParseAckPayload: %v", err)
	}
	want := crypto.ComputeAckHash(plaintext, node.id[:])
	if parsedAck.Checksum != want {
		t.Errorf("signed ACK checksum = %08x, want %08x (keyed by receiver pubkey)", parsedAck.Checksum, want)
	}
}

func TestHandleAck(t *testing.T) {
	node, collector := testNode(t)

	checksum := uint32(0xDEADBEEF)
	payload := codec.BuildAckPayload(checksum)
	pkt := codec.NewPacket(codec.PayloadTypeAck, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ackEvt, ok := events[0].(*event.AckReceived)
	if !ok {
		t.Fatalf("expected AckReceived, got %T", events[0])
	}
	if ackEvt.Checksum != checksum {
		t.Errorf("expected checksum 0x%x, got 0x%x", checksum, ackEvt.Checksum)
	}
}

func TestHandleAnonReq(t *testing.T) {
	node, collector := testNode(t)
	peer := peerKeyPair(t)

	// Build anonymous request (login-style)
	// EncryptAnonymous generates an ephemeral keypair internally
	_ = peer // peer not used for anon req (ephemeral key is generated)

	loginData := make([]byte, 9)
	// timestamp(4) + syncSince(4) + null terminator for empty password
	loginData[8] = 0

	// Encrypt anonymously to our node
	ephemeralPubKey, encrypted, err := crypto.EncryptAnonymous(loginData, node.publicKey[:])
	if err != nil {
		t.Fatalf("encrypt anonymous: %v", err)
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAnonReqPayload(node.id.Hash(), ephemeralPubKey, mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeAnonReq, codec.RouteTypeFlood, payload)

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	anon, ok := events[0].(*event.AnonRequestReceived)
	if !ok {
		t.Fatalf("expected AnonRequestReceived, got %T", events[0])
	}
	if anon.EphemeralPubKey != ephemeralPubKey {
		t.Error("expected ephemeral pubkey to match")
	}
	if len(anon.Plaintext) == 0 {
		t.Error("expected non-empty plaintext")
	}
	if len(anon.Reply.SharedSecret) == 0 {
		t.Error("expected ReplyContext to have SharedSecret")
	}
}

func TestHandleUnknownPayloadType(t *testing.T) {
	node, collector := testNode(t)

	pkt := codec.NewPacket(codec.PayloadTypeRawCustom, codec.RouteTypeFlood, []byte{0x01, 0x02})

	node.processPacket(pkt, transport.PacketSourceMQTT)

	events := collector.get()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	_, ok := events[0].(*event.PacketReceived)
	if !ok {
		t.Fatalf("expected PacketReceived catch-all, got %T", events[0])
	}
}

func TestMultipleEventHandlers(t *testing.T) {
	node, collector1 := testNode(t)
	collector2 := &eventCollector{}
	node.OnEvent(collector2.handler)

	pkt := codec.NewPacket(codec.PayloadTypeAck, codec.RouteTypeFlood, codec.BuildAckPayload(123))
	node.processPacket(pkt, transport.PacketSourceMQTT)

	if len(collector1.get()) != 1 {
		t.Error("collector1 should have received event")
	}
	if len(collector2.get()) != 1 {
		t.Error("collector2 should have received event")
	}
}
