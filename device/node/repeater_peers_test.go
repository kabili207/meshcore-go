package node

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/transport"
)

// Adverts from a busy mesh must not push a logged-in admin out of the peer
// table, or the admin's CLI packets stop decrypting.
func TestRepeaterPeers_AdminSurvivesAdvertFlood(t *testing.T) {
	n, ct := newTestRepeater(t, "adminpw", "guestpw")
	client, _ := crypto.GenerateKeyPair()
	loginAdmin(t, n, client)

	for i := 0; i < 300; i++ {
		peer, _ := crypto.GenerateKeyPair()
		n.base.processPacket(buildRepeaterAdvert(t, peer, 500, codec.NodeTypeChat), transport.PacketSourceMQTT)
	}
	if got := n.base.Contacts().Count(); got != 1 {
		t.Errorf("peer table holds %d entries, want only the logged-in client", got)
	}

	n.base.processPacket(buildRepeaterCLI(t, n, client, "get role"), transport.PacketSourceMQTT)
	if _, ok := lastCLIReply(t, n, client, ct); !ok {
		t.Fatal("admin CLI went unanswered after an advert flood")
	}
}

// Every verified advert still reaches event handlers, since apps such as
// bridges track nodes the repeater itself doesn't keep.
func TestRepeaterPeers_AdvertEventsStillEmitted(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	var adverts int
	n.OnEvent(func(evt any) {
		if _, ok := evt.(*event.AdvertReceived); ok {
			adverts++
		}
	})

	peer, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterAdvert(t, peer, 500, codec.NodeTypeChat), transport.PacketSourceMQTT)
	if adverts != 1 {
		t.Errorf("got %d AdvertReceived events, want 1", adverts)
	}
}

// The all-zero key admits forged adverts, so they must not surface as events
// now that the contact store no longer screens them.
func TestRepeaterPeers_ZeroKeyAdvertDropped(t *testing.T) {
	n, _ := newTestRepeater(t, "adminpw", "guestpw")
	var adverts int
	n.OnEvent(func(evt any) {
		if _, ok := evt.(*event.AdvertReceived); ok {
			adverts++
		}
	})

	// The zero key has order 4, so R = identity, S = 0 verifies whenever the
	// challenge hash is a multiple of 4.
	appData := &codec.AdvertAppData{NodeType: codec.NodeTypeChat, Name: "Null"}
	advert := &codec.AdvertPayload{AppData: appData}
	advert.Signature[0] = 0x01
	for ts := uint32(1); ; ts++ {
		advert.Timestamp = ts
		if crypto.VerifyAdvert(advert) {
			break
		}
		if ts > 1000 {
			t.Fatal("no forgeable timestamp found")
		}
	}
	payload := codec.BuildAdvertPayload(advert.PubKey, advert.Timestamp, advert.Signature, appData)
	n.base.processPacket(codec.NewPacket(codec.PayloadTypeAdvert, codec.RouteTypeFlood, payload), transport.PacketSourceMQTT)

	if adverts != 0 {
		t.Errorf("zero-key advert emitted %d events, want 0", adverts)
	}
}

// A client the ACL evicts must lose its peer entry too.
func TestRepeaterPeers_FollowACLEviction(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:    ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword: "adminpw",
		GuestPassword: "guestpw",
		MaxClients:    2,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRepeaterLogin(t, n, first, 100, "guestpw"), transport.PacketSourceMQTT)
	for i := 0; i < 2; i++ {
		guest, _ := crypto.GenerateKeyPair()
		n.base.processPacket(buildRepeaterLogin(t, n, guest, 100, "guestpw"), transport.PacketSourceMQTT)
	}

	if n.acl.GetClient(clientID(first)) != nil {
		t.Fatal("precondition: first guest should have been evicted from the ACL")
	}
	if n.base.Contacts().GetByPubKey(clientID(first)) != nil {
		t.Error("evicted client is still in the peer table")
	}
	if got := n.base.Contacts().Count(); got != 2 {
		t.Errorf("peer table holds %d entries, want 2", got)
	}
}

// An admin restored from ACL persistence can run commands without logging in
// again, as on firmware, which keeps the shared secret with the ACL entry.
func TestRepeaterPeers_PersistedAdminRunsCLI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acl.json")
	kp, _ := crypto.GenerateKeyPair()
	client, _ := crypto.GenerateKeyPair()

	fs := acl.NewFileStore(path)
	n, err := NewRepeater(RepeaterConfig{
		PrivateKey:     ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword:  "adminpw",
		ACLPersistence: fs,
	})
	if err != nil {
		t.Fatal(err)
	}
	loginAdmin(t, n, client)
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	n2, err := NewRepeater(RepeaterConfig{
		PrivateKey:     ed25519.PrivateKey(kp.PrivateKey),
		AdminPassword:  "adminpw",
		ACLPersistence: acl.NewFileStore(path),
	})
	if err != nil {
		t.Fatal(err)
	}
	ct := &captureTransport{}
	n2.base.Router.AddTransport(ct, transport.PacketSourceMQTT)

	n2.base.processPacket(buildRepeaterCLI(t, n2, client, "get role"), transport.PacketSourceMQTT)
	if _, ok := lastCLIReply(t, n2, client, ct); !ok {
		t.Fatal("restored admin's CLI went unanswered")
	}
}
