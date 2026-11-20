package node

import (
	"crypto/ed25519"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/contact"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/room"
	"github.com/kabili207/meshcore-go/transport"
)

func newPeersTestRoom(t *testing.T, kp *crypto.KeyPair, clients room.ClientStore) *RoomNode {
	t.Helper()
	priv := ed25519.PrivateKey(kp.PrivateKey)
	n, err := NewRoom(RoomConfig{
		PrivateKey: priv,
		Contacts:   contact.NewManager(priv, contact.ManagerConfig{MaxContacts: 64, OverwriteWhenFull: true}),
		Room: room.ServerConfig{
			AdminPassword: "adminpw",
			GuestPassword: "guestpw",
			Clients:       clients,
			Posts:         room.NewMemoryPostStore(100),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// buildRoomLogin builds an ANON_REQ login: timestamp(4) + sync_since(4) + password.
func buildRoomLogin(t *testing.T, n *RoomNode, client *crypto.KeyPair, timestamp uint32, password string) *codec.Packet {
	t.Helper()
	data := make([]byte, 8+len(password)+1)
	binary.LittleEndian.PutUint32(data[0:4], timestamp)
	copy(data[8:], password)

	roomPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, roomPub[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(data, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	var clientPub [32]byte
	copy(clientPub[:], client.PublicKey)
	payload := codec.BuildAnonReqPayload(n.base.ID().Hash(), clientPub, mac, ciphertext)
	return &codec.Packet{
		Header:  (codec.PayloadTypeAnonReq << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

// buildRoomTxt builds an addressed plain TXT_MSG from client to the room.
func buildRoomTxt(t *testing.T, n *RoomNode, client *crypto.KeyPair, msg string) *codec.Packet {
	t.Helper()
	content := codec.BuildTxtMsgContent(200, codec.TxtTypePlain, 0, msg, nil)
	roomPub := n.base.PublicKey()
	secret, err := crypto.ComputeSharedSecret(client.PrivateKey, roomPub[:])
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		t.Fatal(err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	id := clientID(client)
	payload := codec.BuildAddressedPayload(n.base.ID().Hash(), id.Hash(), mac, ciphertext)
	return &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeDirect,
		Payload: payload,
	}
}

// countTexts counts TextMessageReceived events, which fire only once a message
// has decrypted.
func countTexts(n *RoomNode) *int {
	var count int
	n.OnEvent(func(evt any) {
		if _, ok := evt.(*event.TextMessageReceived); ok {
			count++
		}
	})
	return &count
}

// Adverts must not push a logged-in client out of the peer table, or its posts
// stop decrypting and it stops receiving pushed posts.
func TestRoomPeers_ClientSurvivesAdvertFlood(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	n := newPeersTestRoom(t, kp, room.NewMemoryClientStore(20))
	texts := countTexts(n)
	client, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRoomLogin(t, n, client, 100, "guestpw"), transport.PacketSourceMQTT)

	for i := 0; i < 100; i++ {
		peer, _ := crypto.GenerateKeyPair()
		n.base.processPacket(buildRepeaterAdvert(t, peer, 500, codec.NodeTypeChat), transport.PacketSourceMQTT)
	}
	if got := n.base.Contacts().Count(); got != 1 {
		t.Errorf("peer table holds %d entries, want only the logged-in client", got)
	}

	n.base.processPacket(buildRoomTxt(t, n, client, "hello"), transport.PacketSourceMQTT)
	if *texts != 1 {
		t.Fatal("client's post did not decrypt after an advert flood")
	}
}

// A client the room's client store evicts must lose its peer entry too.
func TestRoomPeers_FollowClientEviction(t *testing.T) {
	kp, _ := crypto.GenerateKeyPair()
	clients := room.NewMemoryClientStore(2)
	n := newPeersTestRoom(t, kp, clients)

	first, _ := crypto.GenerateKeyPair()
	n.base.processPacket(buildRoomLogin(t, n, first, 100, "guestpw"), transport.PacketSourceMQTT)
	for i := 0; i < 2; i++ {
		guest, _ := crypto.GenerateKeyPair()
		n.base.processPacket(buildRoomLogin(t, n, guest, 100, "guestpw"), transport.PacketSourceMQTT)
	}

	if clients.GetClient(clientID(first)) != nil {
		t.Fatal("precondition: first guest should have been evicted from the client store")
	}
	if n.base.Contacts().GetByPubKey(clientID(first)) != nil {
		t.Error("evicted client is still in the peer table")
	}
	if got := n.base.Contacts().Count(); got != 2 {
		t.Errorf("peer table holds %d entries, want 2", got)
	}
}

// An admin restored from client persistence can post without logging in again.
func TestRoomPeers_PersistedAdminPosts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	kp, _ := crypto.GenerateKeyPair()
	client, _ := crypto.GenerateKeyPair()

	fs := acl.NewFileStore(path)
	n := newPeersTestRoom(t, kp, room.NewMemoryClientStore(20, room.WithPersistence(fs)))
	n.base.processPacket(buildRoomLogin(t, n, client, 100, "adminpw"), transport.PacketSourceMQTT)
	if err := fs.Close(); err != nil {
		t.Fatal(err)
	}

	n2 := newPeersTestRoom(t, kp, room.NewMemoryClientStore(20, room.WithPersistence(acl.NewFileStore(path))))
	texts := countTexts(n2)
	n2.base.processPacket(buildRoomTxt(t, n2, client, "hello"), transport.PacketSourceMQTT)
	if *texts != 1 {
		t.Fatal("restored admin's post did not decrypt")
	}
}
