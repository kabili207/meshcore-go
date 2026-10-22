package contact

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

// An advert from a transient (anon) contact replaces it with a real contact
// allocated from the main pool, as firmware's onAdvertRecv clears the anon slot
// before adding. Updating it in place let the main pool grow into the anon
// slots, after which no new anonymous request could get a slot.
func TestProcessAdvert_TransientReplacedFromMainPool(t *testing.T) {
	m := NewManager(generateTestKeyPair(t).PrivateKey, ManagerConfig{
		MaxContacts:       2,
		MaxAnonContacts:   1,
		OverwriteWhenFull: true,
	})
	for i, name := range []string{"A", "B"} {
		ProcessAdvert(m, makeSignedAdvert(t, generateTestKeyPair(t), name, codec.NodeTypeChat, 1000), uint32(5000+i), true)
	}

	anonKP := generateTestKeyPair(t)
	var anonID core.MeshCoreID
	copy(anonID[:], anonKP.PublicKey)
	path := []byte{0x21, 0x22}
	if _, err := m.AddContact(&ContactInfo{ID: anonID, Type: codec.NodeTypeNone, OutPathLen: 2, OutPath: path, LastMod: 6000}); err != nil {
		t.Fatal(err)
	}

	result := ProcessAdvert(m, makeSignedAdvert(t, anonKP, "Was Anon", codec.NodeTypeChat, 1000), 7000, true)
	if result.Rejected || !result.IsNew {
		t.Fatalf("result = %+v, want a new contact", result)
	}
	if result.Contact.Type != codec.NodeTypeChat || result.Contact.IsTransient() {
		t.Errorf("contact type = %d, want chat", result.Contact.Type)
	}
	// Repeaters and room servers route replies to logged-in clients through
	// these entries, so the learned path carries over.
	if result.Contact.OutPathLen != 2 || !bytes.Equal(result.Contact.OutPath, path) {
		t.Errorf("path = %d/%x, want 2/%x carried over", result.Contact.OutPathLen, result.Contact.OutPath, path)
	}

	regular := 0
	m.ForEach(func(c *ContactInfo) bool {
		if !c.IsTransient() {
			regular++
		}
		return true
	})
	if regular > 2 {
		t.Errorf("%d regular contacts, want at most MaxContacts (2)", regular)
	}

	// The anon pool must still have room for a new anonymous request.
	var newAnon core.MeshCoreID
	newAnon[0] = 0x99
	if _, err := m.AddContact(&ContactInfo{ID: newAnon, Type: codec.NodeTypeNone, OutPathLen: PathUnknown}); err != nil {
		t.Errorf("anon pool starved after the transient advert: %v", err)
	}
}

// When the advert wouldn't be added, the transient entry is left alone rather
// than promoted to a real contact.
func TestProcessAdvert_TransientNotAutoAddedStaysTransient(t *testing.T) {
	m := NewManager(generateTestKeyPair(t).PrivateKey, ManagerConfig{MaxContacts: 4})
	anonKP := generateTestKeyPair(t)
	var anonID core.MeshCoreID
	copy(anonID[:], anonKP.PublicKey)
	if _, err := m.AddContact(&ContactInfo{ID: anonID, Type: codec.NodeTypeNone, OutPathLen: PathUnknown}); err != nil {
		t.Fatal(err)
	}

	result := ProcessAdvert(m, makeSignedAdvert(t, anonKP, "Was Anon", codec.NodeTypeChat, 1000), 7000, false)
	if !result.Rejected {
		t.Error("advert with auto-add off should be rejected")
	}
	c := m.GetByPubKey(anonID)
	if c == nil || !c.IsTransient() {
		t.Errorf("transient entry = %+v, want it left in place and transient", c)
	}
}
