package node

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/contact"
)

type savedPath struct {
	OutPathLen uint8
	OutPath    []byte
}

type recordingPersistence struct {
	saved map[core.MeshCoreID]savedPath
}

func (r *recordingPersistence) Load() ([]*contact.ContactInfo, error) { return nil, nil }

func (r *recordingPersistence) Save(c *contact.ContactInfo) error {
	r.saved[c.ID] = savedPath{c.OutPathLen, bytes.Clone(c.OutPath)}
	return nil
}

func (r *recordingPersistence) Delete(id core.MeshCoreID) error {
	delete(r.saved, id)
	return nil
}

func TestPathChangesArePersisted(t *testing.T) {
	comp, _ := newTestCompanion(t)
	store := &recordingPersistence{saved: map[core.MeshCoreID]savedPath{}}
	comp.base.contacts = contact.NewManager(comp.base.privateKey, contact.ManagerConfig{Persistence: store})

	var id core.MeshCoreID
	id[0] = 0x42
	ct, err := comp.base.Contacts().AddContact(&contact.ContactInfo{ID: id, OutPathLen: contact.PathUnknown})
	if err != nil {
		t.Fatal(err)
	}

	comp.base.updateContactPathFromFlood(&codec.Packet{
		Header:       codec.RouteTypeFlood,
		PathLen:      2,
		PathHashSize: 1,
		Path:         []byte{0x0A, 0x0B},
	}, ct)
	if got, want := store.saved[id].OutPath, []byte{0x0B, 0x0A}; !bytes.Equal(got, want) {
		t.Errorf("saved path = %x, want %x", got, want)
	}

	comp.ResetPath(id)
	if got := store.saved[id].OutPathLen; got != contact.PathUnknown {
		t.Errorf("saved path length = %d, want unknown", got)
	}
}
