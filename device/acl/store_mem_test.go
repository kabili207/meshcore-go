package acl

import (
	"bytes"
	"testing"

	"github.com/kabili207/meshcore-go/core"
)

func TestMemoryStore_UpdateWithStoredPointerKeepsPath(t *testing.T) {
	s := NewMemoryStore(4)
	stored, err := s.AddClient(&Client{ID: core.MeshCoreID{0x01}, OutPathLen: 2, OutPath: []byte{0x0A, 0x0B}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateClient(stored); err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x0A, 0x0B}; !bytes.Equal(stored.OutPath, want) {
		t.Errorf("OutPath = %x, want %x", stored.OutPath, want)
	}
}
