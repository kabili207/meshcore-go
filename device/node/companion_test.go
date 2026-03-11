package node

import (
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
)

func TestNewCompanion_Defaults(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	contacts := contact.NewManager(kp.PrivateKey, contact.ManagerConfig{
		MaxContacts:       32,
		OverwriteWhenFull: true,
	})

	cn, err := NewCompanion(CompanionConfig{
		PrivateKey: kp.PrivateKey,
		Contacts:   contacts,
		Name:       "TestNode",
	})
	if err != nil {
		t.Fatalf("new companion: %v", err)
	}

	if cn.Base() == nil {
		t.Fatal("expected non-nil base node")
	}
	if cn.ACKTracker() == nil {
		t.Fatal("expected non-nil ACK tracker")
	}
	if cn.AdvertScheduler() == nil {
		t.Fatal("expected non-nil advert scheduler")
	}
	if cn.ID() != cn.Base().ID() {
		t.Error("ID should delegate to base")
	}
}

func TestNewCompanion_CustomTimeouts(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	contacts := contact.NewManager(kp.PrivateKey, contact.ManagerConfig{
		MaxContacts:       32,
		OverwriteWhenFull: true,
	})

	cn, err := NewCompanion(CompanionConfig{
		PrivateKey: kp.PrivateKey,
		Contacts:   contacts,
		Name:       "CustomNode",
		ACKTimeout: 30 * time.Second,
		MaxRetries: 5,
	})
	if err != nil {
		t.Fatalf("new companion: %v", err)
	}

	// Verify it created successfully with custom config
	if cn.Base() == nil {
		t.Fatal("expected non-nil base node")
	}
}

func TestNewCompanion_WithTransports(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	contacts := contact.NewManager(kp.PrivateKey, contact.ManagerConfig{
		MaxContacts:       32,
		OverwriteWhenFull: true,
	})

	// Verify transports are accepted in config without error
	cn, err := NewCompanion(CompanionConfig{
		PrivateKey: kp.PrivateKey,
		Contacts:   contacts,
		Name:       "WithTransports",
		Transports: []TransportOption{},
	})
	if err != nil {
		t.Fatalf("new companion: %v", err)
	}
	if cn.Base() == nil {
		t.Fatal("expected non-nil base node")
	}
}
