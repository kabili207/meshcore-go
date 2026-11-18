package companion

import (
	"bytes"
	"errors"
	"testing"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/router"
)

type memPersistence struct {
	settings *Settings
	channels map[uint8]Channel
	loadErr  error
	saves    int
}

func (m *memPersistence) LoadSettings(s *Settings) error {
	if m.loadErr != nil {
		return m.loadErr
	}
	if m.settings != nil {
		*s = *m.settings
	}
	return nil
}

func (m *memPersistence) SaveSettings(s *Settings) error {
	saved := *s
	m.settings = &saved
	m.saves++
	return nil
}

func (m *memPersistence) LoadChannels() ([]Channel, error) {
	var out []Channel
	for _, ch := range m.channels {
		out = append(out, ch)
	}
	return out, nil
}

func (m *memPersistence) SaveChannel(ch Channel) error {
	if m.channels == nil {
		m.channels = map[uint8]Channel{}
	}
	m.channels[ch.Index] = ch
	return nil
}

func setChannelFrame(idx uint8, name string, secret []byte) []byte {
	f := make([]byte, 50)
	f[0], f[1] = serial.CmdSetChannel, idx
	copy(f[2:34], name)
	copy(f[34:50], secret)
	return f
}

func TestSettingsAndChannelsSurviveRestart(t *testing.T) {
	store := &memPersistence{}
	secret := bytes.Repeat([]byte{9}, 16)
	node := &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	s := NewServer(Config{Node: node, Identity: Identity{Name: "first"}, Persistence: store})

	var input []byte
	input = append(input, cmd(append([]byte{serial.CmdSetAdvertName}, "renamed"...)...)...)
	input = append(input, cmd(setChannelFrame(1, "club", secret)...)...)
	input = append(input, cmd(setChannelFrame(0, "", make([]byte, 16))...)...)
	collectResponses(t, s, input)

	node = &fakeNode{clk: clock.New(), contacts: &stubStore{}}
	node.AddChannel(crypto.DefaultChannelKey) // as CompanionNode does
	s = NewServer(Config{Node: node, Identity: Identity{Name: "flag"}, Persistence: store})

	if s.Name() != "renamed" {
		t.Errorf("name = %q, want the saved name", s.Name())
	}
	if idx, ok := s.channelIndexForKey(secret); !ok || idx != 1 {
		t.Errorf("channel index = %d, %v, want 1", idx, ok)
	}
	if !node.hasChannel(secret) {
		t.Error("restored channel was not registered with the node")
	}
	if node.hasChannel(crypto.DefaultChannelKey) {
		t.Error("deleted Public channel came back")
	}
}

func TestFirstRunSavesInitialSettings(t *testing.T) {
	store := &memPersistence{}
	NewServer(Config{Node: &fakeNode{clk: clock.New(), contacts: &stubStore{}}, Identity: Identity{Name: "first"}, Persistence: store})
	if store.settings == nil || store.settings.Name != "first" {
		t.Errorf("saved settings = %+v", store.settings)
	}
}

func TestDefaultScopeAppliedOnRestore(t *testing.T) {
	var key router.TransportKey
	key[0] = 0x11
	var applied router.TransportKey
	NewServer(Config{
		Node:          &fakeNode{clk: clock.New(), contacts: &stubStore{}},
		Persistence:   &memPersistence{settings: &Settings{DefaultScopeKey: key}},
		SetFloodScope: func(k router.TransportKey) { applied = k },
	})
	if applied != key {
		t.Errorf("applied scope = %x, want %x", applied, key)
	}
}

func TestLoadFailureDoesNotOverwrite(t *testing.T) {
	saved := &Settings{Name: "precious"}
	store := &memPersistence{settings: saved, loadErr: errors.New("boom")}
	s := NewServer(Config{Node: &fakeNode{clk: clock.New(), contacts: &stubStore{}}, Identity: Identity{Name: "x"}, Persistence: store})
	collectResponses(t, s, cmd(append([]byte{serial.CmdSetAdvertName}, "new"...)...))
	if store.saves != 0 || store.settings.Name != "precious" {
		t.Errorf("saved state was overwritten: %+v after %d saves", store.settings, store.saves)
	}
}
