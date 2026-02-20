package advert

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
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

// makeTestRouter creates a router with a mock transport for testing.
func makeTestRouter(t *testing.T, mt *mockTransport) *router.Router {
	t.Helper()
	r := router.New(router.Config{
		SelfID: core.MeshCoreID{0x42},
	})
	r.AddTransport(mt, transport.PacketSourceMQTT)
	return r
}

// makeTestBuilder creates a simple AdvertBuilder that counts invocations.
func makeTestBuilder(callCount *atomic.Int32) AdvertBuilder {
	return func() *codec.Packet {
		callCount.Add(1)
		return &codec.Packet{
			Header:  codec.PayloadTypeAdvert << codec.PHTypeShift,
			Payload: make([]byte, codec.AdvertMinSize),
		}
	}
}

func TestScheduler_NewScheduler_Defaults(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)

	// Both intervals zero → use defaults
	s := NewScheduler(r, func() *codec.Packet { return nil }, SchedulerConfig{})
	if s.cfg.LocalAdvertInterval != DefaultLocalAdvertInterval {
		t.Errorf("default local interval = %d, want %d", s.cfg.LocalAdvertInterval, DefaultLocalAdvertInterval)
	}
	if s.cfg.FloodAdvertInterval != DefaultFloodAdvertInterval {
		t.Errorf("default flood interval = %d, want %d", s.cfg.FloodAdvertInterval, DefaultFloodAdvertInterval)
	}
}

func TestScheduler_SendNow_Flood(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 12,
	})

	s.SendNow(true) // flood

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1", calls.Load())
	}
	if mt.sentCount() != 1 {
		t.Errorf("sent %d packets, want 1", mt.sentCount())
	}
	// Flood packets should have flood route type set by router.SendFlood
	pkt := mt.lastPacket()
	if pkt == nil {
		t.Fatal("no packet sent")
	}
	if !pkt.IsFlood() {
		t.Error("expected flood packet")
	}
}

func TestScheduler_SendNow_Local(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 12,
	})

	s.SendNow(false) // local / zero-hop

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1", calls.Load())
	}
	if mt.sentCount() != 1 {
		t.Errorf("sent %d packets, want 1", mt.sentCount())
	}
	pkt := mt.lastPacket()
	if pkt == nil {
		t.Fatal("no packet sent")
	}
	if !pkt.IsDirect() {
		t.Error("expected direct (zero-hop) packet")
	}
}

func TestScheduler_LocalAdvert_Fires(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1,   // 2 minutes
		FloodAdvertInterval: 255, // very far in the future
	})

	// Override nowFn to control time
	now := time.Now()
	s.nowFn = func() time.Time { return now }

	// Initialize timers
	s.resetTimers()

	// Advance time past the local interval (2 minutes)
	now = now.Add(3 * time.Minute)
	s.checkTimers()

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1", calls.Load())
	}
	if mt.sentCount() != 1 {
		t.Errorf("sent %d packets, want 1", mt.sentCount())
	}
	pkt := mt.lastPacket()
	if pkt == nil {
		t.Fatal("no packet sent")
	}
	if !pkt.IsDirect() {
		t.Error("local advert should be zero-hop (direct)")
	}
}

func TestScheduler_FloodAdvert_Fires(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1, // 2 minutes
		FloodAdvertInterval: 1, // 1 hour
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Advance past flood interval (1 hour)
	now = now.Add(2 * time.Hour)
	s.checkTimers()

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1", calls.Load())
	}
	pkt := mt.lastPacket()
	if pkt == nil {
		t.Fatal("no packet sent")
	}
	if !pkt.IsFlood() {
		t.Error("flood advert should be flood routed")
	}
}

func TestScheduler_FloodResetsLocal(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1, // 2 minutes
		FloodAdvertInterval: 1, // 1 hour
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Advance past both local and flood intervals
	now = now.Add(2 * time.Hour)
	s.checkTimers()

	// Only 1 call (flood wins, local is also due but flood resets local)
	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1 (flood only)", calls.Load())
	}

	// Now advance just past the local interval again (2 min from reset)
	now = now.Add(3 * time.Minute)
	s.checkTimers()

	// Should fire a local advert now
	if calls.Load() != 2 {
		t.Errorf("builder called %d times, want 2 (flood + local)", calls.Load())
	}
}

func TestScheduler_DisabledLocalInterval(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 0, // disabled
		FloodAdvertInterval: 1,
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Advance past what would be local interval
	now = now.Add(5 * time.Minute)
	s.checkTimers()

	// No local advert should have fired
	if calls.Load() != 0 {
		t.Errorf("builder called %d times, want 0 (local disabled)", calls.Load())
	}

	// Advance past flood interval
	now = now.Add(2 * time.Hour)
	s.checkTimers()

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1 (flood only)", calls.Load())
	}
}

func TestScheduler_DisabledFloodInterval(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 0, // disabled
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Advance past local interval
	now = now.Add(3 * time.Minute)
	s.checkTimers()

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1 (local only)", calls.Load())
	}

	// Advance much further — flood should never fire
	now = now.Add(24 * time.Hour)
	s.checkTimers()

	// Just another local
	if calls.Load() != 2 {
		t.Errorf("builder called %d times, want 2 (locals only)", calls.Load())
	}
}

func TestScheduler_UpdateIntervals(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)
	var calls atomic.Int32

	s := NewScheduler(r, makeTestBuilder(&calls), SchedulerConfig{
		LocalAdvertInterval: 1, // 2 minutes
		FloodAdvertInterval: 1, // 1 hour
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Update to shorter local interval (actual = 2 * 2 = 4 minutes)
	// and disable flood
	s.UpdateIntervals(2, 0)

	// Advance 5 minutes (past 4-minute local interval)
	now = now.Add(5 * time.Minute)
	s.checkTimers()

	if calls.Load() != 1 {
		t.Errorf("builder called %d times, want 1", calls.Load())
	}
}

func TestScheduler_Stop(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)

	s := NewScheduler(r, func() *codec.Packet { return nil }, SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 1,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)

	// Stop via context cancellation
	cancel()

	select {
	case <-done:
		// OK, stopped
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop within timeout")
	}
}

func TestScheduler_StopMethod(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)

	s := NewScheduler(r, func() *codec.Packet { return nil }, SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 1,
	})

	done := make(chan struct{})
	go func() {
		s.Start(context.Background())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	s.Stop()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not stop within timeout")
	}
}

func TestScheduler_NilBuilderHandled(t *testing.T) {
	mt := newMockTransport()
	r := makeTestRouter(t, mt)

	// Builder returns nil
	s := NewScheduler(r, func() *codec.Packet { return nil }, SchedulerConfig{
		LocalAdvertInterval: 1,
		FloodAdvertInterval: 1,
	})

	now := time.Now()
	s.nowFn = func() time.Time { return now }
	s.resetTimers()

	// Should not panic when builder returns nil
	now = now.Add(3 * time.Minute)
	s.checkTimers()

	// No packets sent
	if mt.sentCount() != 0 {
		t.Errorf("sent %d packets, want 0 (nil builder)", mt.sentCount())
	}
}
