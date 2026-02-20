package connection

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core"
)

func makeTestID(b byte) core.MeshCoreID {
	var id core.MeshCoreID
	id[0] = b
	return id
}

func TestManager_NewManager_Defaults(t *testing.T) {
	m := NewManager(ManagerConfig{})

	if m.cfg.KeepAliveInterval != DefaultKeepAliveInterval {
		t.Errorf("default KeepAliveInterval = %v, want %v", m.cfg.KeepAliveInterval, DefaultKeepAliveInterval)
	}
	if m.cfg.TimeoutMultiplier != DefaultTimeoutMultiplier {
		t.Errorf("default TimeoutMultiplier = %v, want %v", m.cfg.TimeoutMultiplier, DefaultTimeoutMultiplier)
	}
	if m.ConnectedCount() != 0 {
		t.Errorf("new manager should have 0 peers, got %d", m.ConnectedCount())
	}
}

func TestManager_Register_And_IsConnected(t *testing.T) {
	m := NewManager(ManagerConfig{})
	id := makeTestID(0x01)

	m.Register(id)

	if !m.IsConnected(id) {
		t.Error("registered peer should be connected")
	}
	if m.ConnectedCount() != 1 {
		t.Errorf("ConnectedCount = %d, want 1", m.ConnectedCount())
	}
}

func TestManager_IsConnected_Unknown(t *testing.T) {
	m := NewManager(ManagerConfig{})
	id := makeTestID(0xFF)

	if m.IsConnected(id) {
		t.Error("unknown peer should not be connected")
	}
}

func TestManager_Register_Updates_LastSeen(t *testing.T) {
	m := NewManager(ManagerConfig{})
	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id := makeTestID(0x01)
	m.Register(id)

	// Re-register with later time
	now = now.Add(5 * time.Second)
	m.Register(id)

	if m.ConnectedCount() != 1 {
		t.Errorf("re-register should not duplicate, ConnectedCount = %d", m.ConnectedCount())
	}
}

func TestManager_Touch(t *testing.T) {
	m := NewManager(ManagerConfig{
		KeepAliveInterval: 10 * time.Second,
		TimeoutMultiplier: 2.0,
	})

	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id := makeTestID(0x01)
	m.Register(id)

	// Advance close to timeout (20 seconds)
	now = now.Add(15 * time.Second)
	m.Touch(id) // refresh

	// Advance another 15 seconds (total 30 from register, 15 from touch)
	now = now.Add(15 * time.Second)
	m.CheckTimeouts()

	// Should still be connected (15s since touch < 20s timeout)
	if !m.IsConnected(id) {
		t.Error("touched peer should still be connected")
	}
}

func TestManager_Touch_Unknown(t *testing.T) {
	m := NewManager(ManagerConfig{})
	// Should not panic
	m.Touch(makeTestID(0xFF))
}

func TestManager_Remove(t *testing.T) {
	m := NewManager(ManagerConfig{})
	id := makeTestID(0x01)

	m.Register(id)
	m.Remove(id)

	if m.IsConnected(id) {
		t.Error("removed peer should not be connected")
	}
	if m.ConnectedCount() != 0 {
		t.Errorf("ConnectedCount = %d, want 0", m.ConnectedCount())
	}
}

func TestManager_Remove_NoCallback(t *testing.T) {
	m := NewManager(ManagerConfig{})

	var called atomic.Bool
	m.SetOnDisconnect(func(_ core.MeshCoreID) { called.Store(true) })

	id := makeTestID(0x01)
	m.Register(id)
	m.Remove(id)

	if called.Load() {
		t.Error("Remove should not fire OnDisconnect")
	}
}

func TestManager_CheckTimeouts_Disconnects(t *testing.T) {
	m := NewManager(ManagerConfig{
		KeepAliveInterval: 10 * time.Second,
		TimeoutMultiplier: 2.0, // timeout = 20 seconds
	})

	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id := makeTestID(0x01)
	m.Register(id)

	var disconnectedID core.MeshCoreID
	var disconnected atomic.Bool
	m.SetOnDisconnect(func(id core.MeshCoreID) {
		disconnectedID = id
		disconnected.Store(true)
	})

	// Advance past timeout
	now = now.Add(25 * time.Second)
	m.CheckTimeouts()

	if !disconnected.Load() {
		t.Error("OnDisconnect should have been called")
	}
	if disconnectedID != id {
		t.Error("OnDisconnect should receive the correct ID")
	}
	if m.IsConnected(id) {
		t.Error("timed-out peer should be removed")
	}
}

func TestManager_CheckTimeouts_NoFalsePositive(t *testing.T) {
	m := NewManager(ManagerConfig{
		KeepAliveInterval: 10 * time.Second,
		TimeoutMultiplier: 2.0, // timeout = 20 seconds
	})

	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id := makeTestID(0x01)
	m.Register(id)

	// Advance but not past timeout
	now = now.Add(15 * time.Second)
	m.CheckTimeouts()

	if !m.IsConnected(id) {
		t.Error("peer should still be connected before timeout")
	}
}

func TestManager_CheckTimeouts_Multiple(t *testing.T) {
	m := NewManager(ManagerConfig{
		KeepAliveInterval: 10 * time.Second,
		TimeoutMultiplier: 2.0,
	})

	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id1 := makeTestID(0x01)
	id2 := makeTestID(0x02)
	id3 := makeTestID(0x03)

	m.Register(id1) // registered at t=0
	now = now.Add(10 * time.Second)
	m.Register(id2) // registered at t=10
	now = now.Add(5 * time.Second)
	m.Register(id3) // registered at t=15

	var disconnectCount atomic.Int32
	m.SetOnDisconnect(func(_ core.MeshCoreID) { disconnectCount.Add(1) })

	// At t=25: id1 has been idle for 25s (> 20s timeout), others are fine
	now = now.Add(10 * time.Second)
	m.CheckTimeouts()

	if disconnectCount.Load() != 1 {
		t.Errorf("disconnected %d peers, want 1", disconnectCount.Load())
	}
	if m.IsConnected(id1) {
		t.Error("id1 should be disconnected")
	}
	if !m.IsConnected(id2) {
		t.Error("id2 should still be connected")
	}
	if !m.IsConnected(id3) {
		t.Error("id3 should still be connected")
	}
}

func TestManager_CheckTimeouts_NilCallback(t *testing.T) {
	m := NewManager(ManagerConfig{
		KeepAliveInterval: 10 * time.Second,
		TimeoutMultiplier: 2.0,
	})

	now := time.Now()
	m.nowFn = func() time.Time { return now }

	id := makeTestID(0x01)
	m.Register(id)

	// No callback set — should not panic
	now = now.Add(25 * time.Second)
	m.CheckTimeouts()

	if m.IsConnected(id) {
		t.Error("timed-out peer should still be removed even without callback")
	}
}

func TestManager_Stop(t *testing.T) {
	m := NewManager(ManagerConfig{})

	done := make(chan struct{})
	go func() {
		m.Start(context.Background())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	m.Stop()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not stop within timeout")
	}
}

func TestManager_Stop_Context(t *testing.T) {
	m := NewManager(ManagerConfig{})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		m.Start(ctx)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("manager did not stop within timeout")
	}
}
