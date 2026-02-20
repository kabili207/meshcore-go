package router

import "sync/atomic"

// RouterCounters tracks packet routing statistics using atomic counters.
// All fields are safe for concurrent access.
type RouterCounters struct {
	PacketsRecv atomic.Uint32 // Total packets received (after version check)
	PacketsSent atomic.Uint32 // Total packets sent to transports
	RecvFlood   atomic.Uint32 // Flood-routed packets received
	RecvDirect  atomic.Uint32 // Direct-routed packets received
	SentFlood   atomic.Uint32 // Flood-mode packets sent
	SentDirect  atomic.Uint32 // Direct-mode packets sent
	FloodDups   atomic.Uint32 // Duplicate flood packets detected
	DirectDups  atomic.Uint32 // Duplicate direct packets detected
}

// CountersSnapshot is a plain-value copy of RouterCounters for reading.
type CountersSnapshot struct {
	PacketsRecv uint32
	PacketsSent uint32
	RecvFlood   uint32
	RecvDirect  uint32
	SentFlood   uint32
	SentDirect  uint32
	FloodDups   uint32
	DirectDups  uint32
}

// Snapshot returns a consistent point-in-time copy of all counters.
func (c *RouterCounters) Snapshot() CountersSnapshot {
	return CountersSnapshot{
		PacketsRecv: c.PacketsRecv.Load(),
		PacketsSent: c.PacketsSent.Load(),
		RecvFlood:   c.RecvFlood.Load(),
		RecvDirect:  c.RecvDirect.Load(),
		SentFlood:   c.SentFlood.Load(),
		SentDirect:  c.SentDirect.Load(),
		FloodDups:   c.FloodDups.Load(),
		DirectDups:  c.DirectDups.Load(),
	}
}

// Reset zeroes all counters.
func (c *RouterCounters) Reset() {
	c.PacketsRecv.Store(0)
	c.PacketsSent.Store(0)
	c.RecvFlood.Store(0)
	c.RecvDirect.Store(0)
	c.SentFlood.Store(0)
	c.SentDirect.Store(0)
	c.FloodDups.Store(0)
	c.DirectDups.Store(0)
}
