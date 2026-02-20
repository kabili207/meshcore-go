package router

import (
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// QueueEntry is returned by Pop and contains the packet along with routing
// metadata indicating which transports should receive it.
type QueueEntry struct {
	Packet        *codec.Packet
	ExcludeSource transport.PacketSource
	SendToAll     bool // if true, send to all transports (ignore ExcludeSource)
}

// SendQueue is a priority-ordered outbound packet queue.
// Lower priority numbers are dequeued first. Items with a future readyAt
// time are held until that time has passed.
type SendQueue struct {
	mu    sync.Mutex
	items []queueItem
}

type queueItem struct {
	pkt           *codec.Packet
	priority      uint8
	readyAt       time.Time
	excludeSource transport.PacketSource
	sendToAll     bool
}

// NewSendQueue creates an empty send queue.
func NewSendQueue() *SendQueue {
	return &SendQueue{}
}

// Push adds a packet to the queue with the given priority, delay, and routing
// metadata. Priority 0 is highest. The packet will not be returned by Pop
// until the delay has elapsed.
func (q *SendQueue) Push(pkt *codec.Packet, priority uint8, delay time.Duration, excludeSource transport.PacketSource, sendToAll bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, queueItem{
		pkt:           pkt,
		priority:      priority,
		readyAt:       time.Now().Add(delay),
		excludeSource: excludeSource,
		sendToAll:     sendToAll,
	})
}

// Pop returns the highest-priority ready entry, or nil if none are ready.
// Among items with equal priority, the earliest-inserted item is returned.
func (q *SendQueue) Pop() *QueueEntry {
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	bestIdx := -1
	var bestPri uint8 = 255

	for i, item := range q.items {
		if now.Before(item.readyAt) {
			continue
		}
		if bestIdx == -1 || item.priority < bestPri {
			bestIdx = i
			bestPri = item.priority
		}
	}

	if bestIdx == -1 {
		return nil
	}

	entry := &QueueEntry{
		Packet:        q.items[bestIdx].pkt,
		ExcludeSource: q.items[bestIdx].excludeSource,
		SendToAll:     q.items[bestIdx].sendToAll,
	}
	q.items = append(q.items[:bestIdx], q.items[bestIdx+1:]...)
	return entry
}

// Len returns the total number of items in the queue (ready or not).
func (q *SendQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
