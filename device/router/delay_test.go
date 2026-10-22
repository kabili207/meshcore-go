package router

import (
	"context"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

func TestDelayedSends(t *testing.T) {
	const delay = 50 * time.Millisecond
	for _, tc := range []struct {
		name string
		send func(r *Router, pkt *codec.Packet)
	}{
		{"direct", func(r *Router, pkt *codec.Packet) { r.SendDirectDelayed(pkt, []byte{0x11}, delay) }},
		{"scoped flood", func(r *Router, pkt *codec.Packet) { r.SendFloodScopedDelayed(pkt, delay) }},
		{"flood", func(r *Router, pkt *codec.Packet) { r.SendFloodWithKeyDelayed(pkt, [16]byte{}, delay) }},
		{"flood path", func(r *Router, pkt *codec.Packet) { r.SendFloodPathWithKeyDelayed(pkt, [16]byte{}, delay) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMockTransport()
			r := New(Config{SelfID: selfID(0xAA), DrainInterval: time.Millisecond})
			r.AddTransport(mt, transport.PacketSourceMQTT)
			r.Start(context.Background())
			defer r.Stop()

			start := time.Now()
			tc.send(r, makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01}))
			if mt.sentCount() != 0 {
				t.Fatal("packet sent before its delay")
			}
			for mt.sentCount() == 0 {
				if time.Since(start) > 2*time.Second {
					t.Fatal("delayed packet was never sent")
				}
				time.Sleep(time.Millisecond)
			}
			if elapsed := time.Since(start); elapsed < delay {
				t.Errorf("sent after %v, want at least %v", elapsed, delay)
			}
		})
	}
}
