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
		{"zero hop", func(r *Router, pkt *codec.Packet) { r.SendZeroHopDelayed(pkt, delay) }},
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

// A stored path keeps its own hash size, whatever the router's PathHashMode.
// Firmware's sendDirect copies the encoded path_len the same way.
func TestSendDirectPath_KeepsPathEncoding(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hashSize uint8
		path     []byte
	}{
		{"2-byte hashes on a 1-byte router", 2, []byte{0xA1, 0xA2, 0xB1, 0xB2}},
		{"3-byte hashes on a 1-byte router", 3, []byte{1, 2, 3, 4, 5, 6}},
		{"zero hops", 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mt := newMockTransport()
			r := New(Config{SelfID: selfID(0xAA)}) // PathHashMode 0: 1-byte hashes
			r.AddTransport(mt, transport.PacketSourceMQTT)

			hops := uint8(len(tc.path)) / tc.hashSize
			pathLen := codec.PathInfo{HashSize: tc.hashSize, HopCount: hops}.ToWireByte()
			pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
			r.SendDirectPath(pkt, pathLen, tc.path, 0)

			if !pkt.IsDirect() || pkt.PathLen != pathLen || pkt.PathHashSize != tc.hashSize || pkt.HopCount() != int(hops) {
				t.Errorf("sent PathLen=%#x hashSize=%d hops=%d, want %#x/%d/%d",
					pkt.PathLen, pkt.PathHashSize, pkt.HopCount(), pathLen, tc.hashSize, hops)
			}
			if mt.sentCount() != 1 {
				t.Errorf("sent %d packets, want 1", mt.sentCount())
			}
		})
	}
}

// A path whose bytes don't match its encoded length is corrupt state. It's
// still sent, using the router's own hash size, rather than dropped.
func TestSendDirectPath_MismatchFallsBack(t *testing.T) {
	mt := newMockTransport()
	r := New(Config{SelfID: selfID(0xAA)})
	r.AddTransport(mt, transport.PacketSourceMQTT)

	pathLen := codec.PathInfo{HashSize: 2, HopCount: 3}.ToWireByte() // claims 6 bytes
	pkt := makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01})
	r.SendDirectPath(pkt, pathLen, []byte{1, 2}, 0)

	if mt.sentCount() != 1 || pkt.PathHashSize != 1 || pkt.HopCount() != 2 {
		t.Errorf("sent=%d hashSize=%d hops=%d, want the 1-byte fallback", mt.sentCount(), pkt.PathHashSize, pkt.HopCount())
	}
}
