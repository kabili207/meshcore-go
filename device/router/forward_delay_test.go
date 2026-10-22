package router

import (
	"context"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// Firmware's repeater waits a random 0..5t before relaying, where t is the
// packet's airtime times txdelay (floods) or direct.txdelay (direct packets),
// so neighbors relaying the same packet don't transmit over each other.

func TestRetransmitDelayWindow(t *testing.T) {
	r := New(Config{SelfID: selfID(0xAA)})
	pkt := &codec.Packet{
		Header:  (codec.PayloadTypeTxtMsg << codec.PHTypeShift) | codec.RouteTypeFlood,
		Path:    []byte{0x11, 0x22},
		Payload: make([]byte, 50),
	}
	airtimeMS := DefaultRadioParams.Airtime(2 + 50 + 2).Milliseconds()
	wantMax := 5 * int(float64(airtimeMS)*0.5)

	var gotN int
	r.randIntN = func(n int) int { gotN = n; return n - 1 }
	if got := r.retransmitDelay(pkt, 0.5); got != time.Duration(wantMax)*time.Millisecond {
		t.Errorf("max delay = %v, want %dms (5 x airtime x 0.5)", got, wantMax)
	}
	if gotN != wantMax+1 {
		t.Errorf("random draw over [0, %d), want [0, %d]", gotN, wantMax)
	}
	if got := r.retransmitDelay(pkt, 0); got != 0 {
		t.Errorf("factor 0 delay = %v, want 0", got)
	}
}

// startedRouter returns a running router that forwards, with a fixed random
// draw so delays are known exactly.
func startedRouter(t *testing.T, cfg Config, draw int) (*Router, *mockTransport) {
	t.Helper()
	cfg.SelfID = selfID(0xAA)
	cfg.ForwardPackets = true
	cfg.DrainInterval = time.Millisecond
	r := New(cfg)
	r.randIntN = func(n int) int { return min(draw, n-1) }
	mt := newMockTransport()
	r.AddTransport(mt, transport.PacketSourceMQTT)
	r.Start(context.Background())
	t.Cleanup(r.Stop)
	return r, mt
}

// waitSent waits until mt has sent n packets and returns how long that took.
func waitSent(t *testing.T, mt *mockTransport, start time.Time, n int) time.Duration {
	t.Helper()
	for mt.sentCount() < n {
		if time.Since(start) > 3*time.Second {
			t.Fatalf("only %d of %d packets sent", mt.sentCount(), n)
		}
		time.Sleep(time.Millisecond)
	}
	return time.Since(start)
}

func TestFloodForwardDelayed(t *testing.T) {
	r, mt := startedRouter(t, Config{TxDelayFactor: 0.5}, 80)

	start := time.Now()
	r.HandlePacket(makeFloodPacket(codec.PayloadTypeTxtMsg, []byte{0x01, 0x02}), transport.PacketSourceSerial)
	if mt.sentCount() != 0 {
		t.Fatal("flood relayed without a delay")
	}
	if got := waitSent(t, mt, start, 1); got < 80*time.Millisecond {
		t.Errorf("flood relayed after %v, want at least 80ms", got)
	}
}

func TestDirectForwardDelayed(t *testing.T) {
	r, mt := startedRouter(t, Config{DirectTxDelayFactor: 0.3}, 60)

	pkt := makeDirectPacket(codec.PayloadTypeTxtMsg, []byte{0xAA, 0xBB}, []byte{0x01, 0x02})
	start := time.Now()
	r.HandlePacket(pkt, transport.PacketSourceSerial)
	if mt.sentCount() != 0 {
		t.Fatal("direct packet relayed without a delay")
	}
	if got := waitSent(t, mt, start, 1); got < 60*time.Millisecond {
		t.Errorf("direct packet relayed after %v, want at least 60ms", got)
	}
}

// A forwarded direct ACK waits the direct delay, then sends the extra
// multipart copies 300ms apart, and the ACK itself last (Mesh.cpp
// routeDirectRecvAcks).
func TestAckForwardDelayAndExtraCopies(t *testing.T) {
	r, mt := startedRouter(t, Config{DirectTxDelayFactor: 0.3, ExtraAckTransmits: 1}, 40)

	ack := makeDirectPacket(codec.PayloadTypeAck, []byte{0xAA, 0xBB}, codec.BuildAckPayload(0x01020304))
	start := time.Now()
	r.HandlePacket(ack, transport.PacketSourceSerial)

	first := waitSent(t, mt, start, 1)
	second := waitSent(t, mt, start, 2)
	sent := mt.sentPackets()
	if sent[0].PayloadType() != codec.PayloadTypeMultipart || sent[1].PayloadType() != codec.PayloadTypeAck {
		t.Fatalf("sent types %d then %d, want the multipart copy then the ACK", sent[0].PayloadType(), sent[1].PayloadType())
	}
	if first < 40*time.Millisecond {
		t.Errorf("multipart copy sent after %v, want at least the 40ms direct delay", first)
	}
	if second < 340*time.Millisecond {
		t.Errorf("ACK sent after %v, want at least 40ms + 300ms", second)
	}
	for _, p := range sent {
		if !p.IsDirect() || p.HopCount() != 1 {
			t.Errorf("type %d sent with route %d hops %d, want direct with one hop left", p.PayloadType(), p.RouteType(), p.HopCount())
		}
	}
}

// A relayed multipart ACK waits an extra (remaining+1) x 300ms, leaving room for
// the copies still on their way (Mesh.cpp forwardMultipartDirect).
func TestMultipartAckForwardWaitsForRemaining(t *testing.T) {
	r, mt := startedRouter(t, Config{}, 0) // no direct delay, isolate the spacing

	mp := codec.BuildMultipartPayload(1, codec.PayloadTypeAck, codec.BuildAckPayload(0x0A0B0C0D))
	pkt := makeDirectPacket(codec.PayloadTypeMultipart, []byte{0xAA, 0xBB}, mp)
	start := time.Now()
	r.HandlePacket(pkt, transport.PacketSourceSerial)
	if got := waitSent(t, mt, start, 1); got < 600*time.Millisecond {
		t.Errorf("relayed multipart ACK sent after %v, want at least (1+1) x 300ms", got)
	}
}

func (m *mockTransport) sentPackets() []*codec.Packet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*codec.Packet(nil), m.sent...)
}
