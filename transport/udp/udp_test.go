package udp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
	"golang.org/x/net/ipv4"
)

// makeTestPacket creates a simple MeshCore packet for testing.
func makeTestPacket() *codec.Packet {
	return &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 0,
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}
}

// framePacket wraps a packet in an RS232 frame (one frame per datagram).
func framePacket(t *testing.T, pkt *codec.Packet) []byte {
	t.Helper()
	frame, err := codec.EncodeRS232Frame(pkt.WriteTo())
	if err != nil {
		t.Fatalf("failed to encode RS232 frame: %v", err)
	}
	return frame
}

func TestProcessDatagram_SingleFrame(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	var received []*codec.Packet
	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, source transport.PacketSource) {
		received = append(received, p)
		if source != transport.PacketSourceUDP {
			t.Errorf("expected PacketSourceUDP, got %v", source)
		}
	}

	tr.processDatagram(frame)

	if len(received) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(received))
	}
	if received[0].PayloadType() != pkt.PayloadType() {
		t.Errorf("payload type mismatch: got %d, want %d", received[0].PayloadType(), pkt.PayloadType())
	}
}

func TestProcessDatagram_MultipleFrames(t *testing.T) {
	pkt1 := makeTestPacket()
	pkt2 := &codec.Packet{
		Header:  (codec.PayloadTypeAck << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 0,
		Payload: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}
	combined := append(framePacket(t, pkt1), framePacket(t, pkt2)...)

	var received []*codec.Packet
	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		received = append(received, p)
	}

	tr.processDatagram(combined)

	if len(received) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(received))
	}
}

func TestProcessDatagram_Malformed(t *testing.T) {
	// A datagram whose leading bytes are not a valid frame is dropped whole.
	var received []*codec.Packet
	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		received = append(received, p)
	}

	tr.processDatagram([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})

	if len(received) != 0 {
		t.Fatalf("expected 0 packets from malformed datagram, got %d", len(received))
	}
}

func TestProcessDatagram_NoHandler(t *testing.T) {
	tr := &Transport{}
	// No handler set — must not panic.
	tr.processDatagram(framePacket(t, makeTestPacket()))
}

func TestNew_Defaults(t *testing.T) {
	tr := New(Config{})
	if tr.cfg.GroupAddress != DefaultGroupAddress {
		t.Errorf("expected default group %q, got %q", DefaultGroupAddress, tr.cfg.GroupAddress)
	}
	if tr.cfg.Port != DefaultPort {
		t.Errorf("expected default port %d, got %d", DefaultPort, tr.cfg.Port)
	}
	if tr.log == nil {
		t.Error("expected logger to be set")
	}
}

func TestSendPacket_NotConnected(t *testing.T) {
	tr := New(Config{})
	if err := tr.SendPacket(makeTestPacket()); err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestStart_InvalidGroup(t *testing.T) {
	tr := New(Config{GroupAddress: "10.0.0.1"}) // not a multicast address
	if err := tr.Start(context.Background()); err == nil {
		t.Fatal("expected error for non-multicast group address")
	}
}

// multicastIface returns a non-loopback, multicast-capable, up interface, or
// skips the test if the environment has none (common in sandboxes/CI).
func multicastIface(t *testing.T) *net.Interface {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate interfaces: %v", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if addrs, _ := ifi.Addrs(); len(addrs) > 0 {
			return &ifi
		}
	}
	t.Skip("no multicast-capable interface available")
	return nil
}

// TestMulticastRoundTrip exercises the full socket path: a running Transport
// joins the group and must decode a framed datagram sent by a separate
// loopback-enabled sender on the same host. Best-effort: it skips (rather than
// fails) when the environment doesn't actually deliver the multicast, since the
// pure decode/dispatch logic is covered by the tests above.
func TestMulticastRoundTrip(t *testing.T) {
	ifi := multicastIface(t)

	const port = 44022
	tr := New(Config{Port: port, Interface: ifi.Name})

	got := make(chan *codec.Packet, 1)
	var once sync.Once
	tr.SetPacketHandler(func(p *codec.Packet, source transport.PacketSource) {
		if source != transport.PacketSourceUDP {
			t.Errorf("expected PacketSourceUDP, got %v", source)
		}
		once.Do(func() { got <- p })
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tr.Start(ctx); err != nil {
		t.Skipf("could not start UDP transport in this environment: %v", err)
	}
	defer tr.Stop()

	// Separate sender with loopback enabled so the same-host receiver can hear it.
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Skipf("could not open sender socket: %v", err)
	}
	defer pc.Close()
	sender := ipv4.NewPacketConn(pc)
	if err := sender.SetMulticastInterface(ifi); err != nil {
		t.Skipf("could not set sender multicast interface: %v", err)
	}
	_ = sender.SetMulticastLoopback(true)

	dst := &net.UDPAddr{IP: net.ParseIP(DefaultGroupAddress), Port: port}
	pkt := makeTestPacket()
	if _, err := sender.WriteTo(framePacket(t, pkt), nil, dst); err != nil {
		t.Skipf("could not send multicast datagram: %v", err)
	}

	select {
	case p := <-got:
		if p.PayloadType() != pkt.PayloadType() {
			t.Errorf("payload type mismatch: got %d, want %d", p.PayloadType(), pkt.PayloadType())
		}
	case <-time.After(2 * time.Second):
		t.Skip("multicast datagram not delivered in this environment")
	}
}
