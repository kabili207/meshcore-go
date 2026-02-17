package serial

import (
	"sync"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// makeTestPacket creates a simple MeshCore packet for testing.
func makeTestPacket() *codec.Packet {
	return &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 0,
		Payload: []byte{0x01, 0x02, 0x03, 0x04},
	}
}

// framePacket wraps a packet in an RS232 frame.
func framePacket(t *testing.T, pkt *codec.Packet) []byte {
	t.Helper()
	data := pkt.WriteTo()
	frame, err := codec.EncodeRS232Frame(data)
	if err != nil {
		t.Fatalf("failed to encode RS232 frame: %v", err)
	}
	return frame
}

func TestProcessFrames_SingleFrame(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	var received []*codec.Packet
	var mu sync.Mutex

	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, source transport.PacketSource) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, p)
		if source != transport.PacketSourceSerial {
			t.Errorf("expected PacketSourceSerial, got %v", source)
		}
	}

	remaining := tr.processFrames(frame)
	if len(remaining) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(remaining))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(received))
	}

	if received[0].PayloadType() != pkt.PayloadType() {
		t.Errorf("payload type mismatch: got %d, want %d", received[0].PayloadType(), pkt.PayloadType())
	}
}

func TestProcessFrames_MultipleFrames(t *testing.T) {
	pkt1 := makeTestPacket()
	pkt2 := &codec.Packet{
		Header:  (codec.PayloadTypeAck << codec.PHTypeShift) | codec.RouteTypeFlood,
		PathLen: 0,
		Payload: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}

	frame1 := framePacket(t, pkt1)
	frame2 := framePacket(t, pkt2)
	combined := append(frame1, frame2...)

	var received []*codec.Packet
	var mu sync.Mutex

	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, p)
	}

	remaining := tr.processFrames(combined)
	if len(remaining) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(remaining))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(received))
	}

	if received[0].PayloadType() != pkt1.PayloadType() {
		t.Errorf("first packet type mismatch: got %d, want %d", received[0].PayloadType(), pkt1.PayloadType())
	}
	if received[1].PayloadType() != pkt2.PayloadType() {
		t.Errorf("second packet type mismatch: got %d, want %d", received[1].PayloadType(), pkt2.PayloadType())
	}
}

func TestProcessFrames_IncompleteFrame(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	// Truncate the frame to simulate incomplete data
	partial := frame[:len(frame)-2]

	var received []*codec.Packet

	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		received = append(received, p)
	}

	remaining := tr.processFrames(partial)
	if len(received) != 0 {
		t.Errorf("expected 0 packets from incomplete frame, got %d", len(received))
	}
	if len(remaining) != len(partial) {
		t.Errorf("expected all bytes returned as remaining, got %d vs %d", len(remaining), len(partial))
	}
}

func TestProcessFrames_IncrementalAssembly(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	var received []*codec.Packet

	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		received = append(received, p)
	}

	// Feed bytes one at a time, simulating slow serial arrival
	var buf []byte
	for _, b := range frame {
		buf = append(buf, b)
		buf = tr.processFrames(buf)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 packet after incremental assembly, got %d", len(received))
	}
	if len(buf) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(buf))
	}
}

func TestProcessFrames_GarbageBeforeFrame(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	// Prepend garbage bytes that don't start with magic
	garbage := []byte{0x00, 0x01, 0x02, 0xFF}
	data := append(garbage, frame...)

	var received []*codec.Packet

	tr := &Transport{}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		received = append(received, p)
	}

	remaining := tr.processFrames(data)

	if len(received) != 1 {
		t.Fatalf("expected 1 packet after skipping garbage, got %d", len(received))
	}
	if len(remaining) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(remaining))
	}
}

func TestProcessFrames_NoHandler(t *testing.T) {
	pkt := makeTestPacket()
	frame := framePacket(t, pkt)

	tr := &Transport{}
	// No handler set — should not panic

	remaining := tr.processFrames(frame)
	if len(remaining) != 0 {
		t.Errorf("expected no remaining bytes, got %d", len(remaining))
	}
}

func TestFindMagic(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{
			name: "magic at start",
			data: []byte{0xC0, 0x3E, 0x05},
			want: 0,
		},
		{
			name: "magic in middle",
			data: []byte{0x00, 0x01, 0xC0, 0x3E, 0x05},
			want: 2,
		},
		{
			name: "no magic",
			data: []byte{0x00, 0x01, 0x02, 0x03},
			want: -1,
		},
		{
			name: "partial magic at end",
			data: []byte{0x00, 0xC0},
			want: -1,
		},
		{
			name: "empty",
			data: []byte{},
			want: -1,
		},
		{
			name: "just magic",
			data: []byte{0xC0, 0x3E},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findMagic(tt.data)
			if got != tt.want {
				t.Errorf("findMagic() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSendPacket_NotConnected(t *testing.T) {
	tr := New(Config{Port: "/dev/null", BaudRate: 115200})

	pkt := makeTestPacket()
	err := tr.SendPacket(pkt)
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestNew_Defaults(t *testing.T) {
	tr := New(Config{Port: "/dev/ttyUSB0"})
	if tr.cfg.BaudRate != DefaultBaudRate {
		t.Errorf("expected default baud rate %d, got %d", DefaultBaudRate, tr.cfg.BaudRate)
	}
	if tr.log == nil {
		t.Error("expected logger to be set")
	}
}
