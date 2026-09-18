package kiss

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
)

// blockingRadio holds each transmission until the test releases it, so a second
// packet can be offered while the first is still in flight.
type blockingRadio struct {
	entered chan []byte
	release chan struct{}
}

func newBlockingRadio() *blockingRadio {
	return &blockingRadio{
		entered: make(chan []byte, 4),
		release: make(chan struct{}),
	}
}

func (r *blockingRadio) Send(ctx context.Context, packet []byte) error {
	r.entered <- append([]byte(nil), packet...)
	select {
	case <-r.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// rawHost drives a modem with hand-built frames, standing in for a KISS client.
type rawHost struct {
	t      *testing.T
	conn   net.Conn
	reader *kisscodec.FrameReader
}

// startModem wires a rawHost to a modem serving over an in-memory connection.
func startModem(t *testing.T, cfg Config) (*Modem, *rawHost) {
	t.Helper()

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())

	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = m.Serve(ctx, serverConn)
	}()

	t.Cleanup(func() {
		cancel()
		clientConn.Close()
		serverConn.Close()
		<-served
	})

	return m, &rawHost{t: t, conn: clientConn, reader: kisscodec.NewFrameReader(clientConn)}
}

func (h *rawHost) send(typeByte byte, data []byte) {
	h.t.Helper()
	frame, err := kisscodec.EncodeFrame(typeByte, data)
	if err != nil {
		h.t.Fatalf("EncodeFrame: %v", err)
	}
	if _, err := h.conn.Write(frame); err != nil {
		h.t.Fatalf("write: %v", err)
	}
}

func (h *rawHost) sendHardware(subCmd uint8, data []byte) {
	h.t.Helper()
	h.send(kisscodec.CmdSetHardware, append([]byte{byte(subCmd)}, data...))
}

// expectHardware reads the next frame and asserts it is the given SetHardware
// response, returning its payload.
func (h *rawHost) expectHardware(subCmd uint8) []byte {
	h.t.Helper()
	h.conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	typeByte, data, err := h.reader.ReadFrame()
	if err != nil {
		h.t.Fatalf("ReadFrame: %v", err)
	}
	if typeByte != kisscodec.CmdSetHardware {
		h.t.Fatalf("frame type = %#x, want SetHardware", typeByte)
	}
	if len(data) == 0 {
		h.t.Fatal("SetHardware frame carried no sub-command")
	}
	if data[0] != byte(subCmd) {
		h.t.Fatalf("sub-command = %#x, want %#x", data[0], subCmd)
	}
	return data[1:]
}

// expectNothing asserts the modem stays silent for a short window.
func (h *rawHost) expectNothing(d time.Duration) {
	h.t.Helper()
	h.conn.SetReadDeadline(time.Now().Add(d))

	typeByte, data, err := h.reader.ReadFrame()
	if err == nil {
		h.t.Fatalf("expected silence, got frame %#x %x", typeByte, data)
	}
	h.conn.SetReadDeadline(time.Time{})
}

func immediateTxConfig(radio Radio) Config {
	return Config{Radio: radio}
}

func TestUnknownSubCommandReturnsError(t *testing.T) {
	_, host := startModem(t, immediateTxConfig(RadioFunc(func(context.Context, []byte) error { return nil })))

	host.sendHardware(0x7E, nil)

	data := host.expectHardware(kisscodec.HWRespError)
	if len(data) != 1 || data[0] != kisscodec.HWErrUnknownCmd {
		t.Errorf("error payload = %x, want unknown command", data)
	}
}

func TestShortRequestReturnsInvalidLength(t *testing.T) {
	_, host := startModem(t, immediateTxConfig(RadioFunc(func(context.Context, []byte) error { return nil })))

	// GetRandom needs a length byte.
	host.sendHardware(kisscodec.HWCmdGetRandom, nil)

	data := host.expectHardware(kisscodec.HWRespError)
	if len(data) != 1 || data[0] != kisscodec.HWErrInvalidLength {
		t.Errorf("error payload = %x, want invalid length", data)
	}
}

func TestGetRandomRejectsOutOfRangeLength(t *testing.T) {
	_, host := startModem(t, immediateTxConfig(RadioFunc(func(context.Context, []byte) error { return nil })))

	host.sendHardware(kisscodec.HWCmdGetRandom, []byte{65})

	data := host.expectHardware(kisscodec.HWRespError)
	if len(data) != 1 || data[0] != kisscodec.HWErrInvalidParam {
		t.Errorf("error payload = %x, want invalid parameter", data)
	}
}

func TestSecondDataFrameWhileTransmittingIsRefused(t *testing.T) {
	radio := newBlockingRadio()
	_, host := startModem(t, immediateTxConfig(radio))

	// Transmit without keyup delay or backoff so the radio is reached at once.
	host.send(kisscodec.CmdTxDelay, []byte{0})
	host.send(kisscodec.CmdPersistence, []byte{255})

	host.send(kisscodec.CmdData, []byte{0x01, 0x02})

	select {
	case got := <-radio.entered:
		if !bytes.Equal(got, []byte{0x01, 0x02}) {
			t.Fatalf("radio got %x", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("radio never saw the first packet")
	}

	host.send(kisscodec.CmdData, []byte{0x03})

	data := host.expectHardware(kisscodec.HWRespError)
	if len(data) != 1 || data[0] != kisscodec.HWErrTxBusy {
		t.Errorf("error payload = %x, want TxBusy", data)
	}

	close(radio.release)

	result := host.expectHardware(kisscodec.HWRespTxDone)
	if len(result) != 1 || result[0] != 0x01 {
		t.Errorf("TxDone payload = %x, want success", result)
	}
}

func TestOversizeDataFrameIsDroppedSilently(t *testing.T) {
	radio := newBlockingRadio()
	_, host := startModem(t, immediateTxConfig(radio))

	host.send(kisscodec.CmdTxDelay, []byte{0})
	host.send(kisscodec.CmdPersistence, []byte{255})

	// One byte past the MeshCore transmission unit. Firmware neither transmits
	// it nor complains.
	host.send(kisscodec.CmdData, make([]byte, kisscodec.MaxPacketSize+1))

	host.expectNothing(200 * time.Millisecond)

	select {
	case got := <-radio.entered:
		t.Fatalf("radio transmitted an over-MTU packet of %d bytes", len(got))
	default:
	}
}

func TestFramesOnOtherPortsAndReturnAreIgnored(t *testing.T) {
	_, host := startModem(t, immediateTxConfig(RadioFunc(func(context.Context, []byte) error { return nil })))

	// Port 1 is not this TNC's, and Return only means "leave KISS mode".
	host.send(kisscodec.TypeByte(1, kisscodec.CmdSetHardware), []byte{kisscodec.HWCmdPing})
	host.send(kisscodec.CmdReturn, nil)
	host.expectNothing(200 * time.Millisecond)

	// The connection must still be live.
	host.sendHardware(kisscodec.HWCmdPing, nil)
	host.expectHardware(kisscodec.HWRespPong)
}

func TestCarrierSenseDefersTransmission(t *testing.T) {
	radio := newBlockingRadio()
	close(radio.release) // never block inside Send

	busy := make(chan struct{})
	cfg := immediateTxConfig(radio)
	cfg.IsChannelBusy = func() bool {
		select {
		case <-busy:
			return false
		default:
			return true
		}
	}
	cfg.EstimateAirtime = func(n int) time.Duration { return time.Duration(n) * time.Millisecond }

	_, host := startModem(t, cfg)

	host.send(kisscodec.CmdTxDelay, []byte{0})
	host.send(kisscodec.CmdPersistence, []byte{255})
	host.send(kisscodec.CmdSlotTime, []byte{1}) // 10ms slots keep the test quick
	host.send(kisscodec.CmdData, []byte{0xEE})

	select {
	case <-radio.entered:
		t.Fatal("transmitted while the channel was busy")
	case <-time.After(100 * time.Millisecond):
	}

	close(busy)

	select {
	case got := <-radio.entered:
		if !bytes.Equal(got, []byte{0xEE}) {
			t.Errorf("radio got %x, want ee", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("never transmitted after the channel cleared")
	}
}

func TestReceiveDropsPacketsOutsideMTU(t *testing.T) {
	m, host := startModem(t, immediateTxConfig(RadioFunc(func(context.Context, []byte) error { return nil })))

	m.Receive(nil, kisscodec.RxMeta{})
	m.Receive(make([]byte, kisscodec.MaxPacketSize+1), kisscodec.RxMeta{})

	host.expectNothing(200 * time.Millisecond)
}

func TestNewRequiresRadio(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected an error when Config.Radio is missing")
	}
}

// bufferedStream models a socket: writes complete immediately into a buffer
// rather than waiting for a reader. net.Pipe cannot show shutdown races because
// its synchronous Write forces the writer to commit before anything else runs.
type bufferedStream struct {
	mu     sync.Mutex
	out    bytes.Buffer
	in     chan []byte
	rest   []byte
	closed chan struct{}
	once   sync.Once
}

func newBufferedStream() *bufferedStream {
	return &bufferedStream{in: make(chan []byte, 8), closed: make(chan struct{})}
}

func (s *bufferedStream) Read(p []byte) (int, error) {
	for len(s.rest) == 0 {
		select {
		case chunk := <-s.in:
			s.rest = chunk
		case <-s.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, s.rest)
	s.rest = s.rest[n:]
	return n, nil
}

func (s *bufferedStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.Write(p)
}

func (s *bufferedStream) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

func (s *bufferedStream) written() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.out.Bytes()...)
}

func TestRebootAcknowledgementSurvivesTheShutdown(t *testing.T) {
	// The reboot hook cancels the connection immediately afterward, so the
	// acknowledgement races the shutdown. The host must still see it, which is
	// why the firmware flushes its serial port before rebooting. Repeat enough
	// times to catch a select that picks at random.
	const rounds = 50

	for i := range rounds {
		stream := newBufferedStream()
		rebooted := make(chan struct{})

		m, err := New(Config{
			Radio:    RadioFunc(func(context.Context, []byte) error { return nil }),
			Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
			OnReboot: func() { close(rebooted) },
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		served := make(chan struct{})
		go func() {
			defer close(served)
			_ = m.Serve(context.Background(), stream)
		}()

		frame, err := kisscodec.EncodeHardwareFrame(kisscodec.HWCmdReboot, nil)
		if err != nil {
			t.Fatalf("EncodeHardwareFrame: %v", err)
		}
		stream.in <- frame

		select {
		case <-rebooted:
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: reboot hook never ran", i)
		}
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Fatalf("round %d: Serve did not return", i)
		}

		want, err := kisscodec.EncodeHardwareFrame(kisscodec.HWRespOK, nil)
		if err != nil {
			t.Fatalf("EncodeHardwareFrame: %v", err)
		}
		if got := stream.written(); !bytes.Contains(got, want) {
			t.Fatalf("round %d: reboot acknowledgement was lost, host saw %x", i, got)
		}
		stream.Close()
	}
}
