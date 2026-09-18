package kiss

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/transport"
)

// makeTestPacket creates a simple MeshCore packet for testing.
func makeTestPacket(payload ...byte) *codec.Packet {
	return &codec.Packet{
		Header:  (codec.PayloadTypeAdvert << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: payload,
	}
}

// collector records dispatched packets for assertions.
type collector struct {
	mu      sync.Mutex
	packets []*codec.Packet
	sources []transport.PacketSource
	notify  chan struct{}
}

func newCollector() *collector {
	return &collector{notify: make(chan struct{}, 8)}
}

func (c *collector) handle(p *codec.Packet, source transport.PacketSource) {
	c.mu.Lock()
	c.packets = append(c.packets, p)
	c.sources = append(c.sources, source)
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *collector) all() []*codec.Packet {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*codec.Packet(nil), c.packets...)
}

// waitFor blocks until at least n packets have been dispatched.
func (c *collector) waitFor(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		c.mu.Lock()
		got := len(c.packets)
		c.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-c.notify:
		case <-deadline:
			t.Fatalf("only %d of %d packets dispatched", got, n)
		}
	}
}

func TestLoggerNilSafe(t *testing.T) {
	// A zero-value Transport has no logger. The receive path must not assume
	// New built it.
	tr := &Transport{}
	tr.handleDataFrame([]byte{0x00}) // too short to parse; exercises the log call
	tr.handleHardwareFrame(kisscodec.HWRespRxMeta, nil)
	tr.handleHardwareFrame(kisscodec.HWRespError, []byte{kisscodec.HWErrTxBusy})
}

func TestSendPacketNotConnected(t *testing.T) {
	tr := New(Config{Port: "/dev/null"})
	if err := tr.SendPacket(makeTestPacket(1, 2, 3)); !errors.Is(err, ErrNotConnected) {
		t.Errorf("SendPacket error = %v, want ErrNotConnected", err)
	}
}

func TestHandleDataFrameDispatchesImmediatelyWhenHoldDisabled(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: -1}}
	tr.packetHandler = c.handle

	pkt := makeTestPacket(0xAA)
	tr.handleDataFrame(pkt.WriteTo())

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("dispatched %d packets, want 1", len(got))
	}
	if !bytes.Equal(got[0].Payload, []byte{0xAA}) {
		t.Errorf("payload = %x, want aa", got[0].Payload)
	}
	if c.sources[0] != transport.PacketSourceKISS {
		t.Errorf("source = %v, want kiss", c.sources[0])
	}
}

func TestSignalReportAttachesToHeldPacket(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: time.Minute}}
	tr.packetHandler = c.handle

	tr.handleDataFrame(makeTestPacket(0xBB).WriteTo())

	// Still held, waiting on its signal report.
	if got := c.all(); len(got) != 0 {
		t.Fatalf("packet dispatched before its signal report: %d", len(got))
	}

	meta := kisscodec.RxMeta{SNRQuarterDB: -30, RSSI: -101}
	tr.handleHardwareFrame(kisscodec.HWRespRxMeta, meta.Encode())

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("dispatched %d packets, want 1", len(got))
	}
	if got[0].SNR != meta.SNRQuarterDB {
		t.Errorf("SNR = %d, want %d", got[0].SNR, meta.SNRQuarterDB)
	}
}

func TestHeldPacketIsReleasedByTheHoldTimer(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: 20 * time.Millisecond}}
	tr.packetHandler = c.handle

	tr.handleDataFrame(makeTestPacket(0xCC).WriteTo())
	c.waitFor(t, 1)

	if got := c.all()[0]; got.SNR != 0 {
		t.Errorf("SNR = %d, want 0 when no report arrives", got.SNR)
	}
}

func TestSecondPacketReleasesTheFirst(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: time.Minute}}
	tr.packetHandler = c.handle

	tr.handleDataFrame(makeTestPacket(0x01).WriteTo())
	tr.handleDataFrame(makeTestPacket(0x02).WriteTo())

	got := c.all()
	if len(got) != 1 {
		t.Fatalf("dispatched %d packets, want the first one only", len(got))
	}
	if !bytes.Equal(got[0].Payload, []byte{0x01}) {
		t.Errorf("released payload = %x, want 01", got[0].Payload)
	}

	// The signal report now belongs to the second packet.
	tr.handleHardwareFrame(kisscodec.HWRespRxMeta, kisscodec.RxMeta{SNRQuarterDB: 8}.Encode())

	got = c.all()
	if len(got) != 2 {
		t.Fatalf("dispatched %d packets, want 2", len(got))
	}
	if !bytes.Equal(got[1].Payload, []byte{0x02}) || got[1].SNR != 8 {
		t.Errorf("second packet = %x SNR %d", got[1].Payload, got[1].SNR)
	}
}

func TestStopReleasesAHeldPacket(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: time.Minute}}
	tr.packetHandler = c.handle

	tr.handleDataFrame(makeTestPacket(0xDD).WriteTo())
	if len(c.all()) != 0 {
		t.Fatal("packet dispatched before its signal report")
	}

	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := c.all(); len(got) != 1 {
		t.Errorf("dispatched %d packets after Stop, want 1", len(got))
	}
}

func TestMalformedPacketIsDropped(t *testing.T) {
	c := newCollector()
	tr := &Transport{cfg: Config{SignalReportWait: -1}}
	tr.packetHandler = c.handle

	tr.handleDataFrame([]byte{0x00}) // header only, no payload

	if got := c.all(); len(got) != 0 {
		t.Errorf("dispatched %d packets, want none", len(got))
	}
}

func TestTxDoneFiresCallbackWithoutAWaiter(t *testing.T) {
	results := make(chan bool, 1)
	tr := &Transport{cfg: Config{OnTxDone: func(ok bool) { results <- ok }}}

	tr.handleHardwareFrame(kisscodec.HWRespTxDone, []byte{0x00})

	select {
	case ok := <-results:
		if ok {
			t.Error("OnTxDone reported success for a failed transmission")
		}
	case <-time.After(time.Second):
		t.Fatal("OnTxDone never fired")
	}
}

func TestTxBusyErrorFailsTheWaitingSend(t *testing.T) {
	// The modem refuses a data frame with a bare error and never follows it
	// with a TxDone. Discarding that error leaves SendPacket blocked for the
	// whole TxTimeout, and the next TxDone to arrive would then be credited to
	// it as a success.
	tr := &Transport{}
	done := make(chan txOutcome, 1)
	tr.txDone = done

	tr.handleHardwareFrame(kisscodec.HWRespError, []byte{kisscodec.HWErrTxBusy})

	select {
	case res := <-done:
		var hwErr *kisscodec.HardwareError
		if !errors.As(res.err, &hwErr) || hwErr.Code != kisscodec.HWErrTxBusy {
			t.Errorf("outcome = %+v, want a TxBusy hardware error", res)
		}
	default:
		t.Fatal("the waiting send was not released by the refusal")
	}
}

func TestErrorPrefersAPendingRequestWhenNotTxBusy(t *testing.T) {
	tr := &Transport{}
	done := make(chan txOutcome, 1)
	tr.txDone = done
	pending := &pendingRequest{want: kisscodec.HWRespStats, ch: make(chan hwResult, 1)}
	tr.pending = pending

	tr.handleHardwareFrame(kisscodec.HWRespError, []byte{kisscodec.HWErrNoCallback})

	select {
	case res := <-pending.ch:
		var hwErr *kisscodec.HardwareError
		if !errors.As(res.err, &hwErr) || hwErr.Code != kisscodec.HWErrNoCallback {
			t.Errorf("request result = %+v, want a NoCallback error", res)
		}
	default:
		t.Fatal("the pending request was not answered")
	}
	if len(done) != 0 {
		t.Error("an unrelated error was charged to the waiting send")
	}
}

func TestAbandonedTxDoneIsNotCreditedToTheNextSend(t *testing.T) {
	tr := &Transport{}

	// A sender gives up on a transmission the modem has not reported.
	done := make(chan txOutcome, 1)
	tr.txDone = done
	if err := tr.abandonTx(done); !errors.Is(err, ErrTxTimeout) {
		t.Fatalf("abandonTx = %v, want ErrTxTimeout", err)
	}

	// The next sender arms its own slot before the modem catches up.
	next := make(chan txOutcome, 1)
	tr.txDone = next

	// The late notification belongs to the abandoned packet, not this one.
	tr.handleTxDone(true)
	if len(next) != 0 {
		t.Fatal("a stale TxDone was reported as this send's success")
	}

	// A fresh notification still reaches the current sender.
	tr.handleTxDone(true)
	select {
	case res := <-next:
		if err := res.result(); err != nil {
			t.Errorf("outcome = %v, want success", err)
		}
	default:
		t.Fatal("the current send never received its TxDone")
	}
}

func TestAbandonTxTakesAResultThatArrivedDuringTheRace(t *testing.T) {
	// The modem can answer between the timer firing and abandonTx taking the
	// lock. Recording that as abandoned would swallow the next real TxDone.
	tr := &Transport{}
	done := make(chan txOutcome, 1)
	tr.txDone = done
	done <- txOutcome{success: true}

	if err := tr.abandonTx(done); err != nil {
		t.Errorf("abandonTx = %v, want the delivered success", err)
	}
	if tr.staleTxDone != 0 {
		t.Errorf("staleTxDone = %d, want 0", tr.staleTxDone)
	}
}

func TestDispatchIsSerializedAndOrdered(t *testing.T) {
	// A held packet released by its own timer must not run the handler
	// alongside, or after, a packet the read loop delivers later. Every other
	// transport dispatches only from its read loop, so handlers assume that.
	var (
		mu       sync.Mutex
		order    []byte
		inFlight atomic.Int32
		overlaps atomic.Int32
	)

	tr := &Transport{cfg: Config{SignalReportWait: 20 * time.Millisecond}}
	tr.packetHandler = func(p *codec.Packet, _ transport.PacketSource) {
		if inFlight.Add(1) > 1 {
			overlaps.Add(1)
		}
		time.Sleep(80 * time.Millisecond)
		mu.Lock()
		order = append(order, p.Payload[0])
		mu.Unlock()
		inFlight.Add(-1)
	}

	// Packet A is held; its timer releases it 20ms later into a slow handler.
	tr.handleDataFrame(makeTestPacket(0x0A).WriteTo())
	time.Sleep(40 * time.Millisecond)

	// Packet B arrives while that handler is still running, and its signal
	// report follows immediately.
	tr.handleDataFrame(makeTestPacket(0x0B).WriteTo())
	tr.handleHardwareFrame(kisscodec.HWRespRxMeta, kisscodec.RxMeta{SNRQuarterDB: 4}.Encode())

	if n := overlaps.Load(); n != 0 {
		t.Errorf("packet handler ran concurrently %d times", n)
	}
	mu.Lock()
	got := append([]byte(nil), order...)
	mu.Unlock()
	if !bytes.Equal(got, []byte{0x0A, 0x0B}) {
		t.Errorf("delivery order = %x, want 0a0b", got)
	}
}

func TestResponseWithoutAPendingRequestIsIgnored(t *testing.T) {
	tr := &Transport{}
	// None of these have a waiter, so they must be discarded rather than
	// blocking or panicking.
	tr.handleHardwareFrame(kisscodec.HWRespPong, nil)
	tr.handleHardwareFrame(kisscodec.HWRespError, []byte{kisscodec.HWErrTxBusy})
	tr.handleHardwareFrame(kisscodec.HWRespError, nil)
}
