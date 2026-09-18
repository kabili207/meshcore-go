// Package kiss provides a transport that drives a MeshCore KISS modem: the
// host half of the protocol in core/codec/kiss.
//
// Unlike the other transports in this repo, which carry mesh packets over an IP
// or USB link, this one puts packets on the air. The modem is a raw radio pipe,
// so transmissions are subject to real airtime. SendPacket reflects that: it
// waits for the modem's TxDone notification by default, which is what keeps a
// caller from overrunning a radio that can only hold one pending packet.
//
// The modem's SetHardware extensions (radio configuration, signal readings,
// telemetry, and the crypto offload) live in hardware.go.
package kiss

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/transport"
	goserial "go.bug.st/serial"
)

// Compile-time interface check.
var _ transport.Transport = (*Transport)(nil)

// Wire types re-exported so callers configuring a modem need only this package.
type (
	RadioConfig = kisscodec.RadioConfig
	Stats       = kisscodec.Stats
	RxMeta      = kisscodec.RxMeta
)

const (
	// DefaultBaudRate is the rate the KISS modem firmware runs its serial port at.
	DefaultBaudRate = 115200

	// DefaultTxTimeout bounds how long SendPacket waits for TxDone. It is
	// generous because the modem may sit in CSMA backoff before it ever keys
	// the transmitter.
	DefaultTxTimeout = 30 * time.Second

	// DefaultRequestTimeout bounds a SetHardware round trip.
	DefaultRequestTimeout = 5 * time.Second

	// DefaultSignalReportWait is how long a received packet is held so the
	// RxMeta frame that follows it can be attached. The modem queues the two
	// together, so this only ever waits out serial latency.
	DefaultSignalReportWait = 100 * time.Millisecond
)

var (
	// ErrNotConnected is returned by operations attempted before Start or after Stop.
	ErrNotConnected = errors.New("kiss: not connected")
	// ErrTxTimeout is returned when the modem never reports the transmission finishing.
	ErrTxTimeout = errors.New("kiss: timed out waiting for transmit to complete")
	// ErrTxFailed is returned when the modem reports the transmission failed.
	ErrTxFailed = errors.New("kiss: modem reported transmit failure")
)

// Config holds the configuration for a KISS transport.
type Config struct {
	// Port is the serial port path (e.g. "/dev/ttyUSB0" or "COM3"). Leave it
	// empty and set Stream to drive a modem over something other than a local
	// serial port.
	Port string
	// BaudRate is the serial baud rate. Defaults to DefaultBaudRate. Ignored
	// when Stream is set.
	BaudRate int
	// Stream is an already-open connection to the modem, used instead of Port.
	// Stop closes it. A TCP connection to a KISS-over-TCP bridge is the usual
	// case.
	Stream io.ReadWriteCloser

	// TxTimeout bounds how long SendPacket waits for the modem to report the
	// transmission finished. Defaults to DefaultTxTimeout. A negative value
	// makes SendPacket return as soon as the frame is written, which gives up
	// backpressure and invites TxBusy errors.
	TxTimeout time.Duration
	// RequestTimeout bounds a SetHardware round trip. Defaults to
	// DefaultRequestTimeout.
	RequestTimeout time.Duration
	// SignalReportWait is how long a received packet is held so a trailing
	// RxMeta frame can populate its SNR. Defaults to DefaultSignalReportWait.
	// Set it negative to dispatch packets immediately and leave SNR unset.
	SignalReportWait time.Duration

	// OnRxMeta, if set, receives every signal report alongside the packet it
	// describes. The packet handler already gets the SNR via Packet.SNR; this
	// callback is how a caller reaches RSSI.
	OnRxMeta func(packet *codec.Packet, meta RxMeta)
	// OnTxDone, if set, is called for every transmission the modem completes,
	// including ones SendPacket has already stopped waiting for.
	OnTxDone func(success bool)

	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements transport.Transport by driving a KISS modem.
type Transport struct {
	cfg Config
	log *slog.Logger

	mu        sync.RWMutex
	stream    io.ReadWriteCloser
	connected bool
	cancel    context.CancelFunc
	done      chan struct{}

	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler

	// writeMu serializes frame writes so two goroutines cannot interleave
	// bytes within a frame.
	writeMu sync.Mutex

	// txMu admits one transmission at a time, matching the modem's single
	// pending-packet slot.
	txMu sync.Mutex
	// txDone carries the outcome to the SendPacket currently waiting, if any.
	// Guarded by mu, and only ever written to under it, so a notification
	// cannot land in the gap between a sender giving up and the next one
	// arming its own slot.
	txDone chan txOutcome
	// staleTxDone counts transmissions a caller stopped waiting for. The modem
	// still reports each one eventually, and that late notification must be
	// dropped rather than handed to whoever is sending next.
	staleTxDone int

	// pending is the outstanding SetHardware request, if any. See hardware.go.
	reqMu   sync.Mutex
	pending *pendingRequest

	// rxHold buffers a received packet until its RxMeta arrives or the wait
	// expires, so Packet.SNR can be populated before dispatch.
	rxMu    sync.Mutex
	rxHeld  *codec.Packet
	rxTimer *time.Timer

	// dispatchMu serializes calls into the packet handler. Received packets
	// reach it from either the read loop or a hold timer, and callers written
	// against the other transports assume a single delivery goroutine.
	dispatchMu sync.Mutex
}

// txOutcome is how a transmission ended: err set when the modem never answered,
// otherwise success reports whether it keyed the transmitter.
type txOutcome struct {
	success bool
	err     error
}

// New creates a new KISS transport with the given configuration.
func New(cfg Config) *Transport {
	if cfg.BaudRate == 0 {
		cfg.BaudRate = DefaultBaudRate
	}
	if cfg.TxTimeout == 0 {
		cfg.TxTimeout = DefaultTxTimeout
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.SignalReportWait == 0 {
		cfg.SignalReportWait = DefaultSignalReportWait
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Transport{
		cfg: cfg,
		log: cfg.Logger.WithGroup("kiss"),
	}
}

// logger returns the configured logger, falling back to the default. A
// zero-value Transport has no logger, so the receive path must not assume New
// was used to build it.
func (t *Transport) logger() *slog.Logger {
	if t.log == nil {
		return slog.Default()
	}
	return t.log
}

// Start opens the modem connection and begins reading frames.
func (t *Transport) Start(ctx context.Context) error {
	stream := t.cfg.Stream
	if stream == nil {
		if t.cfg.Port == "" {
			return errors.New("kiss: either Port or Stream is required")
		}
		port, err := goserial.Open(t.cfg.Port, &goserial.Mode{BaudRate: t.cfg.BaudRate})
		if err != nil {
			return fmt.Errorf("kiss: opening serial port: %w", err)
		}
		stream = port
	}

	t.mu.Lock()
	t.stream = stream
	t.connected = true
	t.done = make(chan struct{})
	handler := t.stateHandler
	t.mu.Unlock()

	readCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel

	go t.readLoop(readCtx, stream)

	if t.cfg.Port != "" {
		t.logger().Info("connected to KISS modem", "port", t.cfg.Port, "baud", t.cfg.BaudRate)
	} else {
		t.logger().Info("connected to KISS modem over supplied stream")
	}

	if handler != nil {
		handler(t, transport.EventConnected)
	}
	return nil
}

// Stop closes the modem connection and stops the read loop.
func (t *Transport) Stop() error {
	t.mu.Lock()
	handler := t.stateHandler
	t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	t.mu.Lock()
	t.connected = false
	stream := t.stream
	t.stream = nil
	done := t.done
	t.mu.Unlock()

	var err error
	if stream != nil {
		err = stream.Close()
	}
	if done != nil {
		<-done
	}

	t.flushHeldPacket()
	// The read loop exits quietly on a cancelled context, so anything waiting
	// on the modem has to be released here rather than sitting out its timeout.
	t.releaseWaiters(nil)

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}
	return err
}

// IsConnected returns true if the modem connection is open.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connected
}

// SetPacketHandler sets the callback for incoming MeshCore packets.
func (t *Transport) SetPacketHandler(fn transport.PacketHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.packetHandler = fn
}

// SetStateHandler sets the callback for transport state changes.
func (t *Transport) SetStateHandler(fn transport.StateHandler) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stateHandler = fn
}

// SendPacket transmits a packet over the air.
//
// The modem holds one pending packet, so calls are serialized: each waits for
// the previous transmission to finish before queuing its own. It then waits up
// to Config.TxTimeout for the modem's TxDone notification, and reports
// ErrTxFailed if the modem could not key the transmitter. Set a negative
// TxTimeout to skip the wait.
func (t *Transport) SendPacket(packet *codec.Packet) error {
	frame, err := kisscodec.EncodeDataFrame(packet.WriteTo())
	if err != nil {
		return err
	}

	t.txMu.Lock()
	defer t.txMu.Unlock()

	if t.cfg.TxTimeout < 0 {
		return t.writeFrame(frame)
	}

	// Arm the notification slot before writing, so a fast modem cannot answer
	// before there is anywhere to put the result.
	done := make(chan txOutcome, 1)
	t.mu.Lock()
	t.txDone = done
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		if t.txDone == done {
			t.txDone = nil
		}
		t.mu.Unlock()
	}()

	if err := t.writeFrame(frame); err != nil {
		return err
	}

	timeout := t.cfg.TxTimeout
	if timeout == 0 {
		timeout = DefaultTxTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-done:
		return res.result()
	case <-timer.C:
		return t.abandonTx(done)
	}
}

// result turns an outcome into the error SendPacket returns.
func (o txOutcome) result() error {
	if o.err != nil {
		return o.err
	}
	if !o.success {
		return ErrTxFailed
	}
	return nil
}

// abandonTx gives up on a transmission the modem has not reported. It records
// that one TxDone is still owed so the notification, when it finally arrives,
// is not credited to the next sender.
func (t *Transport) abandonTx(done chan txOutcome) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// The modem may have answered in the gap between the timer firing and this
	// lock. Notifications are delivered under mu, so checking here is enough.
	select {
	case res := <-done:
		return res.result()
	default:
	}

	t.staleTxDone++
	t.txDone = nil
	return ErrTxTimeout
}

// failPendingTx hands err to a SendPacket waiting on the modem, reporting
// whether there was one to fail.
func (t *Transport) failPendingTx(err error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.txDone == nil {
		return false
	}
	select {
	case t.txDone <- txOutcome{err: err}:
	default:
	}
	t.txDone = nil
	return true
}

// SetTxDelay sets the transmitter keyup delay, in 10ms units.
func (t *Transport) SetTxDelay(units uint8) error { return t.writeParam(kisscodec.CmdTxDelay, units) }

// SetPersistence sets the CSMA persistence parameter. Higher values transmit
// sooner once the channel is clear.
func (t *Transport) SetPersistence(p uint8) error {
	return t.writeParam(kisscodec.CmdPersistence, p)
}

// SetSlotTime sets the CSMA slot interval, in 10ms units.
func (t *Transport) SetSlotTime(units uint8) error {
	return t.writeParam(kisscodec.CmdSlotTime, units)
}

// SetTxTail sets the post-transmission hold time, in 10ms units.
func (t *Transport) SetTxTail(units uint8) error { return t.writeParam(kisscodec.CmdTxTail, units) }

// SetFullDuplex enables or disables full-duplex operation. Enabling it bypasses
// CSMA entirely, so the modem transmits after TXDELAY without sensing the
// channel.
func (t *Transport) SetFullDuplex(enabled bool) error {
	var v uint8
	if enabled {
		v = 1
	}
	return t.writeParam(kisscodec.CmdFullDuplex, v)
}

// writeParam sends a one-byte KISS parameter command. These are fire and
// forget; the modem never acknowledges them.
func (t *Transport) writeParam(cmd uint8, value uint8) error {
	frame, err := kisscodec.EncodeFrame(byte(cmd), []byte{value})
	if err != nil {
		return err
	}
	return t.writeFrame(frame)
}

func (t *Transport) writeFrame(frame []byte) error {
	t.mu.RLock()
	stream := t.stream
	connected := t.connected
	t.mu.RUnlock()

	if !connected || stream == nil {
		return ErrNotConnected
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if _, err := stream.Write(frame); err != nil {
		return fmt.Errorf("kiss: writing frame: %w", err)
	}
	return nil
}

// readLoop reads frames from the modem until the stream closes.
func (t *Transport) readLoop(ctx context.Context, stream io.Reader) {
	defer close(t.done)

	reader := kisscodec.NewFrameReader(stream)

	for {
		typeByte, data, err := reader.ReadFrame()
		if err != nil {
			if errors.Is(err, kisscodec.ErrFrameTooLarge) {
				// The reader has already resynchronized.
				t.logger().Debug("discarded oversize KISS frame", "error", err)
				continue
			}
			if ctx.Err() != nil {
				return // cancelled, clean shutdown
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				t.handleDisconnect(nil)
				return
			}
			t.handleDisconnect(err)
			return
		}

		port, cmd := kisscodec.SplitTypeByte(typeByte)
		if typeByte == kisscodec.CmdReturn || port != 0 {
			continue
		}

		switch cmd {
		case kisscodec.CmdData:
			t.handleDataFrame(data)
		case kisscodec.CmdSetHardware:
			if len(data) > 0 {
				t.handleHardwareFrame(data[0], data[1:])
			}
		default:
			t.logger().Debug("ignoring unexpected KISS frame from modem", "command", cmd)
		}
	}
}

// handleDataFrame parses a received packet and holds it briefly so the RxMeta
// frame the modem sends next can fill in the signal report.
func (t *Transport) handleDataFrame(data []byte) {
	var packet codec.Packet
	if err := packet.ReadFrom(data); err != nil {
		t.logger().Debug("failed to parse MeshCore packet from KISS frame", "error", err)
		return
	}

	if t.cfg.SignalReportWait < 0 {
		t.dispatchNow(&packet)
		return
	}

	wait := t.cfg.SignalReportWait
	if wait == 0 {
		wait = DefaultSignalReportWait
	}

	// A second packet arriving before the first one's RxMeta means the report
	// is not coming; release the older packet now.
	t.flushHeldPacket()

	held := &packet
	t.rxMu.Lock()
	t.rxHeld = held
	// The timer names the packet it was armed for. A timer that fires just as
	// the next packet is taking the slot must not release that one early.
	t.rxTimer = time.AfterFunc(wait, func() { t.releaseHeld(held, nil) })
	t.rxMu.Unlock()
}

// releaseHeld dispatches the packet awaiting a signal report. want limits the
// claim to one specific packet; meta, when non-nil, is attached first.
//
// The claim and the dispatch happen under one lock so packets reach the handler
// one at a time and in the order they arrived. Without it a hold timer firing
// on an older packet could run the handler concurrently with, or after, the
// read loop's dispatch of a newer one, which no other transport in this repo
// does.
func (t *Transport) releaseHeld(want *codec.Packet, meta *RxMeta) bool {
	t.dispatchMu.Lock()
	defer t.dispatchMu.Unlock()

	packet := t.takeHeld(want)
	if packet == nil {
		return false
	}
	if meta != nil {
		packet.SNR = meta.SNRQuarterDB
		if t.cfg.OnRxMeta != nil {
			t.cfg.OnRxMeta(packet, *meta)
		}
	}
	t.dispatch(packet)
	return true
}

// takeHeld claims the packet awaiting its signal report. When want is non-nil,
// it claims that packet only, leaving any newer one in place.
func (t *Transport) takeHeld(want *codec.Packet) *codec.Packet {
	t.rxMu.Lock()
	defer t.rxMu.Unlock()

	if t.rxHeld == nil || (want != nil && t.rxHeld != want) {
		return nil
	}
	packet := t.rxHeld
	t.rxHeld = nil
	if t.rxTimer != nil {
		t.rxTimer.Stop()
		t.rxTimer = nil
	}
	return packet
}

// flushHeldPacket dispatches a packet waiting on its signal report, if any.
func (t *Transport) flushHeldPacket() {
	t.releaseHeld(nil, nil)
}

// handleRxMeta attaches a signal report to the packet awaiting it and
// dispatches that packet.
func (t *Transport) handleRxMeta(meta RxMeta) {
	if !t.releaseHeld(nil, &meta) {
		// Signal reporting was enabled mid-stream, the packet failed to parse,
		// or the hold already expired. Nothing to attach it to.
		t.logger().Debug("received RxMeta with no packet awaiting it", "rssi", meta.RSSI)
	}
}

// dispatch delivers a packet to the handler. Callers hold dispatchMu.
func (t *Transport) dispatch(packet *codec.Packet) {
	t.mu.RLock()
	handler := t.packetHandler
	t.mu.RUnlock()

	if handler != nil {
		handler(packet, transport.PacketSourceKISS)
	}
}

// dispatchNow delivers a packet that was never held, taking the dispatch lock
// so it still cannot overlap a held packet's release.
func (t *Transport) dispatchNow(packet *codec.Packet) {
	t.dispatchMu.Lock()
	defer t.dispatchMu.Unlock()
	t.dispatch(packet)
}

func (t *Transport) handleDisconnect(err error) {
	t.mu.Lock()
	t.connected = false
	handler := t.stateHandler
	t.mu.Unlock()

	if err != nil {
		t.logger().Error("KISS modem disconnected", "error", err)
	}

	t.releaseWaiters(err)

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}
}

// releaseWaiters fails everything blocked on a modem that is no longer there:
// an in-flight SetHardware request and a transmission still awaiting its
// TxDone. Neither would otherwise return until its own timeout, and TxTimeout
// defaults to half a minute.
func (t *Transport) releaseWaiters(cause error) {
	err := error(ErrNotConnected)
	if cause != nil {
		err = fmt.Errorf("%w: %w", ErrNotConnected, cause)
	}
	t.failPendingRequest(cause)
	t.failPendingTx(err)
}
