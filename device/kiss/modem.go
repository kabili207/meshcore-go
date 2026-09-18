// Package kiss implements the modem half of the MeshCore KISS TNC protocol: a
// server that presents a radio to a KISS host over a byte stream.
//
// It is the counterpart to transport/kiss, which is the host half. Both speak
// the wire format in core/codec/kiss.
//
// Because meshcore-go has no LoRa driver, the physical layer is supplied by the
// caller through the Radio interface. That makes the modem equally usable as a
// front end for real hardware and as a bridge that exposes an existing mesh
// transport to KISS clients such as Direwolf or a phone app.
//
// Each connected host gets its own KISS parameters, its own single pending
// transmission, and its own signal-report setting, exactly as the firmware
// modem behaves over its one serial port. The radio itself is shared: only one
// transmission is on the air at a time, and every received packet is delivered
// to every connected host.
package kiss

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	kisscodec "github.com/kabili207/meshcore-go/core/codec/kiss"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/telemetry"
)

// Radio is the physical layer the modem transmits through.
type Radio interface {
	// Send transmits one raw packet, blocking until the transmission finishes.
	// The modem reports success or failure to the host as a TxDone
	// notification, and serializes calls so only one is ever in flight.
	Send(ctx context.Context, packet []byte) error
}

// RadioFunc adapts a plain function to the Radio interface.
type RadioFunc func(ctx context.Context, packet []byte) error

// Send calls f.
func (f RadioFunc) Send(ctx context.Context, packet []byte) error { return f(ctx, packet) }

// Config configures a Modem.
//
// The optional hooks mirror the firmware's callbacks: leaving one nil makes the
// matching SetHardware sub-command answer with HWErrNoCallback, which is what
// firmware does on boards that lack the hardware.
type Config struct {
	// Radio is the physical layer. Required.
	Radio Radio

	// Identity backs the crypto sub-commands. When nil, all of them answer
	// HWErrNoCallback rather than exposing a key the caller did not provide.
	Identity *crypto.KeyPair

	// DeviceName is reported by GetDeviceName.
	DeviceName string

	// SetRadio applies new modulation settings. The modem remembers whatever
	// was last applied and reports it from GetRadio, so a caller that only
	// needs the settings echoed back can supply a hook that returns nil.
	SetRadio func(cfg kisscodec.RadioConfig) error
	// SetTxPower sets the transmit power in dBm.
	SetTxPower func(dBm uint8) error

	// IsChannelBusy reports whether the radio is currently receiving. It also
	// drives carrier sensing in the CSMA state machine; without it the modem
	// treats the channel as always clear.
	IsChannelBusy func() bool
	// CurrentRSSI returns an instantaneous channel reading in dBm.
	CurrentRSSI func() int8
	// NoiseFloor returns the calibrated noise floor in dBm.
	NoiseFloor func() int16
	// EstimateAirtime returns how long a packet of the given length occupies
	// the channel. It also bounds how long CSMA will wait for a busy channel.
	EstimateAirtime func(packetLen int) time.Duration

	// Stats returns the lifetime packet counters.
	Stats func() kisscodec.Stats
	// Battery returns the battery voltage in millivolts.
	Battery func() uint16
	// MCUTemp returns the microcontroller temperature in degrees Celsius. The
	// second result reports whether a reading was available.
	MCUTemp func() (float32, bool)
	// Telemetry answers GetSensors with a CayenneLPP payload.
	Telemetry telemetry.Provider
	// OnReboot is invoked after the modem acknowledges a Reboot request.
	OnReboot func()

	// Rand supplies bytes for GetRandom and CSMA. Defaults to crypto/rand.
	Rand io.Reader

	// OutboundQueueDepth is how many frames may await writing to a host before
	// the modem starts dropping them and reporting TxBusy. Defaults to
	// DefaultOutboundQueueDepth.
	OutboundQueueDepth int

	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// DefaultOutboundQueueDepth bounds a host's pending outbound frames. The
// firmware modem uses two slots; a Go host is not writing into a 64-byte UART
// buffer, so the default is roomier.
const DefaultOutboundQueueDepth = 16

// Modem serves the KISS protocol to one or more connected hosts.
type Modem struct {
	cfg Config
	log *slog.Logger

	// txMu keeps one transmission on the air at a time across all hosts.
	txMu sync.Mutex

	mu sync.RWMutex
	// radioCfg is the last configuration applied through SetRadio, echoed back
	// by GetRadio the way the firmware echoes its cached RadioConfig.
	radioCfg kisscodec.RadioConfig
	txPower  uint8
	conns    map[*conn]struct{}
}

// New creates a Modem. It returns an error if Config.Radio is missing.
func New(cfg Config) (*Modem, error) {
	if cfg.Radio == nil {
		return nil, errors.New("kiss: Config.Radio is required")
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.OutboundQueueDepth <= 0 {
		cfg.OutboundQueueDepth = DefaultOutboundQueueDepth
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Modem{
		cfg:   cfg,
		log:   cfg.Logger.WithGroup("kiss-modem"),
		conns: make(map[*conn]struct{}),
	}, nil
}

// Serve speaks KISS to one host over rw until the stream ends or ctx is
// cancelled. It returns nil on a clean disconnect.
//
// Cancelling ctx closes rw when it is an io.Closer. Without that, the read
// blocked on the stream would keep Serve running until the host hung up on its
// own.
//
// Serve is safe to call concurrently for several hosts.
func (m *Modem) Serve(ctx context.Context, rw io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if closer, ok := rw.(io.Closer); ok {
		stopped := make(chan struct{})
		defer close(stopped)
		go func() {
			select {
			case <-ctx.Done():
				closer.Close()
			case <-stopped:
			}
		}()
	}

	c := newConn(m, rw, cancel)

	m.mu.Lock()
	m.conns[c] = struct{}{}
	m.mu.Unlock()

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		c.writeLoop(ctx)
	}()

	defer func() {
		m.mu.Lock()
		delete(m.conns, c)
		m.mu.Unlock()
		c.close()
		// Wait for the writer to drain. Returning first would let a caller
		// close the stream out from under an outbound frame, which is how a
		// reboot acknowledgement goes missing.
		<-writeDone
	}()

	return c.readLoop(ctx)
}

// ListenAndServe accepts KISS hosts on addr until ctx is cancelled. Each
// connection is served in its own goroutine.
func (m *Modem) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	m.log.Info("KISS modem listening", "addr", ln.Addr().String())

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer nc.Close()
			if err := m.Serve(ctx, nc); err != nil {
				m.log.Debug("KISS host disconnected", "remote", nc.RemoteAddr().String(), "error", err)
			}
		}()
	}
}

// Receive delivers a packet received off the air to every connected host,
// followed by a signal report for the hosts that have one enabled.
//
// Packets longer than the MeshCore transmission unit are dropped, matching the
// firmware modem.
func (m *Modem) Receive(packet []byte, meta kisscodec.RxMeta) {
	if len(packet) == 0 || len(packet) > kisscodec.MaxPacketSize {
		m.log.Debug("dropping received packet outside MTU", "len", len(packet))
		return
	}

	frame, err := kisscodec.EncodeDataFrame(packet)
	if err != nil {
		m.log.Debug("failed to encode received packet", "error", err)
		return
	}
	metaFrame, err := kisscodec.EncodeHardwareFrame(kisscodec.HWRespRxMeta, meta.Encode())
	if err != nil {
		m.log.Debug("failed to encode signal report", "error", err)
		return
	}

	m.mu.RLock()
	conns := make([]*conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.mu.RUnlock()

	for _, c := range conns {
		// The signal report only goes out if the data frame did, so a host
		// that dropped the packet never sees metadata for a packet it lacks.
		if c.enqueue(frame) && c.signalReportEnabled() {
			c.enqueue(metaFrame)
		}
	}
}

// RadioConfig returns the modulation settings last applied through SetRadio.
func (m *Modem) RadioConfig() kisscodec.RadioConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.radioCfg
}

// TxPower returns the transmit power last applied through SetTxPower, in dBm.
func (m *Modem) TxPower() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.txPower
}

// conn is one host connection: its KISS parameters, its outbound queue, and its
// single pending transmission.
type conn struct {
	m      *Modem
	rw     io.ReadWriter
	cancel context.CancelFunc

	out    chan []byte
	closed chan struct{}
	once   sync.Once

	mu sync.Mutex
	// busyErrPending records a frame dropped because out was full, so the
	// error can be reported once there is room, as the firmware does.
	busyErrPending bool
	txPending      bool
	txDelay        uint8
	persistence    uint8
	slotTime       uint8
	txTail         uint8
	fullDuplex     bool
	signalReport   bool
}

func newConn(m *Modem, rw io.ReadWriter, cancel context.CancelFunc) *conn {
	return &conn{
		m:            m,
		rw:           rw,
		cancel:       cancel,
		out:          make(chan []byte, m.cfg.OutboundQueueDepth),
		closed:       make(chan struct{}),
		txDelay:      kisscodec.DefaultTxDelay,
		persistence:  kisscodec.DefaultPersistence,
		slotTime:     kisscodec.DefaultSlotTime,
		txTail:       kisscodec.DefaultTxTail,
		signalReport: true,
	}
}

func (c *conn) close() {
	c.once.Do(func() { close(c.closed) })
}

func (c *conn) signalReportEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signalReport
}

// enqueue queues a frame for writing, reporting whether it was accepted. A full
// queue drops the frame and arms a TxBusy error for the writer to emit once it
// has drained.
func (c *conn) enqueue(frame []byte) bool {
	select {
	case <-c.closed:
		return false
	case c.out <- frame:
		return true
	default:
		c.mu.Lock()
		c.busyErrPending = true
		c.mu.Unlock()
		c.m.log.Debug("host outbound queue full, dropping frame")
		return false
	}
}

// sendHardware queues a SetHardware response.
func (c *conn) sendHardware(subCmd uint8, data []byte) bool {
	frame, err := kisscodec.EncodeHardwareFrame(subCmd, data)
	if err != nil {
		c.m.log.Debug("failed to encode SetHardware response", "sub_command", subCmd, "error", err)
		return false
	}
	return c.enqueue(frame)
}

// sendError queues an error response carrying one of the HWErr codes.
func (c *conn) sendError(code uint8) bool {
	return c.sendHardware(kisscodec.HWRespError, []byte{code})
}

func (c *conn) writeLoop(ctx context.Context) {
	defer c.cancel()

	for {
		select {
		case <-ctx.Done():
			c.flushQueued()
			return
		case <-c.closed:
			c.flushQueued()
			return
		case frame := <-c.out:
			if _, err := c.rw.Write(frame); err != nil {
				c.m.log.Debug("write to KISS host failed", "error", err)
				return
			}
			c.drainBusyError()
		}
	}
}

// flushQueued writes whatever is already queued before the loop gives up.
//
// Without this a reply enqueued immediately before shutdown races the
// cancellation and is lost about half the time, because a select with both
// cases ready picks at random. Reboot is the case that matters: the host must
// see its acknowledgement even though the connection is about to go away, which
// is why the firmware flushes its serial port before rebooting.
func (c *conn) flushQueued() {
	for {
		select {
		case frame := <-c.out:
			if _, err := c.rw.Write(frame); err != nil {
				return
			}
		default:
			return
		}
	}
}

// drainBusyError emits the deferred TxBusy notice now that the queue has room.
func (c *conn) drainBusyError() {
	c.mu.Lock()
	pending := c.busyErrPending
	c.busyErrPending = false
	c.mu.Unlock()

	if !pending {
		return
	}
	frame, err := kisscodec.EncodeHardwareFrame(kisscodec.HWRespError, []byte{kisscodec.HWErrTxBusy})
	if err != nil {
		return
	}
	select {
	case c.out <- frame:
	default:
		// Still no room. Re-arm rather than lose the notice.
		c.mu.Lock()
		c.busyErrPending = true
		c.mu.Unlock()
	}
}

func (c *conn) readLoop(ctx context.Context) error {
	reader := kisscodec.NewFrameReader(c.rw)

	for {
		typeByte, data, err := reader.ReadFrame()
		if err != nil {
			if errors.Is(err, kisscodec.ErrFrameTooLarge) {
				c.m.log.Debug("discarded oversize frame from host", "error", err)
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if err := ctx.Err(); err != nil {
			return nil
		}

		c.handleFrame(ctx, typeByte, data)
	}
}

func (c *conn) handleFrame(ctx context.Context, typeByte byte, data []byte) {
	if typeByte == kisscodec.CmdReturn {
		return // leaving KISS mode is a no-op
	}

	port, cmd := kisscodec.SplitTypeByte(typeByte)
	if port != 0 {
		return
	}

	switch cmd {
	case kisscodec.CmdData:
		c.handleData(ctx, data)
	case kisscodec.CmdTxDelay:
		c.setParam(data, func(v uint8) { c.txDelay = v })
	case kisscodec.CmdPersistence:
		c.setParam(data, func(v uint8) { c.persistence = v })
	case kisscodec.CmdSlotTime:
		c.setParam(data, func(v uint8) { c.slotTime = v })
	case kisscodec.CmdTxTail:
		c.setParam(data, func(v uint8) { c.txTail = v })
	case kisscodec.CmdFullDuplex:
		c.setParam(data, func(v uint8) { c.fullDuplex = v != 0 })
	case kisscodec.CmdSetHardware:
		if len(data) > 0 {
			c.handleHardware(ctx, data[0], data[1:])
		}
	}
}

func (c *conn) setParam(data []byte, apply func(uint8)) {
	if len(data) < 1 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	apply(data[0])
}
