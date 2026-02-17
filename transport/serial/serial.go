// Package serial provides a serial transport for connecting to MeshCore devices.
//
// MeshCore devices communicate over serial using RS232 framing with Fletcher-16
// checksums. This transport handles the frame assembly from raw serial data and
// exposes the same Transport interface as the MQTT transport.
package serial

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
	"go.bug.st/serial"
)

// Compile-time interface check.
var _ transport.Transport = (*Transport)(nil)

const (
	// DefaultBaudRate is the default baud rate for MeshCore serial connections.
	DefaultBaudRate = 115200

	// readBufSize is the size of the serial read buffer.
	readBufSize = 1024
)

// Config holds the configuration for a serial transport.
type Config struct {
	// Port is the serial port path (e.g., "/dev/ttyUSB0" or "COM3").
	Port string
	// BaudRate is the serial baud rate. Defaults to 115200.
	BaudRate int
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements transport.Transport over a serial connection.
type Transport struct {
	cfg           Config
	port          serial.Port
	log           *slog.Logger
	mu            sync.RWMutex
	connected     bool
	cancel        context.CancelFunc
	done          chan struct{}
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler
}

// New creates a new serial transport with the given configuration.
func New(cfg Config) *Transport {
	if cfg.BaudRate == 0 {
		cfg.BaudRate = DefaultBaudRate
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Transport{
		cfg: cfg,
		log: cfg.Logger.WithGroup("serial"),
	}
}

// Start opens the serial port and begins reading packets.
func (t *Transport) Start(ctx context.Context) error {
	if t.cfg.Port == "" {
		return errors.New("serial port is required")
	}

	mode := &serial.Mode{
		BaudRate: t.cfg.BaudRate,
	}

	port, err := serial.Open(t.cfg.Port, mode)
	if err != nil {
		return fmt.Errorf("opening serial port: %w", err)
	}

	t.mu.Lock()
	t.port = port
	t.connected = true
	t.done = make(chan struct{})
	handler := t.stateHandler
	t.mu.Unlock()

	readCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel

	go t.readLoop(readCtx)

	t.log.Info("connected to serial port", "port", t.cfg.Port, "baud", t.cfg.BaudRate)

	if handler != nil {
		handler(t, transport.EventConnected)
	}

	return nil
}

// Stop closes the serial port and stops the read loop.
func (t *Transport) Stop() error {
	t.mu.Lock()
	handler := t.stateHandler
	t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	t.mu.Lock()
	t.connected = false
	port := t.port
	t.port = nil
	done := t.done
	t.mu.Unlock()

	var err error
	if port != nil {
		err = port.Close()
	}

	// Wait for read loop to finish
	if done != nil {
		<-done
	}

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}

	return err
}

// IsConnected returns true if the serial port is open.
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

// SendPacket encodes a MeshCore packet in an RS232 frame and writes it to the serial port.
func (t *Transport) SendPacket(packet *codec.Packet) error {
	t.mu.RLock()
	port := t.port
	connected := t.connected
	t.mu.RUnlock()

	if !connected || port == nil {
		return errors.New("not connected")
	}

	data := packet.WriteTo()
	frame, err := codec.EncodeRS232Frame(data)
	if err != nil {
		return fmt.Errorf("encoding RS232 frame: %w", err)
	}

	_, err = port.Write(frame)
	if err != nil {
		return fmt.Errorf("writing to serial port: %w", err)
	}

	return nil
}

// readLoop continuously reads from the serial port and assembles RS232 frames.
func (t *Transport) readLoop(ctx context.Context) {
	defer close(t.done)

	buf := make([]byte, readBufSize)
	var assemblyBuf []byte

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := t.port.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return // context cancelled, clean shutdown
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				t.handleDisconnect(err)
				return
			}
			t.log.Error("serial read error", "error", err)
			t.handleDisconnect(err)
			return
		}

		if n == 0 {
			continue
		}

		assemblyBuf = append(assemblyBuf, buf[:n]...)
		assemblyBuf = t.processFrames(assemblyBuf)
	}
}

// processFrames extracts complete RS232 frames from the buffer and dispatches packets.
// Returns any remaining bytes that don't form a complete frame.
func (t *Transport) processFrames(data []byte) []byte {
	for len(data) >= codec.MinFrameSize {
		frame, remaining, err := codec.DecodeRS232Frame(data)
		if err != nil {
			if errors.Is(err, codec.ErrIncompleteFrame) {
				return data // wait for more data
			}
			// Bad frame — try to find the next magic bytes
			if idx := findMagic(data[1:]); idx >= 0 {
				data = data[1+idx:]
				continue
			}
			// No magic found, discard everything
			return nil
		}

		data = remaining

		var packet codec.Packet
		if err := packet.ReadFrom(frame.Payload); err != nil {
			t.log.Debug("failed to parse MeshCore packet from frame", "error", err)
			continue
		}

		t.mu.RLock()
		handler := t.packetHandler
		t.mu.RUnlock()

		if handler != nil {
			handler(&packet, transport.PacketSourceSerial)
		}
	}

	return data
}

// findMagic searches for the RS232 magic bytes in data.
// Returns the index of the first byte of the magic, or -1 if not found.
func findMagic(data []byte) int {
	magic := [2]byte{byte(uint16(codec.BridgePacketMagic) >> 8), byte(codec.BridgePacketMagic & 0xFF)}
	for i := 0; i+1 < len(data); i++ {
		if data[i] == magic[0] && data[i+1] == magic[1] {
			return i
		}
	}
	return -1
}

func (t *Transport) handleDisconnect(err error) {
	t.mu.Lock()
	t.connected = false
	handler := t.stateHandler
	t.mu.Unlock()

	if err != nil {
		t.log.Error("serial disconnected", "error", err)
	}

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}
}
