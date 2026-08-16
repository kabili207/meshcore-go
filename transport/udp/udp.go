// Package udp provides a UDP multicast transport for bridging MeshCore packets
// over a local network.
//
// Each datagram carries a single RS232 frame (the same [0xC03E][length][payload]
// [Fletcher-16] framing the serial transport uses), so this transport is wire
// compatible with the kn6plv/MeshCore2Net serial-to-multicast bridge. The
// default group and port (224.0.0.69:4402) match that project.
//
// Loop prevention is handled at two levels: multicast loopback is disabled so a
// node never hears its own transmissions on the same host, and the router
// excludes the originating PacketSource when rebroadcasting, so a packet
// received over UDP is never sent back out over UDP.
package udp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
	"golang.org/x/net/ipv4"
)

// Compile-time interface check.
var _ transport.Transport = (*Transport)(nil)

const (
	// DefaultGroupAddress is the multicast group used by MeshCore2Net.
	DefaultGroupAddress = "224.0.0.69"
	// DefaultPort is the multicast port used by MeshCore2Net.
	DefaultPort = 4402
	// readBufSize bounds a received datagram. A single RS232 frame maxes out at
	// FrameHeaderSize + MaxTransUnit + FrameChecksumSize; this leaves headroom
	// for a datagram that bundles a few frames back to back.
	readBufSize = 2048
)

// Config holds the configuration for a UDP multicast transport.
type Config struct {
	// GroupAddress is the IPv4 multicast group to join. Defaults to 224.0.0.69.
	GroupAddress string
	// Port is the multicast port. Defaults to 4402.
	Port int
	// Interface is the name of the network interface to bind multicast to
	// (e.g. "eth0"). If empty, the system default interface is used.
	Interface string
	// Logger is the logger to use. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Transport implements transport.Transport over UDP multicast.
type Transport struct {
	cfg           Config
	conn          *ipv4.PacketConn
	group         *net.UDPAddr
	log           *slog.Logger
	mu            sync.RWMutex
	connected     bool
	cancel        context.CancelFunc
	done          chan struct{}
	packetHandler transport.PacketHandler
	stateHandler  transport.StateHandler
}

// New creates a new UDP multicast transport with the given configuration.
func New(cfg Config) *Transport {
	if cfg.GroupAddress == "" {
		cfg.GroupAddress = DefaultGroupAddress
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &Transport{
		cfg: cfg,
		log: cfg.Logger.WithGroup("udp"),
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

// Start joins the multicast group and begins reading packets.
func (t *Transport) Start(ctx context.Context) error {
	groupIP := net.ParseIP(t.cfg.GroupAddress)
	if groupIP == nil {
		return fmt.Errorf("invalid multicast group address %q", t.cfg.GroupAddress)
	}
	if !groupIP.IsMulticast() {
		return fmt.Errorf("%q is not a multicast address", t.cfg.GroupAddress)
	}

	var ifi *net.Interface
	if t.cfg.Interface != "" {
		var err error
		ifi, err = net.InterfaceByName(t.cfg.Interface)
		if err != nil {
			return fmt.Errorf("resolving interface %q: %w", t.cfg.Interface, err)
		}
	}

	pc, err := net.ListenPacket("udp4", fmt.Sprintf("0.0.0.0:%d", t.cfg.Port))
	if err != nil {
		return fmt.Errorf("listening on udp port %d: %w", t.cfg.Port, err)
	}

	conn := ipv4.NewPacketConn(pc)
	group := &net.UDPAddr{IP: groupIP, Port: t.cfg.Port}

	if err := conn.JoinGroup(ifi, group); err != nil {
		conn.Close()
		return fmt.Errorf("joining multicast group %s: %w", t.cfg.GroupAddress, err)
	}
	if ifi != nil {
		if err := conn.SetMulticastInterface(ifi); err != nil {
			conn.Close()
			return fmt.Errorf("setting multicast interface %q: %w", t.cfg.Interface, err)
		}
	}
	if err := conn.SetMulticastLoopback(false); err != nil {
		// Not fatal: the router still drops echoes via source exclusion and
		// packet dedup. Log and continue.
		t.logger().Warn("failed to disable multicast loopback", "error", err)
	}

	t.mu.Lock()
	t.conn = conn
	t.group = group
	t.connected = true
	t.done = make(chan struct{})
	handler := t.stateHandler
	t.mu.Unlock()

	readCtx, cancel := context.WithCancel(ctx)
	t.cancel = cancel

	go t.readLoop(readCtx)

	t.logger().Info("joined multicast group", "group", t.cfg.GroupAddress, "port", t.cfg.Port, "interface", t.cfg.Interface)

	if handler != nil {
		handler(t, transport.EventConnected)
	}

	return nil
}

// Stop leaves the multicast group and stops the read loop.
func (t *Transport) Stop() error {
	t.mu.Lock()
	handler := t.stateHandler
	t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	t.mu.Lock()
	t.connected = false
	conn := t.conn
	t.conn = nil
	done := t.done
	t.mu.Unlock()

	var err error
	if conn != nil {
		err = conn.Close()
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

// IsConnected returns true if the multicast group is joined.
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

// SendPacket encodes a MeshCore packet in an RS232 frame and sends it to the
// multicast group.
func (t *Transport) SendPacket(packet *codec.Packet) error {
	t.mu.RLock()
	conn := t.conn
	group := t.group
	connected := t.connected
	t.mu.RUnlock()

	if !connected || conn == nil {
		return errors.New("not connected")
	}

	data := packet.WriteTo()
	frame, err := codec.EncodeRS232Frame(data)
	if err != nil {
		return fmt.Errorf("encoding RS232 frame: %w", err)
	}

	if _, err := conn.WriteTo(frame, nil, group); err != nil {
		return fmt.Errorf("sending multicast datagram: %w", err)
	}

	return nil
}

// readLoop continuously reads datagrams and dispatches the RS232 frames within.
func (t *Transport) readLoop(ctx context.Context) {
	defer close(t.done)

	// Capture the connection once. Stop() nils t.conn under the mutex, so
	// re-reading the field here would race; closing the conn is what unblocks
	// the pending ReadFrom, which is the actual stop signal.
	t.mu.RLock()
	conn := t.conn
	t.mu.RUnlock()

	if conn == nil {
		return
	}

	buf := make([]byte, readBufSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, _, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return // context cancelled or connection closed, clean shutdown
			}
			t.logger().Error("udp read error", "error", err)
			t.handleDisconnect(err)
			return
		}

		if n == 0 {
			continue
		}

		t.processDatagram(buf[:n])
	}
}

// processDatagram decodes every complete RS232 frame in a single datagram and
// dispatches each as a packet. Datagrams are atomic, so any trailing bytes that
// don't form a complete frame are dropped rather than buffered across reads.
func (t *Transport) processDatagram(data []byte) {
	for len(data) >= codec.MinFrameSize {
		frame, remaining, err := codec.DecodeRS232Frame(data)
		if err != nil {
			t.logger().Debug("dropping malformed datagram", "error", err)
			return
		}
		data = remaining

		var packet codec.Packet
		if err := packet.ReadFrom(frame.Payload); err != nil {
			t.logger().Debug("failed to parse MeshCore packet from frame", "error", err)
			continue
		}

		t.mu.RLock()
		handler := t.packetHandler
		t.mu.RUnlock()

		if handler != nil {
			handler(&packet, transport.PacketSourceUDP)
		}
	}
}

func (t *Transport) handleDisconnect(err error) {
	t.mu.Lock()
	t.connected = false
	handler := t.stateHandler
	t.mu.Unlock()

	if err != nil {
		t.logger().Error("udp disconnected", "error", err)
	}

	if handler != nil {
		handler(t, transport.EventDisconnected)
	}
}
