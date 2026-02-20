// Package router provides packet routing and forwarding for MeshCore networks.
//
// The Router sits between transports (MQTT, serial) and application logic,
// making forwarding decisions for every received packet. It handles:
//   - Flood routing: appending this node's hash to the path and re-broadcasting
//   - Direct routing: forwarding packets along a specified path of node hashes
//   - Deduplication: preventing duplicate packet processing via circular hash tables
//   - Multipart reassembly: combining fragmented packets before dispatch
//   - Transport code validation: dropping packets with unrecognized region codes
//   - ACK forwarding: creating new ACK packets when relaying direct-routed ACKs
//   - TRACE forwarding: hop-by-hop path tracing with SNR collection
//   - Send queue: priority-ordered outbound packet queue with optional delay
//
// This corresponds to the firmware's Mesh class (src/Mesh.cpp).
package router

import (
	"context"
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/dedupe"
	"github.com/kabili207/meshcore-go/core/multipart"
	"github.com/kabili207/meshcore-go/transport"
)

const (
	// DefaultMaxFloodHops is the maximum number of flood hops before a packet is dropped.
	DefaultMaxFloodHops = codec.MaxPathSize // 64

	// DefaultDrainInterval is the default interval for the send queue drain loop.
	DefaultDrainInterval = 10 * time.Millisecond

	// Send priorities matching firmware conventions.
	PriorityDirect      = 0 // Highest: direct-routed traffic
	PriorityFloodData   = 1 // Flood data, ACKs
	PriorityFloodPath   = 2 // Flood PATH packets
	PriorityFloodAdvert = 3 // Lowest for outbound: ADVERT packets
	PriorityTrace       = 5 // TRACE forwarding
)

// PacketHandler is called by the router when a packet is received that should
// be processed by the application layer. The handler runs synchronously before
// any forwarding decision — it may call pkt.MarkDoNotRetransmit() to suppress
// flood forwarding.
type PacketHandler func(pkt *codec.Packet, src transport.PacketSource)

// Config configures a Router.
type Config struct {
	// SelfID is this node's identity. Its Hash() (first byte of public key)
	// is used for path matching during direct routing and appended to paths
	// during flood forwarding.
	SelfID core.MeshCoreID

	// ForwardPackets enables packet forwarding (repeater mode).
	// When false (default), the router processes packets addressed to this node
	// but does not relay flood or direct traffic for other nodes.
	// This is equivalent to the firmware's allowPacketForward().
	ForwardPackets bool

	// MaxFloodHops limits how far flood packets can propagate through this node.
	// Packets with path_len >= MaxFloodHops are not forwarded.
	// Default: 64 (MaxPathSize).
	MaxFloodHops int

	// DrainInterval is how often the queue drain goroutine checks for ready
	// packets. Default: 10ms. Only used when Start() is called.
	DrainInterval time.Duration

	// ValidateTransportCode is called for packets that include transport codes.
	// If non-nil, it must return true for the packet to be processed.
	// If nil, packets with transport codes pass through without validation.
	ValidateTransportCode TransportCodeValidator

	// Logger for routing events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Router handles packet routing and forwarding for a MeshCore node.
type Router struct {
	cfg       Config
	log       *slog.Logger
	dedup     *dedupe.PacketDeduplicator
	multipart *multipart.Reassembler
	queue     *SendQueue

	mu         sync.RWMutex
	transports []transportEntry
	onPacket   PacketHandler

	cancel    context.CancelFunc
	drainDone chan struct{}
	started   bool
}

type transportEntry struct {
	transport transport.Transport
	source    transport.PacketSource
}

// New creates a Router with the given configuration.
func New(cfg Config) *Router {
	if cfg.MaxFloodHops <= 0 {
		cfg.MaxFloodHops = DefaultMaxFloodHops
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Router{
		cfg:       cfg,
		log:       logger.WithGroup("router"),
		dedup:     dedupe.New(),
		multipart: multipart.New(),
		queue:     NewSendQueue(),
	}
}

// Start begins the queue drain goroutine. Packets pushed to the queue will
// be sent when ready. If Start is never called, enqueue falls back to
// synchronous sending.
func (r *Router) Start(ctx context.Context) {
	interval := r.cfg.DrainInterval
	if interval <= 0 {
		interval = DefaultDrainInterval
	}
	ctx, r.cancel = context.WithCancel(ctx)
	r.drainDone = make(chan struct{})
	r.started = true
	go r.drainLoop(ctx, interval)
}

// Stop cancels the drain goroutine and waits for it to finish.
func (r *Router) Stop() {
	if r.cancel != nil {
		r.cancel()
		<-r.drainDone
		r.cancel = nil
		r.started = false
	}
}

// drainLoop pops ready packets from the send queue and sends them.
func (r *Router) drainLoop(ctx context.Context, interval time.Duration) {
	defer close(r.drainDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				entry := r.queue.Pop()
				if entry == nil {
					break
				}
				if entry.SendToAll {
					r.broadcastToAllTransports(entry.Packet)
				} else {
					r.broadcastToTransports(entry.Packet, entry.ExcludeSource)
				}
			}
		}
	}
}

// enqueue adds a packet to the send queue if the drain goroutine is running,
// otherwise sends synchronously.
func (r *Router) enqueue(pkt *codec.Packet, priority uint8, delay time.Duration, excludeSource transport.PacketSource, sendToAll bool) {
	if !r.started {
		if sendToAll {
			r.broadcastToAllTransports(pkt)
		} else {
			r.broadcastToTransports(pkt, excludeSource)
		}
		return
	}
	r.queue.Push(pkt, priority, delay, excludeSource, sendToAll)
}

// SetPacketHandler sets the callback for packets that should be processed by
// the application layer. The handler is called synchronously during HandlePacket
// before forwarding decisions are made. The handler may call
// pkt.MarkDoNotRetransmit() to suppress flood forwarding of the packet.
func (r *Router) SetPacketHandler(fn PacketHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onPacket = fn
}

// AddTransport registers a transport with the router. The router installs
// itself as the transport's packet handler so that incoming packets are
// automatically routed through HandlePacket.
func (r *Router) AddTransport(t transport.Transport, source transport.PacketSource) {
	r.mu.Lock()
	r.transports = append(r.transports, transportEntry{transport: t, source: source})
	r.mu.Unlock()

	t.SetPacketHandler(func(pkt *codec.Packet, src transport.PacketSource) {
		r.HandlePacket(pkt, src)
	})
}

// HandlePacket is the main routing entry point. It processes an incoming packet,
// dispatches it to the application callback, and makes forwarding decisions.
//
// This corresponds to the firmware's Mesh::onRecvPacket() + routeRecvPacket().
func (r *Router) HandlePacket(pkt *codec.Packet, src transport.PacketSource) {
	// Gate 1: version check
	if pkt.PayloadVersion() > codec.PayloadVer1 {
		r.log.Debug("dropping packet with unsupported version",
			"version", pkt.PayloadVersion())
		return
	}

	// Gate 1.5: transport code validation (before dedup so rejected packets
	// don't consume dedup slots)
	if pkt.HasTransportCodes() && r.cfg.ValidateTransportCode != nil {
		if !r.cfg.ValidateTransportCode(pkt) {
			r.log.Debug("dropping packet with unrecognized transport code",
				"code0", pkt.TransportCodes[0],
				"code1", pkt.TransportCodes[1])
			return
		}
	}

	// Gate 2: multipart reassembly
	if pkt.PayloadType() == codec.PayloadTypeMultipart {
		r.handleMultipart(pkt, src)
		return
	}

	// Gate 3: deduplication (also inserts the packet into the seen table)
	if r.dedup.HasSeen(pkt) {
		return
	}

	// Gate 3.5: TRACE handling (after dedup, before direct routing —
	// TRACE uses Path[] for SNR values, not relay hashes)
	if pkt.PayloadType() == codec.PayloadTypeTrace {
		r.handleTrace(pkt, src)
		return
	}

	// Gate 4: direct routing with path
	if pkt.IsDirect() && pkt.PathLen > 0 {
		r.handleDirectForward(pkt, src)
		return
	}

	// Gate 5: direct with no path (zero-hop or final destination)
	if pkt.IsDirect() && pkt.PathLen == 0 {
		r.dispatchToApp(pkt, src)
		return
	}

	// Gate 6: flood routing
	if pkt.IsFlood() {
		r.handleFlood(pkt, src)
		return
	}

	// Unknown route type — drop silently
}

// handleMultipart processes a MULTIPART packet fragment. If reassembly completes,
// the assembled packet is dispatched through HandlePacket.
func (r *Router) handleMultipart(pkt *codec.Packet, src transport.PacketSource) {
	frag, err := multipart.ParseFragment(pkt.Payload)
	if err != nil {
		r.log.Debug("failed to parse multipart fragment", "error", err)
		return
	}

	// Use the first byte of the path (or 0 for zero-hop) as the sender key.
	var srcHash uint8
	if pkt.PathLen > 0 {
		srcHash = pkt.Path[0]
	}

	assembled := r.multipart.HandleFragment(frag, srcHash)
	if assembled != nil {
		r.HandlePacket(assembled, src)
	}
}

// handleDirectForward processes a direct-routed packet with path_len >= 1.
func (r *Router) handleDirectForward(pkt *codec.Packet, src transport.PacketSource) {
	// Check if we are the next hop
	if pkt.Path[0] != r.cfg.SelfID.Hash() {
		// Not our hop — drop
		return
	}

	if !r.cfg.ForwardPackets {
		// We match, but forwarding is disabled — drop
		return
	}

	// ACK special case: dispatch to app first (early receive), then create
	// a new ACK packet and queue it at highest priority.
	if pkt.PayloadType() == codec.PayloadTypeAck {
		r.dispatchToApp(pkt, src)
		removeSelfFromPath(pkt)
		r.forwardAck(pkt)
		return
	}

	// Remove ourselves from the path
	removeSelfFromPath(pkt)

	if pkt.PathLen == 0 {
		// We were the last relay hop. The next node to receive this is the
		// final destination (identified by dest_hash in the payload, not path).
		// Forward it out with empty path.
	}

	r.enqueue(pkt, PriorityDirect, 0, src, false)
}

// forwardAck creates a new ACK packet from the forwarded packet's payload
// and queues it at the highest priority. This matches the firmware's
// routeDirectRecvAcks() behavior where new packets are created rather than
// retransmitting the original.
func (r *Router) forwardAck(pkt *codec.Packet) {
	if len(pkt.Payload) < codec.AckSize {
		return
	}
	crc := binary.LittleEndian.Uint32(pkt.Payload[:4])

	ackPkt := &codec.Packet{
		Header:  pkt.Header,
		PathLen: pkt.PathLen,
		Path:    make([]byte, pkt.PathLen),
		Payload: codec.BuildAckPayload(crc),
	}
	if pkt.HasTransportCodes() {
		ackPkt.TransportCodes = pkt.TransportCodes
	}
	copy(ackPkt.Path, pkt.Path[:pkt.PathLen])

	r.enqueue(ackPkt, PriorityDirect, 0, 0, true)
}

// handleFlood processes a flood-routed packet.
func (r *Router) handleFlood(pkt *codec.Packet, src transport.PacketSource) {
	// Dispatch to app first — the app may decrypt the packet and call
	// MarkDoNotRetransmit() to suppress forwarding.
	r.dispatchToApp(pkt, src)

	// Forwarding decision
	r.routeFloodForward(pkt, src)
}

// routeFloodForward decides whether to re-broadcast a flood packet.
// This corresponds to the firmware's Mesh::routeRecvPacket().
func (r *Router) routeFloodForward(pkt *codec.Packet, src transport.PacketSource) {
	if !r.cfg.ForwardPackets {
		return
	}
	if pkt.IsMarkedDoNotRetransmit() {
		return
	}
	if int(pkt.PathLen)+1 > r.cfg.MaxFloodHops {
		return
	}

	// Clone the packet before modifying path for forwarding.
	// The original was already dispatched to the app.
	fwd := pkt.Clone()

	// Append our hash to the path
	if int(fwd.PathLen) >= len(fwd.Path) {
		// Grow path slice if needed
		fwd.Path = append(fwd.Path, r.cfg.SelfID.Hash())
	} else {
		fwd.Path[fwd.PathLen] = r.cfg.SelfID.Hash()
	}
	fwd.PathLen++

	// Firmware uses pathLen as priority for flood forwarding —
	// closer sources get lower (better) priority.
	r.enqueue(fwd, fwd.PathLen, 0, src, false)
}

// dispatchToApp calls the registered application packet handler.
func (r *Router) dispatchToApp(pkt *codec.Packet, src transport.PacketSource) {
	r.mu.RLock()
	handler := r.onPacket
	r.mu.RUnlock()

	if handler != nil {
		handler(pkt, src)
	}
}

// broadcastToTransports sends a packet to all registered transports except the
// one identified by excludeSource. This prevents echoing a packet back to the
// transport it arrived on.
func (r *Router) broadcastToTransports(pkt *codec.Packet, excludeSource transport.PacketSource) {
	r.mu.RLock()
	entries := make([]transportEntry, len(r.transports))
	copy(entries, r.transports)
	r.mu.RUnlock()

	for _, entry := range entries {
		if entry.source == excludeSource {
			continue
		}
		if !entry.transport.IsConnected() {
			continue
		}
		if err := entry.transport.SendPacket(pkt); err != nil {
			r.log.Warn("failed to send packet",
				"transport", entry.source, "error", err)
		}
	}
}

// SendFlood prepares and sends a packet in flood mode.
// The path is cleared, the packet is marked as seen (to prevent loopback),
// and it is sent to all connected transports.
func (r *Router) SendFlood(pkt *codec.Packet) {
	// Set flood route type, preserving payload type and version bits
	pkt.Header = (pkt.Header &^ codec.PHRouteMask) | codec.RouteTypeFlood
	pkt.PathLen = 0
	pkt.Path = nil

	// Mark as seen so we don't process it again if it loops back
	r.dedup.HasSeen(pkt)

	r.enqueue(pkt, PriorityFloodData, 0, 0, true)
}

// SendDirect prepares and sends a packet in direct routing mode.
// The path is set to the provided route, and the packet is marked as seen.
func (r *Router) SendDirect(pkt *codec.Packet, path []byte) {
	pkt.Header = (pkt.Header &^ codec.PHRouteMask) | codec.RouteTypeDirect
	pkt.PathLen = uint8(len(path))
	pkt.Path = make([]byte, len(path))
	copy(pkt.Path, path)

	r.dedup.HasSeen(pkt)

	r.enqueue(pkt, PriorityDirect, 0, 0, true)
}

// SendZeroHop prepares and sends a packet as a zero-hop direct packet.
// These packets are not forwarded by relays (path is empty).
func (r *Router) SendZeroHop(pkt *codec.Packet) {
	pkt.Header = (pkt.Header &^ codec.PHRouteMask) | codec.RouteTypeDirect
	pkt.PathLen = 0
	pkt.Path = nil

	r.dedup.HasSeen(pkt)

	r.enqueue(pkt, PriorityDirect, 0, 0, true)
}

// broadcastToAllTransports sends a packet to every connected transport.
// Used for outbound packets originated by this node (no source to exclude).
func (r *Router) broadcastToAllTransports(pkt *codec.Packet) {
	r.mu.RLock()
	entries := make([]transportEntry, len(r.transports))
	copy(entries, r.transports)
	r.mu.RUnlock()

	for _, entry := range entries {
		if !entry.transport.IsConnected() {
			continue
		}
		if err := entry.transport.SendPacket(pkt); err != nil {
			r.log.Warn("failed to send packet",
				"transport", entry.source, "error", err)
		}
	}
}

// removeSelfFromPath removes the first byte from the packet's path,
// shifting all remaining bytes left by one. This is called when this node
// is the next hop in a direct-routed packet.
func removeSelfFromPath(pkt *codec.Packet) {
	if pkt.PathLen == 0 {
		return
	}
	pkt.PathLen--
	copy(pkt.Path, pkt.Path[1:1+pkt.PathLen])
}
