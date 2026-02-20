package router

import (
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/transport"
)

// handleTrace processes a TRACE packet. TRACE packets use direct routing but
// have unique forwarding semantics: the Path[] field stores per-hop SNR values
// (not relay hashes), and relay hashes are embedded in the payload.
//
// At each relay:
//  1. Parse the 9-byte header; compute hashSize = 1 << (flags & 0x03)
//  2. offset = pathLen * hashSize (index into the embedded path hashes)
//  3. If offset >= len(pathHashes): trace complete, deliver to app
//  4. If selfID matches pathHashes[offset:offset+hashSize]: append SNR, forward
//  5. Else: not our hop, drop
//
// This corresponds to the firmware's TRACE handling in Mesh::onRecvPacket().
func (r *Router) handleTrace(pkt *codec.Packet, src transport.PacketSource) {
	if int(pkt.PathLen) >= codec.MaxPathSize {
		return
	}

	trace, err := codec.ParseTracePayload(pkt.Payload)
	if err != nil {
		r.log.Debug("failed to parse trace payload", "error", err)
		return
	}

	offset := int(pkt.PathLen) * trace.HashSize

	// Check if trace is complete (all hops traversed)
	if offset >= len(trace.PathHashes) {
		r.dispatchToApp(pkt, src)
		return
	}

	// Check if we are the next hop
	hopHash := trace.PathHashes[offset : offset+trace.HashSize]
	if !r.cfg.SelfID.IsHashMatch(hopHash) {
		return
	}

	if !r.cfg.ForwardPackets {
		return
	}

	// Clone, append our SNR to the path, and forward
	fwd := pkt.Clone()

	if int(fwd.PathLen) >= len(fwd.Path) {
		fwd.Path = append(fwd.Path, byte(pkt.SNR))
	} else {
		fwd.Path[fwd.PathLen] = byte(pkt.SNR)
	}
	fwd.PathLen++

	// Mark the forwarded packet as seen (TRACE dedup includes PathLen in
	// the hash, so the forwarded packet has a different hash than the received one)
	r.dedup.HasSeen(fwd)

	r.enqueue(fwd, PriorityTrace, 0, src, false)
}
