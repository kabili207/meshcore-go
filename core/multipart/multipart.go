// Package multipart provides MULTIPART packet reassembly for MeshCore.
//
// MULTIPART packets split a logical payload across multiple radio packets.
// Each fragment contains a header byte encoding the remaining fragment count
// (upper 4 bits) and the inner payload type (lower 4 bits). Fragments arrive
// in order with the remaining count decrementing to 0 for the final fragment.
//
// Currently the firmware only uses MULTIPART for ACK packets, where each
// fragment carries a complete 4-byte ACK value (no actual splitting of data
// across fragments). The reassembler handles both this case and the general
// case of concatenating fragment data.
package multipart

import (
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
)

const (
	// DefaultTimeout is the default time to wait for all fragments before
	// discarding an incomplete reassembly.
	DefaultTimeout = 5 * time.Second
)

// Fragment represents a single MULTIPART fragment after parsing.
type Fragment struct {
	Remaining uint8  // Number of fragments still expected after this one
	InnerType uint8  // Payload type of the inner content
	Data      []byte // Fragment data (header byte stripped)
}

// ParseFragment extracts the multipart header from a MULTIPART packet payload.
func ParseFragment(payload []byte) (*Fragment, error) {
	mp, err := codec.ParseMultipartPayload(payload)
	if err != nil {
		return nil, err
	}
	return &Fragment{
		Remaining: mp.Remaining,
		InnerType: mp.InnerType,
		Data:      mp.Data,
	}, nil
}

// reassemblyKey identifies a group of related fragments.
type reassemblyKey struct {
	innerType uint8
	srcHash   uint8 // from the outer packet's path, to distinguish senders
}

type reassemblyState struct {
	fragments [][]byte
	expected  int // total fragment count (set from first fragment seen)
	startTime time.Time
}

// Reassembler collects MULTIPART fragments and emits complete payloads.
type Reassembler struct {
	pending map[reassemblyKey]*reassemblyState
	timeout time.Duration
}

// New creates a new Reassembler with the default timeout.
func New() *Reassembler {
	return NewWithTimeout(DefaultTimeout)
}

// NewWithTimeout creates a new Reassembler with the specified timeout.
func NewWithTimeout(timeout time.Duration) *Reassembler {
	return &Reassembler{
		pending: make(map[reassemblyKey]*reassemblyState),
		timeout: timeout,
	}
}

// HandleFragment processes a MULTIPART fragment. Returns a reassembled inner
// Packet if all fragments have been received, or nil if more are expected.
//
// srcHash should be derived from the outer packet (e.g. the first byte of the
// sender's path) to distinguish fragments from different senders.
func (r *Reassembler) HandleFragment(fragment *Fragment, srcHash uint8) *codec.Packet {
	r.expire()

	key := reassemblyKey{
		innerType: fragment.InnerType,
		srcHash:   srcHash,
	}

	state, exists := r.pending[key]
	if !exists {
		// First fragment in this group — remaining tells us how many more to expect
		total := int(fragment.Remaining) + 1
		state = &reassemblyState{
			fragments: make([][]byte, 0, total),
			expected:  total,
			startTime: time.Now(),
		}
		r.pending[key] = state
	}

	state.fragments = append(state.fragments, fragment.Data)

	if fragment.Remaining == 0 {
		// Final fragment received — assemble and return
		delete(r.pending, key)
		return r.assemble(fragment.InnerType, state)
	}

	return nil
}

func (r *Reassembler) assemble(innerType uint8, state *reassemblyState) *codec.Packet {
	// Concatenate all fragment data
	totalLen := 0
	for _, f := range state.fragments {
		totalLen += len(f)
	}

	payload := make([]byte, 0, totalLen)
	for _, f := range state.fragments {
		payload = append(payload, f...)
	}

	return &codec.Packet{
		Header:  (innerType << codec.PHTypeShift) | codec.RouteTypeFlood,
		Payload: payload,
	}
}

// expire removes timed-out reassembly states.
func (r *Reassembler) expire() {
	now := time.Now()
	for key, state := range r.pending {
		if now.Sub(state.startTime) > r.timeout {
			delete(r.pending, key)
		}
	}
}

// PendingCount returns the number of in-progress reassemblies.
func (r *Reassembler) PendingCount() int {
	return len(r.pending)
}

// Clear discards all in-progress reassemblies.
func (r *Reassembler) Clear() {
	clear(r.pending)
}
