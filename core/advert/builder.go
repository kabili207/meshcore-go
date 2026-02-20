// Package advert provides ADVERT creation and scheduling for MeshCore networks.
//
// BuildSelfAdvert creates a signed self-advertisement packet suitable for
// broadcasting over the mesh. The Scheduler manages periodic local (zero-hop)
// and flood advertisement timers.
//
// This corresponds to the firmware's createSelfAdvert() and the advertisement
// timer logic in MyMesh.
package advert

import (
	"crypto/ed25519"
	"fmt"

	"github.com/kabili207/meshcore-go/core/clock"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// SelfAdvertConfig describes the local node's identity and advertisement data.
type SelfAdvertConfig struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  [32]byte
	Clock     *clock.Clock
	AppData   *codec.AdvertAppData // Name, NodeType, GPS, etc.
}

// AdvertBuilder is a function that creates a self-ADVERT packet.
// The scheduler calls this to get a fresh packet each time it needs to send.
// Returns nil if the packet could not be created.
type AdvertBuilder func() *codec.Packet

// BuildSelfAdvert creates a signed ADVERT packet for this node.
// The timestamp is obtained from the clock, the payload is signed with
// the node's Ed25519 private key, and the result is a fully formed
// codec.Packet ready for SendFlood or SendZeroHop.
func BuildSelfAdvert(cfg *SelfAdvertConfig) (*codec.Packet, error) {
	timestamp := cfg.Clock.GetCurrentTime()

	appDataBytes := codec.BuildAdvertAppData(cfg.AppData)

	sig, err := crypto.SignAdvert(cfg.PrivateKey, cfg.PublicKey, timestamp, appDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign advert: %w", err)
	}

	payload := codec.BuildAdvertPayload(cfg.PublicKey, timestamp, sig, cfg.AppData)

	pkt := &codec.Packet{
		Header:  codec.PayloadTypeAdvert << codec.PHTypeShift,
		Payload: payload,
	}

	return pkt, nil
}

// NewSelfAdvertBuilder returns an AdvertBuilder function that captures the
// node's identity and configuration. Each call produces a fresh ADVERT with
// a current timestamp.
func NewSelfAdvertBuilder(cfg *SelfAdvertConfig) AdvertBuilder {
	return func() *codec.Packet {
		pkt, _ := BuildSelfAdvert(cfg)
		return pkt
	}
}
