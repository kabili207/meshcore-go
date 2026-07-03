package node

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
)

// telemPermBase is the firmware TELEM_PERM_BASE permission bit.
const telemPermBase = 0x01

// ResetPath forgets the known direct path to a contact, forcing the next send to
// flood and rediscover the route (firmware resetPathTo / CMD_RESET_PATH).
func (n *CompanionNode) ResetPath(to core.MeshCoreID) {
	if ct := n.base.Contacts().GetByPubKey(to); ct != nil {
		ct.OutPathLen = contact.PathUnknown
	}
}

// SendPathDiscovery re-establishes the direct path to a contact by sending a
// base-telemetry request over flood: the flooded request draws a PATH return
// that updates the contact's out_path. Firmware models this as a forced-flood
// telemetry request (CMD_SEND_PATH_DISCOVERY_REQ).
func (n *CompanionNode) SendPathDiscovery(to core.MeshCoreID) error {
	secret, err := n.base.Contacts().GetSharedSecret(to)
	if err != nil {
		return fmt.Errorf("shared secret: %w", err)
	}

	tag := n.clk.GetCurrentTimeUnique()
	// Request data: inverse permission mask (base only) + 3 reserved bytes + a
	// random blob to keep the packet hash unique across retries.
	reqData := make([]byte, 8)
	reqData[0] = ^uint8(telemPermBase)
	_, _ = rand.Read(reqData[4:8])
	content := codec.BuildRequestContent(tag, codec.ReqTypeGetTelemetry, reqData)

	encrypted, err := crypto.EncryptAddressedWithSecret(content, secret)
	if err != nil {
		return fmt.Errorf("encrypt path discovery: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	selfID := n.base.ID()
	payload := codec.BuildAddressedPayload(to.Hash(), selfID.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeReq, codec.RouteTypeFlood, payload)
	// Always flood, even if a (possibly stale) direct path is known.
	n.base.Router.SendFloodScoped(pkt)
	return nil
}

// SendTrace broadcasts a TRACE along the given relay-hash route, collecting the
// per-hop SNR. When the trace returns it is delivered as a TraceReceived event
// (matched by the returned tag). flags encodes the relay hash size in its lower
// two bits; path is the concatenated relay hashes of the round trip.
func (n *CompanionNode) SendTrace(authCode uint32, flags uint8, path []byte) (uint32, error) {
	var tagBytes [4]byte
	if _, err := rand.Read(tagBytes[:]); err != nil {
		return 0, err
	}
	tag := binary.LittleEndian.Uint32(tagBytes[:])

	payload := codec.BuildTracePayload(tag, authCode, flags, path)
	pkt := codec.NewPacket(codec.PayloadTypeTrace, codec.RouteTypeDirect, payload)
	n.base.Router.SendTrace(pkt)
	return tag, nil
}
