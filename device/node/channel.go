package node

import (
	"bytes"
	"fmt"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// AddChannel registers a group channel by its pre-shared key and returns the
// channel hash (first byte of SHA256(key)). GRP_TXT/GRP_DATA messages on this
// channel are decrypted and delivered as GroupTextReceived / GroupDataReceived
// events. Multiple channels may share a hash; all their keys are kept and tried
// on decode. Registering the same key twice is a no-op.
func (b *BaseNode) AddChannel(key []byte) uint8 {
	hash := crypto.ComputeChannelHash(key)
	b.channelMu.Lock()
	defer b.channelMu.Unlock()
	if b.channels == nil {
		b.channels = make(map[uint8][][]byte)
	}
	for _, k := range b.channels[hash] {
		if bytes.Equal(k, key) {
			return hash // already registered
		}
	}
	b.channels[hash] = append(b.channels[hash], append([]byte(nil), key...))
	return hash
}

// RemoveChannel forgets the channel with the given key. Other channels sharing
// the same hash are left intact.
func (b *BaseNode) RemoveChannel(key []byte) {
	hash := crypto.ComputeChannelHash(key)
	b.channelMu.Lock()
	defer b.channelMu.Unlock()
	keys := b.channels[hash]
	for i, k := range keys {
		if bytes.Equal(k, key) {
			b.channels[hash] = append(keys[:i], keys[i+1:]...)
			if len(b.channels[hash]) == 0 {
				delete(b.channels, hash)
			}
			return
		}
	}
}

// channelKeys returns a snapshot of the keys registered under a channel hash.
// The returned slice is a copy; the keys themselves are never mutated in place.
func (b *BaseNode) channelKeys(hash uint8) [][]byte {
	b.channelMu.RLock()
	defer b.channelMu.RUnlock()
	keys := b.channels[hash]
	if len(keys) == 0 {
		return nil
	}
	out := make([][]byte, len(keys))
	copy(out, keys)
	return out
}

// SendChannelText sends a plain group text message on the channel identified by
// key. The text is sent as-is; callers that want firmware-style attribution
// should format it as "name: message". The channel need not be registered.
func (b *BaseNode) SendChannelText(key []byte, text string) error {
	hash := crypto.ComputeChannelHash(key)
	plaintext := crypto.BuildGrpTxtPlaintext(b.clock.GetCurrentTime(), text)
	return b.sendGroup(codec.PayloadTypeGrpTxt, hash, key, plaintext)
}

// SendChannelData sends a binary group datagram on the channel identified by key.
// The channel need not be registered.
func (b *BaseNode) SendChannelData(key []byte, dataType uint16, data []byte) error {
	hash := crypto.ComputeChannelHash(key)
	plaintext := crypto.BuildGrpDataPlaintext(dataType, data)
	return b.sendGroup(codec.PayloadTypeGrpData, hash, key, plaintext)
}

// sendGroup encrypts a group plaintext with the channel key and floods it.
func (b *BaseNode) sendGroup(payloadType, channelHash uint8, key, plaintext []byte) error {
	encrypted, err := crypto.EncryptGroupMessage(plaintext, key)
	if err != nil {
		return fmt.Errorf("encrypt group message: %w", err)
	}
	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildGroupPayload(channelHash, mac, ciphertext)
	pkt := codec.NewPacket(payloadType, codec.RouteTypeFlood, payload)
	b.Router.SendFloodScoped(pkt)
	return nil
}
