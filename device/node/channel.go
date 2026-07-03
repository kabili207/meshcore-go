package node

import (
	"fmt"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
)

// AddChannel registers a group channel by its pre-shared key and returns the
// channel hash (first byte of SHA256(key)). GRP_TXT/GRP_DATA messages on this
// channel are decrypted and delivered as GroupTextReceived / GroupDataReceived
// events. Registering the same channel again replaces the key.
func (b *BaseNode) AddChannel(key []byte) uint8 {
	hash := crypto.ComputeChannelHash(key)
	b.channelMu.Lock()
	if b.channels == nil {
		b.channels = make(map[uint8][]byte)
	}
	b.channels[hash] = append([]byte(nil), key...)
	b.channelMu.Unlock()
	return hash
}

// RemoveChannel forgets the channel with the given hash.
func (b *BaseNode) RemoveChannel(hash uint8) {
	b.channelMu.Lock()
	delete(b.channels, hash)
	b.channelMu.Unlock()
}

// channelKey returns the shared key registered for a channel hash, or nil.
func (b *BaseNode) channelKey(hash uint8) []byte {
	b.channelMu.RLock()
	defer b.channelMu.RUnlock()
	return b.channels[hash]
}

// SendChannelText sends a plain group text message on a registered channel.
// The text is sent as-is; callers that want firmware-style attribution should
// format it as "name: message". Returns an error if the channel is unknown.
func (b *BaseNode) SendChannelText(channelHash uint8, text string) error {
	key := b.channelKey(channelHash)
	if key == nil {
		return fmt.Errorf("unknown channel 0x%02x", channelHash)
	}
	plaintext := crypto.BuildGrpTxtPlaintext(b.clock.GetCurrentTime(), text)
	return b.sendGroup(codec.PayloadTypeGrpTxt, channelHash, key, plaintext)
}

// SendChannelData sends a binary group datagram on a registered channel.
func (b *BaseNode) SendChannelData(channelHash uint8, dataType uint16, data []byte) error {
	key := b.channelKey(channelHash)
	if key == nil {
		return fmt.Errorf("unknown channel 0x%02x", channelHash)
	}
	plaintext := crypto.BuildGrpDataPlaintext(dataType, data)
	return b.sendGroup(codec.PayloadTypeGrpData, channelHash, key, plaintext)
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
