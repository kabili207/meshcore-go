package node

import (
	"context"
	"fmt"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/ack"
)

// SendOption configures optional behavior for SendText.
type SendOption func(*sendOptions)

type sendOptions struct {
	txtType    uint8
	attempt    uint8
	onACK      func()
	onTimeout  func()
	maxChunks  int
	chunkDelay time.Duration
}

func defaultSendOptions() sendOptions {
	return sendOptions{
		txtType:    codec.TxtTypePlain,
		attempt:    0,
		maxChunks:  1,
		chunkDelay: 500 * time.Millisecond,
	}
}

// WithTxtType sets the text message type. Default: TxtTypePlain.
// Use codec.TxtTypeCLI for room server CLI commands.
func WithTxtType(t uint8) SendOption {
	return func(o *sendOptions) { o.txtType = t }
}

// WithAttempt sets the retry attempt number (0-3). Default: 0.
func WithAttempt(a uint8) SendOption {
	return func(o *sendOptions) { o.attempt = a }
}

// WithOnACK sets a callback invoked when the message is acknowledged.
func WithOnACK(fn func()) SendOption {
	return func(o *sendOptions) { o.onACK = fn }
}

// WithOnTimeout sets a callback invoked when the message times out.
func WithOnTimeout(fn func()) SendOption {
	return func(o *sendOptions) { o.onTimeout = fn }
}

// WithMaxChunks sets the maximum number of chunks for long messages.
// Default: 1 (no chunking). Set to 3 for BBS-style multi-chunk replies.
func WithMaxChunks(n int) SendOption {
	return func(o *sendOptions) { o.maxChunks = n }
}

// WithChunkDelay sets the delay between sending chunks. Default: 500ms.
func WithChunkDelay(d time.Duration) SendOption {
	return func(o *sendOptions) { o.chunkDelay = d }
}

// SendText encrypts and sends a text message to a peer. Long messages are
// automatically split into chunks up to MaxChunks. Each chunk is a separate
// radio transmission with TxtTypePlain (default).
//
// The method handles: shared secret lookup, plaintext construction, encryption,
// addressed payload building, header construction, and routing (direct if path
// known, flood otherwise).
func (n *CompanionNode) SendText(ctx context.Context, to core.MeshCoreID, message string, opts ...SendOption) error {
	o := defaultSendOptions()
	for _, fn := range opts {
		fn(&o)
	}

	chunks := splitMessage(message, codec.MaxTextLen)
	if len(chunks) > o.maxChunks {
		chunks = chunks[:o.maxChunks]
		last := chunks[o.maxChunks-1]
		const indicator = "\n[truncated]"
		if len(last)+len(indicator) <= codec.MaxTextLen {
			chunks[o.maxChunks-1] = last + indicator
		}
	}

	for i, chunk := range chunks {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(o.chunkDelay):
			}
		}
		if err := n.sendTextChunk(to, chunk, o); err != nil {
			return err
		}
	}
	return nil
}

// sendTextChunk sends a single text message chunk.
func (n *CompanionNode) sendTextChunk(to core.MeshCoreID, message string, o sendOptions) error {
	secret, err := n.base.contacts.GetSharedSecret(to)
	if err != nil {
		return fmt.Errorf("get shared secret for %s: %w", to, err)
	}

	plaintext := codec.BuildTxtMsgContent(
		n.clk.GetCurrentTime(),
		o.txtType,
		o.attempt,
		message,
		nil,
	)

	encrypted, err := crypto.EncryptAddressedWithSecret(plaintext, secret)
	if err != nil {
		return fmt.Errorf("encrypt message: %w", err)
	}

	mac, ciphertext := codec.SplitMAC(encrypted)
	payload := codec.BuildAddressedPayload(to.Hash(), n.base.id.Hash(), mac, ciphertext)
	pkt := codec.NewPacket(codec.PayloadTypeTxtMsg, codec.RouteTypeFlood, payload)

	ct := n.base.contacts.GetByPubKey(to)
	if ct != nil && ct.HasDirectPath() {
		n.base.Router.SendDirect(pkt, ct.OutPath[:ct.OutPathLen])
	} else {
		n.base.Router.SendFlood(pkt)
	}

	// Track ACK if callbacks are provided
	if o.onACK != nil || o.onTimeout != nil {
		ackData := codec.TrimTxtMsgContent(plaintext, &codec.TxtMsgContent{
			TxtType: o.txtType,
			Message: message,
		})
		ackHash := crypto.ComputeAckHash(ackData, to[:])
		n.ackTracker.Track(ackHash, ack.PendingACK{
			OnACK:     o.onACK,
			OnTimeout: o.onTimeout,
		})
	}

	n.log.Debug("sent text",
		"to", to.String()[:16],
		"len", len(message),
		"type", codec.TxtTypeName(o.txtType))

	return nil
}

// splitMessage breaks a message into chunks that fit within the DM size limit.
// Splits on newline boundaries when possible, otherwise at the byte limit.
func splitMessage(msg string, maxLen int) []string {
	if len(msg) <= maxLen {
		return []string{msg}
	}

	var chunks []string
	for len(msg) > 0 {
		if len(msg) <= maxLen {
			chunks = append(chunks, msg)
			break
		}

		cut := maxLen
		for i := cut - 1; i > 0; i-- {
			if msg[i] == '\n' {
				cut = i + 1
				break
			}
		}

		chunks = append(chunks, msg[:cut])
		msg = msg[cut:]
	}
	return chunks
}
