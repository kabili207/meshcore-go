package node

import (
	"context"
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/crypto"
	"github.com/kabili207/meshcore-go/device/contact"
)

func TestSplitMessage_Short(t *testing.T) {
	msg := "hello"
	chunks := splitMessage(msg, codec.MaxTextLen)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0] != msg {
		t.Errorf("expected %q, got %q", msg, chunks[0])
	}
}

func TestSplitMessage_ExactLimit(t *testing.T) {
	msg := make([]byte, codec.MaxTextLen)
	for i := range msg {
		msg[i] = 'A'
	}
	chunks := splitMessage(string(msg), codec.MaxTextLen)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
}

func TestSplitMessage_SplitsOnNewline(t *testing.T) {
	// Build a message that exceeds MaxTextLen with newlines inside
	line := make([]byte, codec.MaxTextLen/2)
	for i := range line {
		line[i] = 'X'
	}
	msg := string(line) + "\n" + string(line) + "\nfinal"

	chunks := splitMessage(msg, codec.MaxTextLen)
	if len(chunks) < 2 {
		t.Fatalf("expected at least 2 chunks, got %d", len(chunks))
	}

	// First chunk should end at a newline boundary
	lastChar := chunks[0][len(chunks[0])-1]
	if lastChar != '\n' {
		t.Errorf("expected first chunk to end with newline, got %q", string(lastChar))
	}
}

func TestSplitMessage_NoNewline(t *testing.T) {
	// Long message with no newlines — must hard-cut at maxLen
	msg := make([]byte, codec.MaxTextLen+50)
	for i := range msg {
		msg[i] = 'B'
	}
	chunks := splitMessage(string(msg), codec.MaxTextLen)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != codec.MaxTextLen {
		t.Errorf("expected first chunk len %d, got %d", codec.MaxTextLen, len(chunks[0]))
	}
}

func TestSplitMessage_Empty(t *testing.T) {
	chunks := splitMessage("", codec.MaxTextLen)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0] != "" {
		t.Errorf("expected empty string, got %q", chunks[0])
	}
}

// Admin nodes treat a repeated sender timestamp as a retry and don't reply, so
// back-to-back CLI commands must carry distinct timestamps.
func TestSendText_CLITimestampsUnique(t *testing.T) {
	for _, txtType := range []uint8{codec.TxtTypeCLI, codec.TxtTypeCLICommand} {
		t.Run(codec.TxtTypeName(txtType), func(t *testing.T) {
			comp, ct := newTestCompanion(t)
			peer, _ := crypto.GenerateKeyPair()
			peerID := clientID(peer)
			if _, err := comp.base.Contacts().AddContact(&contact.ContactInfo{
				ID: peerID, Type: codec.NodeTypeRepeater, OutPathLen: contact.PathUnknown,
			}); err != nil {
				t.Fatal(err)
			}

			for _, cmd := range []string{"get name", "get role"} {
				if err := comp.SendText(context.Background(), peerID, cmd, WithTxtType(txtType)); err != nil {
					t.Fatal(err)
				}
			}

			compPub := comp.base.PublicKey()
			secret, err := crypto.ComputeSharedSecret(peer.PrivateKey, compPub[:])
			if err != nil {
				t.Fatal(err)
			}
			var stamps []uint32
			for _, p := range ct.sent {
				if p.PayloadType() != codec.PayloadTypeTxtMsg {
					continue
				}
				addr, err := codec.ParseAddressedPayload(p.Payload)
				if err != nil {
					t.Fatal(err)
				}
				pt, err := crypto.DecryptAddressedWithSecret(codec.PrependMAC(addr.MAC, addr.Ciphertext), secret)
				if err != nil {
					t.Fatal(err)
				}
				content, err := codec.ParseTxtMsgContent(pt)
				if err != nil {
					t.Fatal(err)
				}
				stamps = append(stamps, content.Timestamp)
			}
			if len(stamps) != 2 {
				t.Fatalf("captured %d text messages, want 2", len(stamps))
			}
			if stamps[0] == stamps[1] {
				t.Errorf("both CLI commands used timestamp %d", stamps[0])
			}
		})
	}
}
