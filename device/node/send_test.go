package node

import (
	"testing"

	"github.com/kabili207/meshcore-go/core/codec"
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
