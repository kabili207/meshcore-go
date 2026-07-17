package console

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
)

// --- MeshMonitor client simulation ------------------------------------------
//
// These mirror MeshMonitor's meshcore serial backend so the tests fail if our
// framing drifts from what it actually parses.

var (
	// Completion tokens MeshMonitor scans each reply line for.
	completionTokens = []string{"-> >", "OK", "Error", "Unknown command"}
	// "get name" parser.
	nameRe = regexp.MustCompile(`->\s*>\s*(.+)`)
	// "get radio" parser: freq,bw,sf,cr.
	radioRe = regexp.MustCompile(`(\d+\.?\d*),\s*(\d+\.?\d*),\s*(\d+),\s*(\d+)`)
)

// collectReply consumes framed output the way MeshMonitor does: split on '\n',
// strip '\r', drop the first line equal to the echoed command, then accumulate
// until a line carries a completion token. Returns the joined reply and whether
// completion was reached (false means MeshMonitor would have hit its timeout).
func collectReply(command, framed string) (reply string, completed bool) {
	echoSeen := false
	var lines []string
	for _, raw := range strings.Split(framed, "\n") {
		line := strings.TrimRight(raw, "\r")
		if !echoSeen && strings.TrimSpace(line) == command {
			echoSeen = true
			continue
		}
		lines = append(lines, line)
		for _, tok := range completionTokens {
			if strings.Contains(line, tok) {
				return strings.Join(lines, "\n"), true
			}
		}
	}
	return strings.Join(lines, "\n"), false
}

func TestFormatGetNameParses(t *testing.T) {
	framed := string(format("get name", "MyRepeater"))

	reply, completed := collectReply("get name", framed)
	if !completed {
		t.Fatalf("MeshMonitor would time out; framed=%q", framed)
	}
	m := nameRe.FindStringSubmatch(reply)
	if m == nil {
		t.Fatalf("name regex did not match reply %q", reply)
	}
	if m[1] != "MyRepeater" {
		t.Errorf("parsed name = %q, want %q", m[1], "MyRepeater")
	}
}

func TestFormatMultiLineNotTruncated(t *testing.T) {
	// Two neighbor lines (like cliNeighbors) joined with LF. Neither carries a
	// completion token, so the body must survive intact and complete only on
	// the trailing prompt.
	reply := "aabbccddeeff snr=5.00\n001122334455 snr=3.25"
	framed := string(format("neighbors", reply))

	got, completed := collectReply("neighbors", framed)
	if !completed {
		t.Fatalf("multi-line reply never completed; framed=%q", framed)
	}
	for _, want := range []string{"aabbccddeeff snr=5.00", "001122334455 snr=3.25"} {
		if !strings.Contains(got, want) {
			t.Errorf("collected reply %q missing line %q", got, want)
		}
	}
}

func TestFormatSetOKCompletes(t *testing.T) {
	framed := string(format("set name Foo", "OK"))
	if _, completed := collectReply("set name Foo", framed); !completed {
		t.Fatalf("set reply did not complete; framed=%q", framed)
	}
}

func TestFormatUnknownKeyCompletes(t *testing.T) {
	// "??: radio" carries no token on its own, so single-line framing must add
	// the prompt or MeshMonitor hangs.
	framed := string(format("get radio", "??: radio"))
	if _, completed := collectReply("get radio", framed); !completed {
		t.Fatalf("unknown-key reply did not complete; framed=%q", framed)
	}
}

func TestFormatEmptyReplyIsPromptOnly(t *testing.T) {
	framed := string(format("advert", ""))
	if _, completed := collectReply("advert", framed); !completed {
		t.Fatalf("empty reply did not complete; framed=%q", framed)
	}
}

func TestRadioInterceptGetParses(t *testing.T) {
	s := NewServer(Config{
		Run:   func(string) string { return "??: radio" }, // node would 404 it
		Radio: &RadioConfig{Freq: 915.0, BW: 250, SF: 10, CR: 5},
	})

	framed := string(s.handle("get radio"))
	reply, completed := collectReply("get radio", framed)
	if !completed {
		t.Fatalf("radio reply did not complete; framed=%q", framed)
	}
	m := radioRe.FindStringSubmatch(reply)
	if m == nil {
		t.Fatalf("radio regex did not match reply %q", reply)
	}
	if m[1] != "915" || m[2] != "250" || m[3] != "10" || m[4] != "5" {
		t.Errorf("parsed radio = %v, want 915/250/10/5", m[1:])
	}
}

func TestRadioInterceptSet(t *testing.T) {
	rc := &RadioConfig{Freq: 915.0, BW: 250, SF: 10, CR: 5}
	s := NewServer(Config{
		Run:   func(string) string { t.Fatal("set radio should not reach Run"); return "" },
		Radio: rc,
	})

	if reply := s.runCommand("set radio 868.0,125,9,6"); reply != "OK" {
		t.Fatalf("set radio reply = %q, want OK", reply)
	}
	if rc.Freq != 868.0 || rc.BW != 125 || rc.SF != 9 || rc.CR != 6 {
		t.Errorf("radio not updated: %+v", rc)
	}
}

func TestRadioPassthroughWhenUnset(t *testing.T) {
	called := false
	s := NewServer(Config{Run: func(cmd string) string {
		called = true
		return "??: radio"
	}})
	s.runCommand("get radio")
	if !called {
		t.Error("get radio should fall through to Run when Radio is unset")
	}
}

// rw adapts separate reader/writer into an io.ReadWriter for Serve.
type rw struct {
	io.Reader
	io.Writer
}

func TestServeWakeThenCommand(t *testing.T) {
	// A lone CR wake, then a command, both CR-terminated as MeshMonitor sends.
	in := strings.NewReader("\rget name\r")
	var out bytes.Buffer

	err := NewServer(Config{Run: func(cmd string) string {
		if cmd == "get name" {
			return "NodeX"
		}
		return "Unknown command"
	}}).Serve(context.Background(), rw{in, &out})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}

	// The wake produces a bare prompt; the command produces echo + value.
	if !strings.HasPrefix(out.String(), promptLine) {
		t.Errorf("wake did not emit a leading prompt; out=%q", out.String())
	}
	reply, completed := collectReply("get name", strings.TrimPrefix(out.String(), promptLine))
	if !completed {
		t.Fatalf("command reply did not complete; out=%q", out.String())
	}
	if m := nameRe.FindStringSubmatch(reply); m == nil || m[1] != "NodeX" {
		t.Errorf("parsed name from %q = %v, want NodeX", reply, m)
	}
}
