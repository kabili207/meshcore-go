// Package console serves a node's text CLI over a byte stream (a serial line,
// pty, or TCP socket) in the exact shape MeshMonitor's direct-repeater serial
// backend expects. It bridges an incoming CLI command line to a node's
// dispatcher (via a Runner) and frames the reply so MeshMonitor's parser
// accepts it.
//
// MeshMonitor's contract (from its meshcore serial backend):
//   - Commands arrive as UTF-8 text terminated by a single CR ('\r'), no prefix.
//   - It expects the device to echo the command back as the first reply line.
//   - It splits replies on LF ('\n') and accumulates lines until one contains a
//     completion token: "-> >", "OK", "Error", or "Unknown command". If none
//     appears it waits out a multi-second timeout, so every reply must end with
//     one.
//   - It parses "get name" with /->\s*>\s*(.+)/ and "get radio" as four
//     comma-separated numbers, so those values must sit on a "-> >" line.
//
// meshcore-go's dispatcher returns bare values ("MyRepeater"), plain tokens
// ("OK", "Unknown command", "??: key"), and multi-line bodies joined with LF.
// It never emits the "-> >" prompt. This adapter supplies that framing:
//   - single-line replies become "-> > <reply>" (value carried on the prompt
//     line so both parsing and completion work);
//   - multi-line replies are sent verbatim, then a lone "-> > " prompt line
//     terminates them (the token must be the last line, or MeshMonitor would
//     truncate the body at the first line that contains it).
//
// The repeater CLI has no radio config key, but MeshMonitor issues "get radio"
// during its initial sync. Set Config.Radio to answer "get radio"/"set radio"
// from the adapter instead of falling through to a "??: radio" reply.
package console

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

// promptLine is MeshMonitor's completion token, emitted as its own CRLF line.
const promptLine = "-> > \r\n"

// Runner executes a raw CLI command line and returns the reply text. Wire it to
// a node's dispatcher, e.g. (*node.RepeaterNode).ExecuteCLI.
type Runner func(cmd string) string

// RadioConfig answers MeshMonitor's "get radio" / "set radio" for roles (like
// the repeater) whose CLI has no radio key. The stored values are reported back
// verbatim; the adapter does not apply them to any real radio.
type RadioConfig struct {
	Freq float64 // MHz
	BW   float64 // kHz
	SF   int     // spreading factor
	CR   int     // coding rate
}

// String renders the "<freq>,<bw>,<sf>,<cr>" form MeshMonitor parses.
func (r RadioConfig) String() string {
	return fmt.Sprintf("%g,%g,%d,%d", r.Freq, r.BW, r.SF, r.CR)
}

func (r *RadioConfig) parse(s string) error {
	f := strings.Split(s, ",")
	if len(f) != 4 {
		return errors.New("expected freq,bw,sf,cr")
	}
	freq, err := strconv.ParseFloat(strings.TrimSpace(f[0]), 64)
	if err != nil {
		return errors.New("bad freq")
	}
	bw, err := strconv.ParseFloat(strings.TrimSpace(f[1]), 64)
	if err != nil {
		return errors.New("bad bw")
	}
	sf, err := strconv.Atoi(strings.TrimSpace(f[2]))
	if err != nil {
		return errors.New("bad sf")
	}
	cr, err := strconv.Atoi(strings.TrimSpace(f[3]))
	if err != nil {
		return errors.New("bad cr")
	}
	r.Freq, r.BW, r.SF, r.CR = freq, bw, sf, cr
	return nil
}

// Config configures a Server.
type Config struct {
	// Run executes a CLI command line. Required.
	Run Runner

	// Radio, if set, answers "get radio" / "set radio" locally so MeshMonitor's
	// initial sync succeeds on roles whose CLI has no radio key.
	Radio *RadioConfig

	// Logger for connection events. Falls back to slog.Default() if nil.
	Logger *slog.Logger
}

// Server bridges a byte stream to a node's CLI in MeshMonitor's expected format.
type Server struct {
	run   Runner
	radio *RadioConfig
	log   *slog.Logger
}

// NewServer builds a Server. It panics if cfg.Run is nil.
func NewServer(cfg Config) *Server {
	if cfg.Run == nil {
		panic("console: Config.Run is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Server{run: cfg.Run, radio: cfg.Radio, log: log.WithGroup("console")}
}

// Serve runs the CLI loop over rw until the stream closes or ctx is cancelled.
// Commands are handled one at a time, so a single Serve never calls Run
// concurrently. For a real serial device, pass the opened port (115200 8-N-1,
// no flow control); for a pty, pass the master; for TCP, use ListenAndServe.
//
// A blocking read is only interrupted by ctx if rw is an io.Closer that another
// goroutine closes; ListenAndServe wires that up for accepted connections.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	r := bufio.NewReader(rw)
	for {
		// MeshMonitor terminates commands with a bare CR.
		line, err := r.ReadString('\r')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		cmd := strings.Trim(line, "\r\n \t")
		if _, err := rw.Write(s.handle(cmd)); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}

// ListenAndServe accepts TCP connections on addr and serves each with Serve. It
// blocks until ctx is cancelled (which closes the listener and open
// connections) or Accept fails. Use this when MeshMonitor connects over TCP
// rather than a serial device.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	s.log.Info("console listening", "addr", ln.Addr().String())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func() {
			defer conn.Close()
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-stop:
				}
			}()
			if err := s.Serve(ctx, conn); err != nil && ctx.Err() == nil {
				s.log.Debug("console connection ended", "error", err)
			}
		}()
	}
}

// handle turns one received command line into the bytes to write back.
func (s *Server) handle(cmd string) []byte {
	if cmd == "" {
		// A lone CR (MeshMonitor's connect-time wake) or blank line: just a
		// prompt, no echo.
		return []byte(promptLine)
	}
	return format(cmd, s.runCommand(cmd))
}

// runCommand intercepts radio when configured, otherwise defers to the node.
func (s *Server) runCommand(cmd string) string {
	if s.radio != nil {
		switch {
		case cmd == "get radio":
			return s.radio.String()
		case strings.HasPrefix(cmd, "set radio "):
			if err := s.radio.parse(strings.TrimPrefix(cmd, "set radio ")); err != nil {
				return "Error: " + err.Error()
			}
			return "OK"
		}
	}
	return s.run(cmd)
}

// format frames an echo + reply the way MeshMonitor's parser expects. It is the
// pure core of the adapter, kept separate so it can be tested without I/O.
func format(cmd, reply string) []byte {
	var b strings.Builder
	b.WriteString(cmd) // echo; MeshMonitor drops the first line equal to the command
	b.WriteString("\r\n")

	if reply == "" {
		b.WriteString(promptLine)
		return []byte(b.String())
	}

	lines := strings.Split(reply, "\n")
	if len(lines) == 1 {
		// Carry the value on the prompt line: satisfies the "get name"/"get
		// radio" regexes and the completion token in one line.
		b.WriteString("-> > ")
		b.WriteString(lines[0])
		b.WriteString("\r\n")
		return []byte(b.String())
	}

	// Multi-line body first, completion prompt last, so MeshMonitor doesn't
	// truncate the body at the first line carrying the token.
	for _, ln := range lines {
		b.WriteString(strings.TrimRight(ln, "\r"))
		b.WriteString("\r\n")
	}
	b.WriteString(promptLine)
	return []byte(b.String())
}
