package companion

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/core/codec/serial"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/device/event"
)

// runCLICmd handles CMD_RUN_CLI_COMMAND: [cmd][ASCII command]. The reply is
// always RESP_CODE_CLI_REPLY, never OK or ERR.
func (s *Server) runCLICmd(ss *session, payload []byte) error {
	if len(payload) < 3 {
		return ss.send(serial.EncodeErr(serial.ErrCodeIllegalArg))
	}
	return ss.send(serial.EncodeCLIReply(s.runCLI(string(payload[1:]))))
}

// handleRemoteCLI runs a TXT_TYPE_CLI_COMMAND from a contact allowed to use the
// CLI and sends the reply back as TXT_TYPE_CLI, as firmware's onCLICommandRecv
// does. It reports false when the message should go to the app instead.
func (s *Server) handleRemoteCLI(e *event.TextMessageReceived) bool {
	if e.TxtType != serial.TxtTypeCLICommand || s.sendDM == nil {
		return false
	}
	ct := s.node.Contacts().GetByPubKey(e.From)
	if ct == nil || !ct.IsRemoteCLIAllowed() {
		return false
	}
	// TODO: firmware bumps the reply timestamp when it equals the command's, so
	// the app's CLI view keeps them apart. SendDM doesn't let us pick one.
	reply := s.runCLI(e.Message)
	if _, err := s.sendDM(context.Background(), e.From, reply, serial.TxtTypeCLI, 0, nil); err != nil {
		s.log.Warn("remote CLI reply failed", "to", e.From.String(), "error", err)
	}
	return true
}

// runCLI executes a companion CLI command line and returns the reply, matching
// the strings firmware's MyMesh::handleCommand produces. Radio and power
// commands that need hardware report "Unknown command", as firmware does for
// anything it doesn't handle.
func (s *Server) runCLI(command string) string {
	command = strings.TrimLeft(command, " ")
	// Optional "NN|" prefix the app uses to match replies to commands.
	prefix := ""
	if len(command) > 4 && command[2] == '|' {
		prefix, command = command[:3], command[3:]
	}
	reply, ok := s.cliCommand(command)
	if !ok {
		reply = "Unknown command"
	}
	return prefix + reply
}

func (s *Server) cliCommand(command string) (string, bool) {
	switch {
	case strings.HasPrefix(command, "set name "):
		name := command[len("set name "):]
		if !codec.IsValidAdvertName(name) {
			return "Error, bad chars", true
		}
		s.setName(name)
		return "OK", true
	case command == "get name":
		s.mu.RLock()
		defer s.mu.RUnlock()
		return "> " + s.name, true

	case command == "board":
		return s.id.Manufacturer, true
	case command == "ver":
		return cli.FormatVersion(s.id.FirmwareVersion, s.id.BuildDate), true

	case command == "get tz.offset":
		s.mu.RLock()
		defer s.mu.RUnlock()
		return fmt.Sprintf("> %d", s.tzOffset), true
	case strings.HasPrefix(command, "set tz.offset "):
		// Firmware parses with atof and truncates toward zero.
		v, err := strconv.ParseFloat(strings.TrimSpace(command[len("set tz.offset "):]), 64)
		tz := math.Trunc(v)
		if err != nil || tz < -12 || tz > 14 {
			return "Error, must be from -12 to +14", true
		}
		s.mu.Lock()
		s.tzOffset = int8(tz)
		s.mu.Unlock()
		return "OK", true

	case command == "get radio":
		s.mu.RLock()
		defer s.mu.RUnlock()
		return fmt.Sprintf("> %s,%s,%d,%d",
			cli.Ftoa(float32(s.radioFreqKHz)/1000), cli.Ftoa(float32(s.radioBwHz)/1000),
			s.radioSF, s.radioCR), true
	case command == "get freq":
		s.mu.RLock()
		defer s.mu.RUnlock()
		return "> " + cli.Ftoa(float32(s.radioFreqKHz)/1000), true
	case command == "get tx" || strings.HasPrefix(command, "get tx "):
		s.mu.RLock()
		defer s.mu.RUnlock()
		return fmt.Sprintf("> %d", s.txPower), true
	}
	return "", false
}
