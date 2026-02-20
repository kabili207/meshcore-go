package room

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
)

const defaultVersion = "meshcore-go"

// handleCLICommand processes a CLI command from an admin client and sends the
// reply as an encrypted TXT_MSG with TxtTypeCLI. The firmware does NOT send
// an ACK for CLI commands — only the text reply.
func (s *Server) handleCLICommand(pkt *codec.Packet, senderID core.MeshCoreID, secret []byte, content *codec.TxtMsgContent) {
	s.log.Debug("cli command",
		"peer", senderID.String(),
		"cmd", content.Message)

	reply := s.executeCLI(content.Message)
	if reply == "" {
		return
	}
	s.sendCLIReply(pkt, senderID, secret, reply)
}

// executeCLI dispatches a CLI command string and returns the reply text.
// Returns "" for no reply.
func (s *Server) executeCLI(cmd string) string {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	switch parts[0] {
	case "clock":
		return s.cliClock(parts[1:])
	case "ver":
		return s.cliVer()
	case "get":
		if len(parts) < 2 {
			return "??: (missing key)"
		}
		return s.cliGet(parts[1])
	case "set":
		if len(parts) < 3 {
			return "Error: missing value"
		}
		return s.cliSet(parts[1], strings.Join(parts[2:], " "))
	case "setperm":
		return s.cliSetPerm(parts[1:])
	case "clear":
		if len(parts) >= 2 && parts[1] == "stats" {
			return s.cliClearStats()
		}
		return "Unknown command"
	default:
		if s.cfg.CLIHandler != nil {
			return s.cfg.CLIHandler(cmd)
		}
		return "Unknown command"
	}
}

// sendCLIReply sends a CLI reply text message to the client.
func (s *Server) sendCLIReply(origPkt *codec.Packet, recipientID core.MeshCoreID, secret []byte, reply string) {
	nowTS := s.cfg.Clock.GetCurrentTime()
	content := codec.BuildTxtMsgContent(nowTS, codec.TxtTypeCLI, 0, reply, nil)
	s.sendEncryptedResponse(origPkt, recipientID, secret, codec.PayloadTypeTxtMsg, content)
}

// --- Individual command implementations ---

func (s *Server) cliClock(args []string) string {
	if len(args) > 0 && args[0] == "sync" {
		// Clock sync is handled by the caller if needed; here we just
		// report the time after any sync.
		return "OK"
	}
	// Return current time as "HH:MM - DD/MM/YYYY UTC"
	t := time.Unix(int64(s.cfg.Clock.GetCurrentTime()), 0).UTC()
	return fmt.Sprintf("%02d:%02d - %02d/%02d/%04d UTC",
		t.Hour(), t.Minute(), t.Day(), t.Month(), t.Year())
}

func (s *Server) cliVer() string {
	if s.cfg.Version != "" {
		return s.cfg.Version
	}
	return defaultVersion
}

func (s *Server) cliGet(key string) string {
	switch key {
	case "name":
		return s.cfg.Name
	case "guest.password":
		return s.cfg.GuestPassword
	case "allow.read.only":
		if s.cfg.AllowReadOnly {
			return "on"
		}
		return "off"
	case "public.key":
		return hex.EncodeToString(s.cfg.PublicKey[:])
	case "role":
		return "room_server"
	default:
		return "??: " + key
	}
}

func (s *Server) cliSet(key, value string) string {
	switch key {
	case "name":
		s.mu.Lock()
		s.cfg.Name = value
		s.mu.Unlock()
		return "OK"
	case "guest.password":
		s.mu.Lock()
		s.cfg.GuestPassword = value
		s.mu.Unlock()
		return "OK"
	case "allow.read.only":
		switch value {
		case "on":
			s.mu.Lock()
			s.cfg.AllowReadOnly = true
			s.mu.Unlock()
			return "OK"
		case "off":
			s.mu.Lock()
			s.cfg.AllowReadOnly = false
			s.mu.Unlock()
			return "OK"
		default:
			return "Error: expected on/off"
		}
	default:
		return "??: " + key
	}
}

func (s *Server) cliSetPerm(args []string) string {
	if len(args) < 2 {
		return "Error: usage: setperm <pubkey-hex> <permissions>"
	}

	pubKeyHex := args[0]
	permStr := args[1]

	perm, err := strconv.ParseUint(permStr, 10, 8)
	if err != nil {
		return "Error: bad permissions value"
	}

	// Decode hex public key (may be truncated prefix)
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "ERR: bad pubkey"
	}
	if len(pubKeyBytes) == 0 {
		return "ERR: bad pubkey"
	}

	// Search for matching client by public key prefix
	var matched *ClientInfo
	s.cfg.Clients.ForEach(func(c *ClientInfo) bool {
		if matchesPubKeyPrefix(c.ID[:], pubKeyBytes) {
			matched = c
			return false
		}
		return true
	})

	if matched == nil {
		return "ERR: client not found"
	}

	matched.Permissions = uint8(perm)
	s.log.Info("permissions updated",
		"peer", matched.ID.String(),
		"perms", perm)
	return "OK"
}

// StatsResetter is an optional interface that StatsProviders can implement
// to support the "clear stats" CLI command.
type StatsResetter interface {
	ResetStats()
}

func (s *Server) cliClearStats() string {
	if s.cfg.Stats == nil {
		return "OK"
	}
	if resetter, ok := s.cfg.Stats.(StatsResetter); ok {
		resetter.ResetStats()
	}
	return "OK"
}

// matchesPubKeyPrefix returns true if fullKey starts with the given prefix.
func matchesPubKeyPrefix(fullKey, prefix []byte) bool {
	if len(prefix) > len(fullKey) {
		return false
	}
	for i, b := range prefix {
		if fullKey[i] != b {
			return false
		}
	}
	return true
}
