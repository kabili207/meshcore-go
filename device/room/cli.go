package room

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kabili207/meshcore-go/core"
	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/router"
)

const defaultVersion = "meshcore-go"

func loopDetectName(level int) string {
	switch level {
	case router.LoopDetectOff:
		return "off"
	case router.LoopDetectMinimal:
		return "minimal"
	case router.LoopDetectModerate:
		return "moderate"
	case router.LoopDetectStrict:
		return "strict"
	default:
		return fmt.Sprintf("unknown(%d)", level)
	}
}

func parseLoopDetectLevel(s string) (int, bool) {
	switch strings.ToLower(s) {
	case "off", "0":
		return router.LoopDetectOff, true
	case "minimal", "1":
		return router.LoopDetectMinimal, true
	case "moderate", "2":
		return router.LoopDetectModerate, true
	case "strict", "3":
		return router.LoopDetectStrict, true
	default:
		return 0, false
	}
}

// handleCLICommand processes a CLI command from an admin client and sends the
// reply as an encrypted TXT_MSG with TxtTypeCLI. The firmware does NOT send
// an ACK for CLI commands — only the text reply.
func (s *Server) handleCLICommand(pkt *codec.Packet, senderID core.MeshCoreID, secret []byte, content *codec.TxtMsgContent) {
	cmd := content.Message

	// Strip optional companion radio prefix (e.g. "04|get name" → "get name").
	// The firmware reflects the prefix back in the reply so the app can correlate
	// command/response pairs.
	prefix := ""
	if len(cmd) > 4 && cmd[2] == '|' {
		prefix = cmd[:3]
		cmd = cmd[3:]
	}

	s.log.Debug("cli command",
		"peer", senderID.String(),
		"cmd", cmd)

	reply := s.executeCLI(cmd)
	if reply == "" {
		return
	}
	s.sendCLIReply(pkt, senderID, secret, prefix+reply)
}

// executeCLI dispatches a CLI command string and returns the reply text.
// Returns "" for no reply.
func (s *Server) executeCLI(cmd string) string {
	cmd = strings.TrimLeft(cmd, " ")
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
	case "region":
		return s.cliRegion(parts[1:])
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

// cliRegion handles "region ..." admin commands against the Router's RegionMap.
// Requires a RegionMap to be configured on the Router; "region save" persistence
// requires OnRegionsChanged. Edits assume packet handling is serialized (the
// RegionMap is not internally synchronized with the router's receive path).
func (s *Server) cliRegion(args []string) string {
	if s.cfg.Router == nil {
		return "Err - regions not enabled"
	}
	rm := s.cfg.Router.RegionMap()
	if rm == nil {
		return "Err - regions not enabled"
	}

	var save func() error
	if s.cfg.OnRegionsChanged != nil {
		save = func() error { return s.cfg.OnRegionsChanged(rm.MarshalBinary()) }
	}
	return rm.HandleCLICommand(args, save)
}

func (s *Server) cliVer() string {
	if s.cfg.Version != "" {
		return s.cfg.Version
	}
	return defaultVersion
}

func (s *Server) cliGet(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch key {
	case "name":
		return s.cfg.Name
	case "lat":
		if s.cfg.Lat != nil {
			return fmt.Sprintf("%f", *s.cfg.Lat)
		}
		return "0.000000"
	case "lon":
		if s.cfg.Lon != nil {
			return fmt.Sprintf("%f", *s.cfg.Lon)
		}
		return "0.000000"
	case "freq":
		return s.cfg.RadioFreq
	case "bw":
		return s.cfg.RadioBW
	case "sf":
		return s.cfg.RadioSF
	case "cr":
		return s.cfg.RadioCR
	case "radio":
		return s.cfg.RadioModel
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
	case "path.hash.mode":
		return fmt.Sprintf("%d", s.cfg.Router.GetPathHashMode())
	case "loop.detect":
		return loopDetectName(s.cfg.Router.GetLoopDetect())
	case "bootloader.ver":
		if s.cfg.BootloaderVersion != "" {
			return s.cfg.BootloaderVersion
		}
		return "ERROR: unsupported"
	default:
		return "??: " + key
	}
}

func (s *Server) cliSet(key, value string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch key {
	case "name":
		s.cfg.Name = value
		if s.cfg.AppData != nil {
			s.cfg.AppData.Name = value
		}
	case "lat":
		v, err := strconv.ParseFloat(normalizeNumber(value), 64)
		if err != nil {
			return "Error: bad latitude"
		}
		s.cfg.Lat = &v
		if s.cfg.AppData != nil {
			s.cfg.AppData.Lat = &v
		}
	case "lon":
		v, err := strconv.ParseFloat(normalizeNumber(value), 64)
		if err != nil {
			return "Error: bad longitude"
		}
		s.cfg.Lon = &v
		if s.cfg.AppData != nil {
			s.cfg.AppData.Lon = &v
		}
	case "freq":
		s.cfg.RadioFreq = value
	case "bw":
		s.cfg.RadioBW = value
	case "sf":
		s.cfg.RadioSF = value
	case "cr":
		s.cfg.RadioCR = value
	case "radio":
		s.cfg.RadioModel = value
	case "guest.password":
		s.cfg.GuestPassword = value
	case "allow.read.only":
		switch value {
		case "on":
			s.cfg.AllowReadOnly = true
		case "off":
			s.cfg.AllowReadOnly = false
		default:
			return "Error: expected on/off"
		}
	case "path.hash.mode":
		mode, err := strconv.ParseUint(value, 10, 8)
		if err != nil || mode > 2 {
			return "Error: expected 0, 1, or 2"
		}
		s.cfg.Router.SetPathHashMode(uint8(mode))
	case "loop.detect":
		level, ok := parseLoopDetectLevel(value)
		if !ok {
			return "Error: expected off/minimal/moderate/strict"
		}
		s.cfg.Router.SetLoopDetect(level)
	default:
		return "??: " + key
	}

	if s.cfg.OnSettingChanged != nil {
		s.cfg.OnSettingChanged(key, value)
	}
	return "OK"
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

// normalizeNumber replaces Unicode minus sign (U+2212) with ASCII hyphen-minus.
// Mobile apps sometimes send typographic characters in numeric input.
func normalizeNumber(s string) string {
	return strings.ReplaceAll(s, "\u2212", "-")
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
