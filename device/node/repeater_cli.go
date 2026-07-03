package node

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/kabili207/meshcore-go/core/codec"
	"github.com/kabili207/meshcore-go/device/acl"
	"github.com/kabili207/meshcore-go/device/cli"
	"github.com/kabili207/meshcore-go/device/event"
	"github.com/kabili207/meshcore-go/device/router"
)

const repeaterDefaultVersion = "meshcore-go"

// handleCLIMessage runs an admin CLI command received as a TXT_TYPE_CLI message
// and replies with the result. Non-admin senders and non-CLI text are ignored
// (firmware only accepts CLI from admin clients and sends no ACK).
func (n *RepeaterNode) handleCLIMessage(evt *event.TextMessageReceived) {
	if evt.TxtType != codec.TxtTypeCLI {
		return
	}
	client := n.acl.GetClient(evt.From)
	if client == nil || !client.IsAdmin() {
		return
	}
	client.LastActivity = n.base.Clock().GetCurrentTime()

	cmd := evt.Message
	// Strip the optional companion "NN|" prefix and reflect it in the reply so
	// the app can correlate command/response pairs.
	prefix := ""
	if len(cmd) > 4 && cmd[2] == '|' {
		prefix = cmd[:3]
		cmd = cmd[3:]
	}

	reply := n.cli.Execute(cmd)
	if reply == "" {
		return
	}
	content := codec.BuildTxtMsgContent(n.base.Clock().GetCurrentTime(), codec.TxtTypeCLI, 0, prefix+reply, nil)
	if err := n.base.SendReply(evt.Reply, evt.From, codec.PayloadTypeTxtMsg, content); err != nil {
		n.log.Warn("failed to send CLI reply", "error", err)
	}
}

// buildCLI constructs the repeater's shared CLI dispatcher: config keys plus
// repeater commands. Called once from NewRepeater.
func (n *RepeaterNode) buildCLI() *cli.Dispatcher {
	d := cli.New()
	r := n.base.Router

	// --- Config keys ---
	d.Key("name", cli.ConfigKey{
		Get: func() string { return n.appData.Name },
		Set: func(v string) error { n.appData.Name = v; return nil },
	})
	d.Key("lat", cli.ConfigKey{
		Get: func() string { return formatCoord(n.appData.Lat) },
		Set: func(v string) error { return setCoord(&n.appData.Lat, v, "bad latitude") },
	})
	d.Key("lon", cli.ConfigKey{
		Get: func() string { return formatCoord(n.appData.Lon) },
		Set: func(v string) error { return setCoord(&n.appData.Lon, v, "bad longitude") },
	})
	d.Key("path.hash.mode", cli.ConfigKey{
		Get: func() string { return strconv.Itoa(int(r.GetPathHashMode())) },
		Set: func(v string) error {
			mode, err := strconv.ParseUint(v, 10, 8)
			if err != nil || mode > 2 {
				return errors.New("expected 0, 1, or 2")
			}
			r.SetPathHashMode(uint8(mode))
			return nil
		},
	})
	d.Key("loop.detect", cli.ConfigKey{
		Get: func() string { return router.LoopDetectName(r.GetLoopDetect()) },
		Set: func(v string) error {
			level, ok := router.ParseLoopDetectLevel(v)
			if !ok {
				return errors.New("expected off/minimal/moderate/strict")
			}
			r.SetLoopDetect(level)
			return nil
		},
	})
	d.Key("flood.max", cli.ConfigKey{
		Get: func() string { return strconv.Itoa(r.GetMaxFloodHops()) },
		Set: func(v string) error {
			hops, err := strconv.Atoi(v)
			if err != nil || hops < 0 {
				return errors.New("expected a non-negative number")
			}
			r.SetMaxFloodHops(hops)
			return nil
		},
	})
	d.Key("repeat", cli.ConfigKey{
		Get: func() string { return onOff(r.GetForwardPackets()) },
		Set: func(v string) error {
			switch v {
			case "on":
				r.SetForwardPackets(true)
			case "off":
				r.SetForwardPackets(false)
			default:
				return errors.New("expected on/off")
			}
			return nil
		},
	})

	// --- Read-only keys ---
	d.Key("public.key", cli.ConfigKey{Get: func() string {
		pk := n.base.PublicKey()
		return hex.EncodeToString(pk[:])
	}})
	d.Key("role", cli.ConfigKey{Get: func() string { return "repeater" }})

	// --- Commands ---
	d.Command("ver", func([]string) string {
		if n.cfg.Version != "" {
			return n.cfg.Version
		}
		return repeaterDefaultVersion
	})
	d.Command("clock", func([]string) string {
		t := time.Unix(int64(n.base.Clock().GetCurrentTime()), 0).UTC()
		return fmt.Sprintf("%02d:%02d - %02d/%02d/%04d UTC",
			t.Hour(), t.Minute(), t.Day(), t.Month(), t.Year())
	})
	d.Command("advert", func([]string) string { n.advertSched.SendNow(true); return "OK" })
	d.Command("advert.zerohop", func([]string) string { n.advertSched.SendNow(false); return "OK" })
	d.Command("neighbors", func([]string) string { return n.cliNeighbors() })
	d.Command("password", func(args []string) string {
		if len(args) < 1 {
			return "Error: usage: password <new>"
		}
		n.auth.AdminPassword = args[0]
		return "OK"
	})
	d.Command("setperm", func(args []string) string { return n.cliSetPerm(args) })
	d.Command("region", func(args []string) string { return n.cliRegion(args) })

	if n.cfg.OnSettingChanged != nil {
		d.AfterSet(n.cfg.OnSettingChanged)
	}
	return d
}

// cliNeighbors lists the repeater's directly-heard neighbors newest-first.
func (n *RepeaterNode) cliNeighbors() string {
	nb := n.neighbors.snapshot(neighborOrderNewest)
	if len(nb) == 0 {
		return "(no neighbors)"
	}
	var b strings.Builder
	for _, e := range nb {
		fmt.Fprintf(&b, "%s snr=%.2f\n", e.id.String()[:12], float32(e.snr)/4.0)
	}
	return strings.TrimRight(b.String(), "\n")
}

// cliSetPerm sets a client's permissions by public-key prefix.
func (n *RepeaterNode) cliSetPerm(args []string) string {
	if len(args) < 2 {
		return "Error: usage: setperm <pubkey-hex> <permissions>"
	}
	perm, err := strconv.ParseUint(args[1], 10, 8)
	if err != nil {
		return "Error: bad permissions value"
	}
	prefix, err := hex.DecodeString(args[0])
	if err != nil || len(prefix) == 0 {
		return "ERR: bad pubkey"
	}

	var matched *acl.Client
	n.acl.ForEach(func(c *acl.Client) bool {
		if len(prefix) <= len(c.ID) && matchesPrefix(c.ID[:], prefix) {
			matched = c
			return false
		}
		return true
	})
	if matched == nil {
		return "ERR: client not found"
	}
	matched.Permissions = uint8(perm)
	return "OK"
}

// cliRegion runs a "region ..." subcommand against the Router's RegionMap.
func (n *RepeaterNode) cliRegion(args []string) string {
	r := n.base.Router
	if r == nil {
		return "Err - regions not enabled"
	}
	rm := r.RegionMap()
	if rm == nil {
		return "Err - regions not enabled"
	}
	var save func() error
	if n.cfg.OnRegionsChanged != nil {
		save = func() error { return n.cfg.OnRegionsChanged(rm.MarshalBinary()) }
	}
	return rm.HandleCLICommand(args, save)
}

func formatCoord(c *float64) string {
	if c != nil {
		return fmt.Sprintf("%f", *c)
	}
	return "0.000000"
}

func setCoord(dst **float64, value, errMsg string) error {
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return errors.New(errMsg)
	}
	*dst = &f
	return nil
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func matchesPrefix(full, prefix []byte) bool {
	if len(prefix) > len(full) {
		return false
	}
	for i, b := range prefix {
		if full[i] != b {
			return false
		}
	}
	return true
}
