package router

import (
	"fmt"
	"strings"
)

// HandleCLICommand processes a "region ..." admin command and returns the reply
// text, mirroring the firmware repeater CLI (simple_repeater's "region" handler).
// args holds the tokens after "region" (e.g. ["put", "#us"]).
//
// The save callback persists the map for the "region save" command (typically
// storing MarshalBinary output); pass nil if persistence is unavailable, in
// which case "region save" reports it is unsupported. All other subcommands
// mutate the in-memory map directly.
//
// The firmware's stateful "region load" bulk-import session is not supported.
//
// This is not internally synchronized; see the RegionMap concurrency note.
func (m *RegionMap) HandleCLICommand(args []string, save func() error) string {
	if len(args) == 0 {
		return strings.TrimRight(m.ExportString(), "\n")
	}

	switch args[0] {
	case "save":
		if save == nil {
			return "Err - save not supported"
		}
		if err := save(); err != nil {
			return "Err - save failed"
		}
		return "OK"

	case "allowf":
		region := m.regionArg(args)
		if region == nil {
			return "Err - unknown region"
		}
		region.Flags &^= RegionDenyFlood
		return "OK"

	case "denyf":
		region := m.regionArg(args)
		if region == nil {
			return "Err - unknown region"
		}
		region.Flags |= RegionDenyFlood
		return "OK"

	case "get":
		region := m.regionArg(args)
		if region == nil {
			return "Err - unknown region"
		}
		flood := ""
		if region.Flags&RegionDenyFlood == 0 {
			flood = "F"
		}
		if parent := m.FindByID(region.Parent); parent != nil && parent.ID != 0 {
			return fmt.Sprintf(" %s (%s) %s", region.Name, parent.Name, flood)
		}
		return fmt.Sprintf(" %s %s", region.Name, flood)

	case "home":
		if len(args) >= 2 {
			home := m.FindByNamePrefix(args[1])
			if home == nil {
				return "Err - unknown region"
			}
			m.SetHomeRegion(home)
			return " home is now " + home.Name
		}
		home := m.HomeRegion()
		name := "*"
		if home != nil {
			name = home.Name
		}
		return " home is " + name

	case "put":
		if len(args) < 2 {
			return "Err - ??"
		}
		parent := m.Wildcard()
		if len(args) >= 3 {
			parent = m.FindByNamePrefix(args[2])
		}
		if parent == nil {
			return "Err - unknown parent"
		}
		if m.PutRegion(args[1], parent.ID, 0) == nil {
			return "Err - unable to put"
		}
		return "OK"

	case "remove":
		if len(args) < 2 {
			return "Err - ??"
		}
		region := m.FindByName(args[1])
		if region == nil {
			return "Err - not found"
		}
		if !m.RemoveRegion(region) {
			return "Err - not empty"
		}
		return "OK"

	case "list":
		if len(args) < 2 {
			return "Err - use 'allowed' or 'denied'"
		}
		var invert bool
		switch args[1] {
		case "allowed":
			invert = false // regions that do NOT deny flood
		case "denied":
			invert = true // regions that DO deny flood
		default:
			return "Err - use 'allowed' or 'denied'"
		}
		names := m.ExportNames(RegionDenyFlood, invert)
		if names == "" {
			return "-none-"
		}
		return names

	default:
		return "Err - ??"
	}
}

// regionArg resolves the region named by args[1] via prefix match, or nil when
// the argument is missing or unknown.
func (m *RegionMap) regionArg(args []string) *RegionEntry {
	if len(args) < 2 {
		return nil
	}
	return m.FindByNamePrefix(args[1])
}
