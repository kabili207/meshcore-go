// Package cli provides a shared command dispatcher for node roles that expose a
// text CLI (the room server and repeater). A role builds a Dispatcher, registers
// its config keys (get/set) and commands, and calls Execute on each received
// command line. This corresponds to the firmware's CommonCLI shared command set.
package cli

import (
	"strconv"
	"strings"
)

// ConfigKey is a get/set-able configuration value.
type ConfigKey struct {
	// Get returns the current value as a display string.
	Get func() string

	// Set applies a new value. Return a non-nil error to report failure; its
	// message is shown to the user prefixed with "Error: ". A nil Set makes the
	// key read-only (a "set" on it is treated as an unknown key).
	Set func(value string) error
}

// CommandFunc handles a command, receiving its whitespace-split arguments (the
// command word removed) and returning the reply text.
type CommandFunc func(args []string) string

// Dispatcher parses CLI command lines and routes them to registered config keys
// (via the built-in get/set commands) and commands.
type Dispatcher struct {
	keys     map[string]ConfigKey
	commands map[string]CommandFunc
	fallback func(cmd string) string
	afterSet func(key, value string)
}

// New creates an empty Dispatcher.
func New() *Dispatcher {
	return &Dispatcher{
		keys:     make(map[string]ConfigKey),
		commands: make(map[string]CommandFunc),
	}
}

// Key registers a config key. Returns the dispatcher for chaining.
func (d *Dispatcher) Key(name string, k ConfigKey) *Dispatcher {
	d.keys[name] = k
	return d
}

// Command registers a command handler. Returns the dispatcher for chaining.
func (d *Dispatcher) Command(name string, fn CommandFunc) *Dispatcher {
	d.commands[name] = fn
	return d
}

// Fallback sets a handler for command lines that match no registered command.
// It receives the full (trimmed) command line.
func (d *Dispatcher) Fallback(fn func(cmd string) string) *Dispatcher {
	d.fallback = fn
	return d
}

// AfterSet registers a hook called after any successful set.
func (d *Dispatcher) AfterSet(fn func(key, value string)) *Dispatcher {
	d.afterSet = fn
	return d
}

// HasKey reports whether a config key is registered.
func (d *Dispatcher) HasKey(name string) bool {
	_, ok := d.keys[name]
	return ok
}

// HasCommand reports whether a command is registered.
func (d *Dispatcher) HasCommand(name string) bool {
	_, ok := d.commands[name]
	return ok
}

// Execute parses and runs a command line, returning the reply text.
func (d *Dispatcher) Execute(cmd string) string {
	cmd = strings.TrimLeft(cmd, " ")
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	switch parts[0] {
	case "get":
		if len(parts) < 2 {
			return "??: (missing key)"
		}
		return d.get(parts[1])
	case "set":
		if len(parts) < 3 {
			return "Error: missing value"
		}
		return d.set(parts[1], strings.Join(parts[2:], " "))
	}

	if fn, ok := d.commands[parts[0]]; ok {
		return fn(parts[1:])
	}
	if d.fallback != nil {
		return d.fallback(cmd)
	}
	return "Unknown command"
}

// SetClock implements a "time <epoch>" command: it parses an epoch-seconds
// argument and forwards it to cb. A transport-attached node normally has a
// better clock than a remote client, so cb is opt-in; when nil, the command
// reports "unsupported".
func SetClock(cb func(epoch uint32) error, args []string) string {
	if cb == nil {
		return "unsupported"
	}
	if len(args) < 1 {
		return "Error: usage: time <epoch>"
	}
	epoch, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		return "Error: bad epoch"
	}
	if err := cb(uint32(epoch)); err != nil {
		return "Error: " + err.Error()
	}
	return "OK"
}

// Reboot implements a "reboot" command. cb runs in its own goroutine so the CLI
// reply is sent before the app acts on it. When cb is nil the command reports
// "unsupported".
func Reboot(cb func()) string {
	if cb == nil {
		return "unsupported"
	}
	go cb()
	return "OK"
}

func (d *Dispatcher) get(key string) string {
	k, ok := d.keys[key]
	if !ok || k.Get == nil {
		return "??: " + key
	}
	return k.Get()
}

func (d *Dispatcher) set(key, value string) string {
	k, ok := d.keys[key]
	if !ok || k.Set == nil {
		return "??: " + key
	}
	if err := k.Set(value); err != nil {
		return "Error: " + err.Error()
	}
	if d.afterSet != nil {
		d.afterSet(key, value)
	}
	return "OK"
}
