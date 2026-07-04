package cli

import (
	"errors"
	"testing"
)

func TestDispatcher_GetSet(t *testing.T) {
	value := "Alice"
	var afterKey, afterVal string
	d := New().
		Key("name", ConfigKey{
			Get: func() string { return value },
			Set: func(v string) error { value = v; return nil },
		}).
		AfterSet(func(k, v string) { afterKey, afterVal = k, v })

	if got := d.Execute("get name"); got != "Alice" {
		t.Errorf("get name = %q, want Alice", got)
	}
	if got := d.Execute("set name Bob"); got != "OK" {
		t.Errorf("set name = %q, want OK", got)
	}
	if value != "Bob" {
		t.Errorf("value = %q, want Bob", value)
	}
	if afterKey != "name" || afterVal != "Bob" {
		t.Errorf("afterSet(%q, %q), want (name, Bob)", afterKey, afterVal)
	}
}

func TestDispatcher_SetMultiWordValue(t *testing.T) {
	var value string
	d := New().Key("name", ConfigKey{
		Set: func(v string) error { value = v; return nil },
	})
	d.Execute("set name My Cool Node")
	if value != "My Cool Node" {
		t.Errorf("value = %q, want 'My Cool Node'", value)
	}
}

func TestDispatcher_SetError(t *testing.T) {
	d := New().Key("lat", ConfigKey{
		Set: func(string) error { return errors.New("bad latitude") },
	})
	if got := d.Execute("set lat xyz"); got != "Error: bad latitude" {
		t.Errorf("got %q, want 'Error: bad latitude'", got)
	}
}

func TestDispatcher_ReadOnlyKey(t *testing.T) {
	d := New().Key("public.key", ConfigKey{Get: func() string { return "abcd" }})
	if got := d.Execute("get public.key"); got != "abcd" {
		t.Errorf("get = %q, want abcd", got)
	}
	if got := d.Execute("set public.key zzz"); got != "??: public.key" {
		t.Errorf("set read-only = %q, want '??: public.key'", got)
	}
}

func TestDispatcher_UnknownKey(t *testing.T) {
	d := New()
	if got := d.Execute("get nope"); got != "??: nope" {
		t.Errorf("get unknown = %q", got)
	}
	if got := d.Execute("set nope x"); got != "??: nope" {
		t.Errorf("set unknown = %q", got)
	}
}

func TestDispatcher_MissingArgs(t *testing.T) {
	d := New()
	if got := d.Execute("get"); got != "??: (missing key)" {
		t.Errorf("get no key = %q", got)
	}
	if got := d.Execute("set name"); got != "Error: missing value" {
		t.Errorf("set no value = %q", got)
	}
	if got := d.Execute(""); got != "" {
		t.Errorf("empty = %q, want empty", got)
	}
}

func TestDispatcher_Command(t *testing.T) {
	d := New().Command("clear", func(args []string) string {
		if len(args) >= 1 && args[0] == "stats" {
			return "cleared"
		}
		return "Unknown command"
	})
	if got := d.Execute("clear stats"); got != "cleared" {
		t.Errorf("clear stats = %q", got)
	}
	if got := d.Execute("clear junk"); got != "Unknown command" {
		t.Errorf("clear junk = %q", got)
	}
}

func TestDispatcher_Fallback(t *testing.T) {
	d := New().Fallback(func(cmd string) string { return "fallback: " + cmd })
	if got := d.Execute("custom arg"); got != "fallback: custom arg" {
		t.Errorf("fallback = %q", got)
	}

	// No fallback => Unknown command.
	if got := New().Execute("mystery"); got != "Unknown command" {
		t.Errorf("no fallback = %q", got)
	}
}

func TestDispatcher_ProgrammaticSetLoadGet(t *testing.T) {
	value := "Alice"
	afterCalls := 0
	d := New().
		Key("name", ConfigKey{
			Get: func() string { return value },
			Set: func(v string) error { value = v; return nil },
		}).
		AfterSet(func(k, v string) { afterCalls++ })

	// Get.
	if v, ok := d.Get("name"); !ok || v != "Alice" {
		t.Errorf("Get(name) = (%q, %v), want (Alice, true)", v, ok)
	}

	// Set fires AfterSet.
	if err := d.Set("name", "Bob"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if value != "Bob" || afterCalls != 1 {
		t.Errorf("after Set: value=%q afterCalls=%d, want Bob/1", value, afterCalls)
	}

	// Load applies but does NOT fire AfterSet.
	if err := d.Load("name", "Carol"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if value != "Carol" || afterCalls != 1 {
		t.Errorf("after Load: value=%q afterCalls=%d, want Carol/1", value, afterCalls)
	}
}

func TestDispatcher_SetLoadErrors(t *testing.T) {
	d := New().
		Key("name", ConfigKey{
			Set: func(v string) error {
				if v == "" {
					return errors.New("empty")
				}
				return nil
			},
		}).
		Key("role", ConfigKey{Get: func() string { return "repeater" }}) // read-only

	// Unknown key.
	if err := d.Set("nope", "x"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Set(unknown) = %v, want ErrUnknownKey", err)
	}
	if err := d.Load("nope", "x"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Load(unknown) = %v, want ErrUnknownKey", err)
	}
	// Read-only key (no Set).
	if err := d.Set("role", "x"); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Set(read-only) = %v, want ErrUnknownKey", err)
	}
	// Validation error propagates verbatim.
	if err := d.Set("name", ""); err == nil || errors.Is(err, ErrUnknownKey) {
		t.Errorf("Set(name, '') = %v, want validation error", err)
	}
	// Write-only key Get.
	if _, ok := d.Get("name"); ok {
		t.Error("Get(write-only) ok = true, want false")
	}
}
