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
