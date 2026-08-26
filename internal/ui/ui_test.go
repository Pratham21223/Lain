package ui

import (
	"os"
	"strings"
	"testing"
)

func TestColorGuard(t *testing.T) {
	noColor := New(true, os.Stdout)
	if noColor.color {
		t.Error("forceNoColor=true should disable color")
	}

	// Non-terminal output (bytes.Buffer) must disable color even without the flag.
	plain := New(false, &strings.Builder{})
	if plain.color {
		t.Error("non-terminal output should disable color")
	}

	if got := noColor.Red("x"); got != "x" {
		t.Errorf("Red on no-color UI = %q, want %q", got, "x")
	}
}

func TestVisibleLenStripsANSI(t *testing.T) {
	cases := map[string]int{
		"plain":                      5,
		"\x1b[31mred\x1b[0m":         3,
		"\x1b[1m\x1b[36mcyan\x1b[0m": 4,
		"\x1b]8;;file:///x\x1b\\path\x1b]8;;\x1b\\": 4,
	}
	for in, want := range cases {
		if got := visibleLen(in); got != want {
			t.Errorf("visibleLen(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestBoxAligned(t *testing.T) {
	u := New(true, &strings.Builder{})
	box := u.Box("a", "longer line", "c")
	lines := strings.Split(box, "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d: %q", len(lines), box)
	}
	borderWidth := visibleLen(lines[0])
	for i, l := range lines {
		if visibleLen(l) != borderWidth {
			t.Errorf("line %d visible width %d != border width %d: %q", i, visibleLen(l), borderWidth, l)
		}
	}
	if !strings.HasPrefix(lines[1], "│ ") || !strings.HasSuffix(lines[1], " │") {
		t.Errorf("content line not bordered: %q", lines[1])
	}
}

func TestBoxWithMultibyte(t *testing.T) {
	u := New(true, &strings.Builder{})
	box := u.Box("█ 2", "MEDIUM █ 1")
	lines := strings.Split(box, "\n")
	borderWidth := visibleLen(lines[0])
	for _, l := range lines {
		if visibleLen(l) != borderWidth {
			t.Errorf("line visible width %d != border width %d: %q", visibleLen(l), borderWidth, l)
		}
	}
}
