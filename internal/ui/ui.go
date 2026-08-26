package ui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"lain/internal/types"
)

const (
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	green  = "\x1b[32m"
	cyan   = "\x1b[36m"
	bold   = "\x1b[1m"
	reset  = "\x1b[0m"
)

type UI struct {
	out            io.Writer
	color          bool
	mu             sync.Mutex
	progressActive bool
}

// New builds a UI writing to out. Color is enabled unless forceNoColor is set,
// NO_COLOR is present in the environment, or out is not a terminal.
func New(forceNoColor bool, out io.Writer) *UI {
	color := !forceNoColor && os.Getenv("NO_COLOR") == "" && isTerminal(out)
	return &UI{out: out, color: color}
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (u *UI) paint(s, code string) string {
	if !u.color {
		return s
	}
	return code + s + reset
}

func (u *UI) Red(s string) string    { return u.paint(s, red) }
func (u *UI) Yellow(s string) string { return u.paint(s, yellow) }
func (u *UI) Green(s string) string  { return u.paint(s, green) }
func (u *UI) Cyan(s string) string   { return u.paint(s, cyan) }
func (u *UI) Bold(s string) string   { return u.paint(s, bold) }

func severityCode(sev string) string {
	switch sev {
	case "HIGH":
		return red
	case "MEDIUM":
		return yellow
	default:
		return green
	}
}

func (u *UI) Severity(sev string) string { return u.paint(sev, severityCode(sev)) }

// visibleLen counts printable characters (runes), ignoring ANSI CSI color codes
// and OSC 8 hyperlink escape sequences so box borders align correctly.
func visibleLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if s[i] != '\x1b' {
			_, size := utf8.DecodeRuneInString(s[i:])
			if size == 0 {
				size = 1
			}
			n++
			i += size
			continue
		}
		if i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
				j++
			}
			if j < len(s) {
				i = j + 1
			} else {
				i = len(s)
			}
			continue
		}
		if i+1 < len(s) && s[i+1] == ']' {
			j := i + 2
			for j < len(s) && s[j] != '\a' {
				if s[j] == '\x1b' && j+1 < len(s) && s[j+1] == '\\' {
					break
				}
				j++
			}
			if j < len(s) {
				if s[j] == '\a' {
					i = j + 1
				} else {
					i = j + 2
				}
			} else {
				i = len(s)
			}
			continue
		}
		i++
	}
	return n
}

// Box draws a bordered box (┌─┐│└┘) sized to its longest line.
func (u *UI) Box(lines ...string) string {
	width := 0
	for _, l := range lines {
		if w := visibleLen(l); w > width {
			width = w
		}
	}

	var b strings.Builder
	b.WriteString("┌" + strings.Repeat("─", width+2) + "┐\n")
	for _, l := range lines {
		pad := width - visibleLen(l)
		b.WriteString("│ " + l + strings.Repeat(" ", pad) + " │\n")
	}
	b.WriteString("└" + strings.Repeat("─", width+2) + "┘")
	return b.String()
}

const bannerArt = `██╗    █████╗ ██╗███╗   ██╗
██║    ██╔══██╗██║████╗  ██║
██║    ███████║██║██╔██╗ ██║
╚═╝    ╚═══╝╚═╝╚═╝╚═╝╚═╝╚═╝`

func (u *UI) Banner() {
	lines := strings.Split(bannerArt, "\n")
	boxed := make([]string, 0, len(lines)+2)
	for _, l := range lines {
		boxed = append(boxed, u.Bold(u.Cyan(l)))
	}
	boxed = append(boxed, "", u.Cyan("Diff-aware fuzzing for AI-shipped code"))
	fmt.Fprintln(u.out, u.Box(boxed...))
	fmt.Fprintln(u.out)
}

func (u *UI) Info(format string, args ...any) {
	fmt.Fprintln(u.out, u.Cyan(fmt.Sprintf(format, args...)))
}

func (u *UI) Error(format string, args ...any) {
	fmt.Fprintln(os.Stderr, u.Red(fmt.Sprintf(format, args...)))
}

// Progress redraws a single in-place status line as workers complete routes.
func (u *UI) Progress(done, total int, method, path string, findings int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	line := fmt.Sprintf("[%d/%d] %s %s ... %d finding(s)", done, total, method, path, findings)
	fmt.Fprintf(u.out, "\r%s", u.Cyan(line))
	u.progressActive = true
}

func (u *UI) EndProgress() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.progressActive {
		fmt.Fprintln(u.out)
		u.progressActive = false
	}
}

func (u *UI) Findings(findings []types.Finding) {
	for i, f := range findings {
		if i > 0 {
			fmt.Fprintln(u.out)
		}
		fmt.Fprintf(u.out, "[%s] %s — %s\n", u.Severity(f.Severity), f.Title, f.Location)
		fmt.Fprintf(u.out, "    payload:  %s\n", f.Payload)
		fmt.Fprintf(u.out, "    evidence: %s\n", f.Evidence)
	}
}

// Link renders path as an OSC 8 hyperlink when colors are enabled, so it looks
// clickable in modern terminals; otherwise it degrades to plain text.
func (u *UI) Link(path string) string {
	if !u.color {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return fmt.Sprintf("\x1b]8;;file://%s\x1b\\%s\x1b]8;;\x1b\\", abs, path)
}

func (u *UI) severityBar(counts map[string]int) string {
	var parts []string
	for _, sev := range []string{"HIGH", "MEDIUM", "LOW"} {
		n := counts[sev]
		blocks := n
		if blocks > 10 {
			blocks = 10
		}
		bar := u.paint(strings.Repeat("█", blocks), severityCode(sev))
		parts = append(parts, u.Severity(sev)+" "+bar+" "+fmt.Sprint(n))
	}
	return strings.Join(parts, "   ")
}

func (u *UI) Summary(res types.ScanResult, files []string) {
	counts := map[string]int{"HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, f := range res.Findings {
		counts[f.Severity]++
	}
	dur := res.FinishedAt.Sub(res.StartedAt).Round(time.Millisecond)

	links := make([]string, 0, len(files))
	for _, f := range files {
		links = append(links, u.Link(f))
	}

	box := u.Box(
		u.Bold("Scan Summary"),
		"",
		fmt.Sprintf("routes scanned: %d", res.TargetsScanned),
		fmt.Sprintf("total findings: %d", len(res.Findings)),
		u.severityBar(counts),
		fmt.Sprintf("duration:       %s", dur),
		"",
		"reports: "+strings.Join(links, "   "),
	)
	fmt.Fprintln(u.out)
	fmt.Fprintln(u.out, box)
}

func (u *UI) Fail(high int) {
	fmt.Fprintln(u.out, "\n"+u.Red(fmt.Sprintf("❌ FAILED — %d high severity finding(s)", high)))
}

func (u *UI) Pass() {
	fmt.Fprintln(u.out, "\n"+u.Green("✅ PASSED — no high severity findings"))
}
