# lain

**Diff-aware fuzzing for AI-shipped code.**

`lain` is a small, dependency-light Go CLI that security-fuzzes a web app you own. It loads a route manifest (`routes.json`), optionally diffs it against any git ref so only **new/changed routes** get scanned, then runs parameter fuzzing (SQLi, reflected XSS, path traversal) plus directory brute-forcing across a bounded worker pool. Every finding gets a stable ID (so you can say "finding `f9f935b3` is fixed"), a severity, an evidence snippet, a machine-readable **SARIF** report, a human-readable **markdown** report, an interactive **HTML dashboard**, and a **fix.md** that an AI coding assistant (Cursor, Claude Code, Copilot Chat) can apply directly — with each fix tied to the exact route and finding ID that `lain` will re-verify on the next push.

It is designed for the CI loop: run it on a PR, let it fail the build when HIGH-severity findings appear in newly-added routes, and ship the three report files as artifacts. Everything ships as a single static binary with no SDK dependencies; fix generation works with a local [Ollama](https://ollama.com) (free, offline) or any OpenAI-compatible endpoint.

## Diff-aware pitch

```text
Diff mode (HEAD~1): 1 new route(s), 0 changed route(s), 4 unchanged (skipped)
scanning 1 route(s) against http://localhost:3000
```

Instead of re-fuzzing your entire app on every push (noisy, slow), `lain` snapshots `routes.json` at a git ref (defaults to the PR base SHA in CI) and scans only the routes that changed. Same-bug noise drops, review surface shrinks, and the "did my fix work?" loop is fast.

## One-command demo

The **`demo` command is built into the binary**, so it works the same on
Windows, macOS, and Linux — no global install or PATH changes needed. Run it
**from inside the project repo**: it locates the app by walking upward from your
current directory, so it works from any subfolder.

```bash
# Windows (PowerShell or cmd)
cd C:\Users\prath\Desktop\app\lain
.\lain               # or: .\lain demo

# Windows cmd (current dir is searched, so bare "lain" works)
lain demo

# macOS / Linux (first run builds the binary automatically)
cd ~/Desktop/app/lain
./lain demo
```

It starts the vulnerable app (if it isn't running), scans it, opens the
interactive `report.html` dashboard, and stops the app afterwards.

```bash
lain demo --llm      # use the configured LLM (LAIN_LLM_*) for fix.md
lain demo --repo owner/repo --token ghp_xxx   # also auto-file GitHub issues
```

Demo flags: `--target`, `--app-dir`, `--repo`, `--token`, `--llm`, `--no-open`,
`--keep-running`. It exits with lain's exit code (1 = HIGH findings), so it
doubles as a quick local CI gate.

The repo ships `lain.cmd` (Windows cmd) and `lain` (macOS/Linux) launchers.
Windows PowerShell users can also use `run-demo.ps1` (`-Repo`, `-Token`, `-LLM`,
`-NoOpen`, `-KeepRunning`).

## Build

```bash
go build -o lain .
```

Go 1.22+. No runtime dependencies.

## Usage

```bash
# Full scan (all routes in routes.json)
./lain --target http://localhost:3000 --routes routes.json

# Diff scan: only routes added/changed since HEAD~1 (run inside the app's git repo)
./lain --target http://localhost:3000 --routes ../app/routes.json --base-ref HEAD~1

# Offline fix generation (no LLM needed) — the safe demo/venue mode
./lain --target http://localhost:3000 --routes routes.json --skip-llm
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--target` | `http://localhost:3000` | Base URL of the app to scan |
| `--routes` | `./routes.json` | Path to the route manifest |
| `--concurrency` | `10` | Concurrent scan workers |
| `--bruteforce` | `true` | Also run the directory brute-forcer against a built-in wordlist |
| `--base-ref` | `""` | Git ref to diff `routes.json` against; empty = scan all routes |
| `--report-json` | `report.json` | Output path for the SARIF report |
| `--report-md` | `report.md` | Output path for the markdown report |
| `--report-html` | `report.html` | Output path for the interactive HTML dashboard |
| `--fix-out` | `fix.md` | Output path for the fix report |
| `--skip-llm` | `false` | Force the fallback fix template (no LLM calls) |
| `--no-color` | `false` | Disable ANSI colors (also honors `NO_COLOR` and non-TTY output) |
| `--gh-token` | `""` | GitHub token for issue/PR automation (env `GITHUB_TOKEN` or `LAIN_GH_TOKEN`) |
| `--gh-repo` | `""` | `owner/repo` to sync issues against (env `GITHUB_REPOSITORY`, else your git `origin`) |
| `--gh-min-severity` | `MEDIUM` | Minimum severity (`HIGH`/`MEDIUM`/`LOW`) to auto-file issues for |
| `--pr-number` | `""` | Pull request number to post the scan summary to (auto-detected in CI) |

LLM settings come from the environment. `LAIN_LLM_PROVIDER` picks a preset when
no explicit endpoint is set: `ollama` (default), `deepseek`, or `opencode-go`.

| Env | Default | Description |
|---|---|---|
| `LAIN_LLM_PROVIDER` | `ollama` | Preset: endpoint + model for `ollama`, `deepseek`, or `opencode-go` |
| `LAIN_LLM_ENDPOINT` | per provider | Full `…/chat/completions` URL; overrides the preset |
| `LAIN_LLM_MODEL` | per provider | `qwen2.5:7b-instruct` (ollama), `deepseek-v4-flash` (deepseek/opencode-go) |
| `LAIN_LLM_API_KEY` | `""` | Sent as `Authorization: Bearer <key>` (`OPENCODE_API_KEY` and `ANTHROPIC_API_KEY` are aliases) |
| `LAIN_LLM_DISABLED` | `""` | Set to `1` to force the fallback fix template |

Example — DeepSeek V4 Flash via opencode-go (Zen Go):

```bash
export LAIN_LLM_PROVIDER="opencode-go"
export LAIN_LLM_MODEL="deepseek-v4-flash"
export LAIN_LLM_API_KEY="sk-your-opencode-key"
```

or point at the official DeepSeek API with `LAIN_LLM_PROVIDER="deepseek"`, or any
OpenAI-compatible host with `LAIN_LLM_ENDPOINT` + `LAIN_LLM_MODEL` + `LAIN_LLM_API_KEY`.

### Example output

```text
┌────────────────────────────────────────┐
│ ██╗    █████╗ ██╗███╗   ██╗            │
│ ██║    ██╔══██╗██║████╗  ██║           │
│ ██║    ███████║██║██╔██╗ ██║           │
│ ╚═╝    ╚═══╝╚═╝╚═╝╚═╝╚═╝╚═╝            │
│                                        │
│ Diff-aware fuzzing for AI-shipped code │
└────────────────────────────────────────┘

Full scan mode: 5 loaded route(s), no --base-ref diff
brute-force: discovered 0 new route(s)
scanning 5 route(s) against http://localhost:3000

[3/5] GET /search ... 1 finding(s)   # progress streams in place

[HIGH] Unauthenticated sensitive route — GET /admin
    payload:
    evidence: request returned HTTP 200 to sensitive route with no auth header

[MEDIUM] Reflected XSS — GET /api/notes?title
    payload:  <script>alert(1)</script>
    evidence: payload "<script>alert(1)</script>" reflected unescaped in response body

[HIGH] Path Traversal — GET /files?name
    payload:  ../../../../../../etc/passwd
    evidence: response body contains file content signature "root:"

[HIGH] SQL Injection — GET /api/users?id
    payload:  ' OR '1'='1
    evidence: HTTP 500 response

┌─────────────────────────────────────────────────────────────────────────┐
│ Scan Summary                                                            │
│                                                                         │
│ routes scanned: 5                                                       │
│ total findings: 5                                                       │
│ HIGH ███ 3   MEDIUM ██ 2   LOW  0                                       │
│ duration:       26ms                                                    │
│                                                                         │
│ reports: report.json   report.md   fix.md                               │
└─────────────────────────────────────────────────────────────────────────┘

❌ FAILED — 3 high severity finding(s)      # exit code 1 → CI gate
```

Open `report.html` in a browser for an interactive dashboard: severity filters,
live search, and click-to-expand payloads/evidence — a single self-contained
file (no CDN, works offline). Findings are embedded as escaped JSON and rendered
with `textContent`, so XSS payloads discovered by the fuzzer can never execute
inside the report itself.

Every finding row has a **Create issue** button, and when multiple findings are
shown there's a **Create all issues (N)** button. Click one, enter your GitHub
token + repo (pre-filled from `--gh-repo`), and it files the issue(s) directly
to GitHub from your browser — the token is only used for those requests and
never stored in the report. Bulk mode creates each issue sequentially and shows
every resulting link or error.

And the generated `fix.md` (fallback mode) begins with a scannable table:

```markdown
# Lain Fix Report

> **How to use this file:** paste it into your AI coding assistant (Cursor, Claude Code, Copilot Chat) and ask it to apply the fixes below. Each fix references the exact route and finding ID so Lain can verify remediation on the next scan.

**2 finding(s), generated 2026-08-16T03:55:24+05:30**

## Summary

| Finding ID | Severity | Type | Location |
|---|---|---|---|
| `7439aab7` | 🔴 HIGH | Unauthenticated sensitive route | `GET /admin` |
| `f9f935b3` | 🟡 MEDIUM | Reflected XSS | `GET /api/notes?title` |

---

## [🔴 HIGH] Unauthenticated sensitive route — GET /admin

**Location:** `GET /admin`
**Finding ID:** `7439aab7`

### Evidence
request returned HTTP 200 to sensitive route with no auth header

### Root Cause
This sensitive route returns data without any authentication or authorization check, so anyone can reach it.

### Suggested Fix
Add an authentication/authorization guard to this handler (session/JWT check) and return 401/403 when the caller is not permitted.

### Acceptance Check
Lain will re-scan this route on the next push to confirm remediation (finding ID `7439aab7`).
```

## GitHub automation

Give lain a token and it closes the loop on GitHub automatically. Because every
finding has a **stable ID** (same route + param + vuln type always hash the same
way), lain can track a finding across scans and lifecycle its issues:

```bash
# Auto-file an issue per HIGH/MEDIUM finding, auto-close it once fixed
LAIN_GH_TOKEN=ghp_xxx ./lain --target http://localhost:3000 --routes routes.json --gh-repo owner/repo

# Same, but on a pull request — also posts/updates a scan summary comment
# (PR number auto-detected from GITHUB_REF / GITHUB_EVENT_PATH in CI)
./lain --target http://localhost:3000 --routes routes.json
```

- **Finding → issue**: each finding ≥ `--gh-min-severity` gets one issue, titled
  `[lain] HIGH: Reflected XSS — GET /profile?name`, tagged `lain` + `lain:<finding-id>`.
- **Fixed → auto-close**: when a later scan stops reproducing a finding, lain
  closes its issue and leaves a *"Fixed — finding `<id>` no longer reproduced"* comment.
- **PR summary**: on pull requests, lain keeps a single self-updating comment with
  a findings table (route, severity, evidence) plus a link to `fix.md` — or a
  clean "✅ no findings" when the scan passes.
- **Safe to run every push**: issue sync is idempotent, and without a token lain
  skips GitHub entirely (your offline demo still works).

## CI

`action.yml` is a composite GitHub Action. Point your app's workflow at it, pass `target-url` and `routes-file`, and it builds `lain`, runs the scan (diffing against the PR base by default), auto-files GitHub issues for findings, posts the summary to the PR, and uploads `report.json`, `report.md`, `report.html`, and `fix.md` as artifacts — failing the job whenever HIGH-severity findings exist.

```yaml
steps:
  - name: Lain scan
    uses: owner/lain@main
    with:
      target-url: http://localhost:3000
      routes-file: routes.json
      anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      # github-token and gh-min-severity default to the automatic GITHUB_TOKEN / MEDIUM
```

Set `github-token` to a PAT with `repo` scope if you want issues filed as a
specific bot account instead of the default `github-actions` bot.

## Repository layout

- `internal/orchestrator` — bounded worker pool that fans routes out and aggregates findings
- `internal/fuzzer` — SQLi / XSS / path-traversal payloads with conservative detection
- `internal/bruteforce` — concurrent directory brute-forcer
- `internal/diff` — route snapshot + git-ref diffing
- `internal/scorer` — stable finding IDs, dedup, severity mapping
- `internal/report` — SARIF, markdown, and interactive HTML report writers
- `internal/fixgen` — LLM/fallback fix generation
- `internal/gh` — hand-rolled GitHub REST client: issue auto-file/auto-close + PR summary comments
- `internal/ui` — terminal output (colors, banner, progress, summary)
- `demo.go` — built-in cross-platform `lain demo` (start app, scan, open dashboard)
- `run-demo.ps1` — PowerShell one-command demo (Windows convenience wrapper)
