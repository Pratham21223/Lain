<#
.SYNOPSIS
  One-command Lain demo: build the fuzzer, start the vulnerable app, scan it,
  and open the HTML dashboard.

.EXAMPLE
  .\run-demo.ps1

.EXAMPLE
  .\run-demo.ps1 -Repo Pratham21223/Simon-says -Token ghp_xxx   # also file GitHub issues
.EXAMPLE
  .\run-demo.ps1 -KeepRunning -NoOpen                          # leave the app up, don't open the report
#>
[CmdletBinding()]
param(
    [string]$Target = "http://127.0.0.1:5000",
    [string]$AppDir = "",
    [string]$Token = "",
    [string]$Repo = "",
    [string]$MinSeverity = "MEDIUM",
    [switch]$SkipGithub,
    [switch]$LLM,
    [switch]$NoOpen,
    [switch]$KeepRunning
)

$ErrorActionPreference = "Stop"

$lainDir   = $PSScriptRoot
$appRoot   = Split-Path -Parent $lainDir
if (-not $AppDir) { $AppDir = Join-Path $appRoot "vulnbank-" }
$Target    = $Target.TrimEnd('/')
$healthURL = "$Target/health"
$routes    = Join-Path $AppDir "routes.json"
$exe       = Join-Path $lainDir "lain.exe"
$html      = Join-Path $lainDir "report.html"

function Test-Up([string]$url) {
    try { return (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200 } catch { return $false }
}

Write-Host ""
Write-Host "=== Lain one-command demo ===" -ForegroundColor Cyan
Write-Host "app dir : $AppDir"
Write-Host "routes  : $routes"
Write-Host "target  : $Target"
if ($Repo) { Write-Host "github  : $Repo" }
if ($LLM)  { Write-Host "llm     : enabled (LAIN_LLM_* env)" }

# 1. Build lain
Write-Host ""
Write-Host "[1/4] Building lain..." -ForegroundColor Cyan
Push-Location $lainDir
try {
    go build -o lain.exe .
    if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

# 2. Make sure the app is up
Write-Host ""
Write-Host "[2/4] Checking vulnbank..." -ForegroundColor Cyan
$startedApp = $false
$proc = $null
if (Test-Up $healthURL) {
    Write-Host "vulnbank is already running."
} else {
    Write-Host "starting vulnbank (Flask) on $Target"
    $python = (Get-Command python).Source
    if (-not $python) { throw "python not found on PATH" }
    $proc = Start-Process -FilePath $python -ArgumentList "app.py" -WorkingDirectory $AppDir -PassThru -WindowStyle Hidden
    $startedApp = $true
    $up = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Milliseconds 500
        if (Test-Up $healthURL) { $up = $true; break }
        if ($proc.HasExited) {
            throw "vulnbank exited early (code $($proc.ExitCode)). Install deps with: pip install -r $((Join-Path $AppDir 'requirements.txt'))"
        }
    }
    if (-not $up) { throw "vulnbank did not become healthy on $healthURL in time" }
    Write-Host "vulnbank is up."
}

# 3. Run the scan
Write-Host ""
Write-Host "[3/4] Running lain scan..." -ForegroundColor Cyan
$lainArgs = @("--target", $Target, "--routes", $routes)
if (-not $LLM) { $lainArgs += "--skip-llm" }
if (-not $SkipGithub) {
    $tok = $Token
    if (-not $tok) { $tok = $env:LAIN_GH_TOKEN }
    if (-not $tok) { $tok = $env:GITHUB_TOKEN }
    if ($tok) { $lainArgs += @("--gh-token", $tok) }
    if ($Repo) { $lainArgs += @("--gh-repo", $Repo) }
    if ($MinSeverity) { $lainArgs += @("--gh-min-severity", $MinSeverity) }
}
& $exe @lainArgs
$exit = $LASTEXITCODE

# 4. Open the dashboard
if (-not $NoOpen -and (Test-Path $html)) {
    Write-Host ""
    Write-Host "[4/4] Opening dashboard..." -ForegroundColor Cyan
    Start-Process $html
} else {
    Write-Host ""
    Write-Host "[4/4] Dashboard: $html" -ForegroundColor Cyan
}

# Cleanup
if ($startedApp) {
    if ($KeepRunning) {
        Write-Host "Keeping vulnbank running (PID $($proc.Id))."
    } else {
        Write-Host "Stopping vulnbank (PID $($proc.Id))."
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ""
Write-Host "Done. lain exit code: $exit"
exit $exit