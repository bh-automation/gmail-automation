# GMAIL-AUTOMATION | Release-Gate Verification (offline, no Gmail account needed)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
if ($env:OS -eq "Windows_NT") { $Py = Join-Path (Join-Path (Join-Path $Root ".venv") "Scripts") "python.exe" }
else { $Py = Join-Path (Join-Path (Join-Path $Root ".venv") "bin") "python" }
if (-not (Test-Path -LiteralPath $Py)) { throw "Erst scripts/bootstrap.ps1 ausfuehren (.venv fehlt)." }

$Tools = Join-Path $Root "tools"
$Example = Join-Path (Join-Path $Root "config") "rules.example.yaml"
$results = [ordered]@{}
function Gate([string]$Name, [scriptblock]$Block) {
    & $Block
    if ($LASTEXITCODE -eq 0) { $script:results[$Name] = "PASS" } else { $script:results[$Name] = "FAIL" }
}

Write-Host "=== GMAIL-AUTOMATION Verification ==="
Gate "G1 LINT"        { & $Py -m ruff check src tests tools }
Gate "G1 FORMAT"      { & $Py -m ruff format --check src tests tools }
Gate "G1 TYPES"       { & $Py -m mypy }
Gate "G3 SECRET SCAN" { & $Py (Join-Path $Tools "secret_scan.py") }
Gate "G4-6 FORBIDDEN" { & $Py (Join-Path $Tools "forbidden_scan.py") }
Gate "DEPENDENCIES"   { & $Py -m pip check }
Gate "CONFIG"         { & $Py -m src.cli config-check --config $Example }
$OldHome = $env:GMAIL_AUTOMATION_HOME; $OldAnchor = $env:GMAIL_AUTOMATION_ANCHOR_DIR
$env:GMAIL_AUTOMATION_HOME = Join-Path ([System.IO.Path]::GetTempPath()) "gmail-automation verify"
$env:GMAIL_AUTOMATION_ANCHOR_DIR = Join-Path ([System.IO.Path]::GetTempPath()) "gmail-automation verify anchors"
Gate "G2 TESTS"       { & $Py -m pytest }
$env:GMAIL_AUTOMATION_HOME = $OldHome; $env:GMAIL_AUTOMATION_ANCHOR_DIR = $OldAnchor

Write-Host ""
$failed = $false
foreach ($k in $results.Keys) {
    Write-Host ("{0,-16} = {1}" -f $k, $results[$k])
    if ($results[$k] -ne "PASS") { $failed = $true }
}
if ($failed) { Write-Host "VERIFY = FAIL"; exit 1 }
Write-Host "VERIFY = PASS"
exit 0
