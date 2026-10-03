# GMAIL-AUTOMATION | Secure Bootstrap (Windows PowerShell 5.1+ / PowerShell 7)
# Creates .venv, installs pinned dependencies, copies the example config once.
# Never enables APPLY. Default mode remains DRY-RUN.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
Write-Host "GMAIL-AUTOMATION | Secure Bootstrap"
$OnWindows = ($env:OS -eq "Windows_NT")

# Find a Python >= 3.12 (py launcher on Windows, versioned binaries elsewhere).
$Candidates = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $Candidates += ,@("py", "-3.13"); $Candidates += ,@("py", "-3.12") }
foreach ($name in @("python3.13", "python3.12", "python", "python3")) {
    if (Get-Command $name -ErrorAction SilentlyContinue) { $Candidates += ,@($name) }
}
$PyExe = $null; $PyArgs = @()
# Windows PowerShell 5.1 turns redirected native stderr into terminating errors under "Stop":
# probe with "Continue" so a missing 'py -3.13' does not abort the bootstrap.
$PrevEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"
foreach ($c in $Candidates) {
    $exe = $c[0]; $cargs = @($c | Select-Object -Skip 1)
    & $exe @cargs -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $PyExe = $exe; $PyArgs = $cargs; break }
}
$ErrorActionPreference = $PrevEap
if (-not $PyExe) { throw "Python 3.12 oder neuer nicht gefunden. Bitte von python.org installieren." }
Write-Host ("Python: " + (& $PyExe @PyArgs -c "import sys; print(sys.version.split()[0])"))

$Venv = Join-Path $Root ".venv"
if ($OnWindows) { $VenvPy = Join-Path (Join-Path $Venv "Scripts") "python.exe" }
else { $VenvPy = Join-Path (Join-Path $Venv "bin") "python" }
if (-not (Test-Path -LiteralPath $VenvPy)) { & $PyExe @PyArgs -m venv "$Venv" }
if ($LASTEXITCODE -ne 0) { throw "venv konnte nicht angelegt werden." }

& "$VenvPy" -m pip install --upgrade pip
& "$VenvPy" -m pip install -r (Join-Path $Root "requirements-lock.txt")
if ($LASTEXITCODE -ne 0) { throw "Abhaengigkeiten konnten nicht installiert werden." }
& "$VenvPy" -m pip install --no-deps -e "$Root"
& "$VenvPy" -m pip install "pytest>=8" "ruff>=0.6" "mypy>=1.10" types-PyYAML
if ($LASTEXITCODE -ne 0) { throw "Entwicklungswerkzeuge konnten nicht installiert werden." }

$Cfg = Join-Path (Join-Path $Root "config") "rules.yaml"
if (-not (Test-Path -LiteralPath $Cfg)) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $Root "config") "rules.example.yaml") -Destination $Cfg
    Write-Host "config/rules.yaml aus Beispiel angelegt (capabilities: aus)."
}

& "$VenvPy" -c "from src import paths; paths.ensure_private_dir(paths.data_dir()); print('Datenordner (Tokens, Audit, Logs - ausserhalb des Projekts):', paths.data_dir())"
Write-Host "Bootstrap abgeschlossen. Standardmodus bleibt DRY-RUN."
