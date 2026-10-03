# GMAIL-AUTOMATION | Secure Bootstrap (Windows PowerShell 5.1+ / PowerShell 7)
# Creates .venv, installs pinned dependencies, copies the example config once.
# Never enables APPLY. Default mode remains DRY-RUN.
# Idempotent: an interrupted or outdated setup is detected and repaired on the next start.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $Root
Write-Host "GMAIL-AUTOMATION | Secure Bootstrap"
$OnWindows = ($env:OS -eq "Windows_NT")

$Lock = Join-Path $Root "requirements-lock.txt"
$DevLock = Join-Path $Root "requirements-dev-lock.txt"
$Venv = Join-Path $Root ".venv"
$Marker = Join-Path $Venv ".bootstrap-ok"
if ($OnWindows) { $VenvPy = Join-Path (Join-Path $Venv "Scripts") "python.exe" }
else { $VenvPy = Join-Path (Join-Path $Venv "bin") "python" }
$WantHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Lock).Hash.ToLower() + " " + (Get-FileHash -Algorithm SHA256 -LiteralPath $DevLock).Hash.ToLower()

function Invoke-Checked([string]$What, [scriptblock]$Block) {
    & $Block
    if ($LASTEXITCODE -ne 0) { throw "$What fehlgeschlagen (Exit $LASTEXITCODE)." }
}

if ((Test-Path -LiteralPath $Marker) -and ((Get-Content -LiteralPath $Marker -Raw).Trim() -eq $WantHash)) {
    Write-Host "Umgebung ist aktuell (.venv)."
} else {
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

    # A venv from an interrupted setup (no pip, broken interpreter) is rebuilt from scratch.
    $Healthy = $false
    if (Test-Path -LiteralPath $VenvPy) {
        $PrevEap = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & "$VenvPy" -m pip --version 2>$null | Out-Null
        $Healthy = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = $PrevEap
    }
    if (-not $Healthy) {
        if (Test-Path -LiteralPath $Venv) { Write-Host "Unvollstaendige Umgebung gefunden - wird neu angelegt ..." }
        Invoke-Checked "venv anlegen" { & $PyExe @PyArgs -m venv --clear "$Venv" }
    }
    if (Test-Path -LiteralPath $Marker) { Remove-Item -LiteralPath $Marker -Force }

    Invoke-Checked "pip aktualisieren" { & "$VenvPy" -m pip install --upgrade pip }
    Invoke-Checked "Abhaengigkeiten installieren" { & "$VenvPy" -m pip install -r "$Lock" }
    Invoke-Checked "Projekt installieren" { & "$VenvPy" -m pip install --no-deps -e "$Root" }
    Invoke-Checked "Pruefwerkzeuge installieren" { & "$VenvPy" -m pip install -r "$DevLock" }
    Invoke-Checked "Abhaengigkeiten pruefen" { & "$VenvPy" -m pip check }
    Set-Content -LiteralPath $Marker -Value $WantHash -Encoding ASCII
}

$Cfg = Join-Path (Join-Path $Root "config") "rules.yaml"
if (-not (Test-Path -LiteralPath $Cfg)) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $Root "config") "rules.example.yaml") -Destination $Cfg
    Write-Host "config/rules.yaml aus Beispiel angelegt (capabilities: aus)."
}

Invoke-Checked "Datenordner anlegen" { & "$VenvPy" -c "from src import paths; paths.ensure_private_dir(paths.data_dir()); print('Datenordner (Tokens, Audit, Logs - ausserhalb des Projekts):', paths.data_dir())" }
Write-Host "Bootstrap abgeschlossen. Standardmodus bleibt DRY-RUN."
