@echo off
REM GMAIL-AUTOMATION - Startmenue. Dieses Skript aendert NIE das Postfach (kein APPLY).
setlocal EnableExtensions
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PY=%~dp0.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo Erste Einrichtung: virtuelle Umgebung wird angelegt ...
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\bootstrap.ps1"
  if errorlevel 1 goto :failed
)

:menu
echo.
echo  ============================================
echo   GMAIL-AUTOMATION   ^|   Modus: DRY-RUN
echo  ============================================
echo   [1] Doctor        - Umgebung und Sperren pruefen
echo   [2] Scan          - lesen + klassifizieren, keine Aenderung
echo   [3] Status        - letzte Laeufe + Audit
echo   [4] Anmelden      - Google-Login OBSERVE (nur lesen)
echo   [5] Verify        - alle Release-Gates offline pruefen
echo   [6] Beenden
echo.
choice /c 123456 /n /m "Auswahl: "
if errorlevel 6 goto :end
if errorlevel 5 ( powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\verify.ps1" & goto :menu )
if errorlevel 4 ( "%PY%" -m src.cli auth --profile observe & goto :menu )
if errorlevel 3 ( "%PY%" -m src.cli status & goto :menu )
if errorlevel 2 ( "%PY%" -m src.cli scan & goto :menu )
if errorlevel 1 ( "%PY%" -m src.cli doctor & goto :menu )
goto :menu

:failed
echo Einrichtung fehlgeschlagen - siehe Meldung oben.
pause
exit /b 1

:end
endlocal
exit /b 0
