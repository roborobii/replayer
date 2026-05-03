@echo off
REM Phase 2 replay launcher. Double-click to run.
REM Plays back recording_smoke5 against Mac emulator.
setlocal
set RECORDING_ID=smoke5
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Users\RC3\replay\play-rc3.ps1" -RecordingId %RECORDING_ID%
echo.
echo [start.bat] done. Press any key to close.
pause >nul
