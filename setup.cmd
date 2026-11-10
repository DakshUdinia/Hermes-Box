@echo off
title Hermes Box - One-Click Setup Wizard
echo Starting Hermes Box Installer...
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install.ps1" %*
) else (
  powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install.ps1" %*
)
pause
