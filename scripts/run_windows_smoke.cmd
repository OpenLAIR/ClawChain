@echo off
setlocal EnableExtensions
for %%I in ("%~dp0..") do set "ROOT_DIR=%%~fI"
if defined PYTHONPATH (
  set "PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%ROOT_DIR%"
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_windows_smoke.ps1" %*
