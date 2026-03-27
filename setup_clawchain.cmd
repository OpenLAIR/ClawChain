@echo off
setlocal EnableExtensions
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_clawchain.ps1" %*
exit /b %ERRORLEVEL%
