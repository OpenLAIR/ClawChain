@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8888"
if "%HOST%"=="" set "HOST=127.0.0.1"

where python >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_EXE=python"
  set "PYTHON_FLAG="
) else (
  where py >nul 2>nul
  if not errorlevel 1 (
    set "PYTHON_EXE=py"
    set "PYTHON_FLAG=-3"
  ) else (
    echo [clawchain] python or py launcher is required on PATH 1>&2
    exit /b 1
  )
)

cd /d "%ROOT_DIR%"
if defined PYTHONPATH (
  set "PYTHONPATH=%ROOT_DIR%;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%ROOT_DIR%"
)

echo [clawchain] starting UI on http://%HOST%:%PORT%
"%PYTHON_EXE%" %PYTHON_FLAG% -m clawchain.agent_proxy_cli ui --host "%HOST%" --port "%PORT%" --replace-existing
