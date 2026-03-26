@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
set "PORT=%~1"
if "%PORT%"=="" set "PORT=8888"
if "%HOST%"=="" set "HOST=127.0.0.1"

cd /d "%ROOT_DIR%"
set "PYTHONPATH=%ROOT_DIR%"

echo [clawchain] starting UI on http://%HOST%:%PORT%
python -m clawchain.agent_proxy_cli ui --host "%HOST%" --port "%PORT%"
