$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
Set-Location $RootDir
if ($env:PYTHONPATH) {
  $env:PYTHONPATH = "$RootDir;$env:PYTHONPATH"
} else {
  $env:PYTHONPATH = $RootDir
}
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
  & $python.Source scripts/platform_smoke.py --platform windows @args
  exit $LASTEXITCODE
}
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
  & $py.Source -3 scripts/platform_smoke.py --platform windows @args
  exit $LASTEXITCODE
}
throw "Neither 'python' nor 'py' launcher is available on PATH."
