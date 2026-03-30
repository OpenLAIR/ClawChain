$ErrorActionPreference = "Stop"

# Resolve repo root robustly regardless of how the script is invoked
if ($PSScriptRoot -and $PSScriptRoot -ne "") {
    $RootDir = Split-Path -Parent $PSScriptRoot
} else {
    $RootDir = (Get-Location).Path
}

Write-Host "[smoke] repo root: $RootDir"
Set-Location $RootDir

if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$RootDir;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = $RootDir
}

$scriptPath = "$RootDir\scripts\dangerous_ops_smoke.py"
if (-not (Test-Path $scriptPath)) {
    throw "Script not found: $scriptPath"
}

$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    Write-Host "[smoke] using python: $($python.Source)"
    & $python.Source $scriptPath @args
    exit $LASTEXITCODE
}
$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    Write-Host "[smoke] using py launcher"
    & $py.Source -3 $scriptPath @args
    exit $LASTEXITCODE
}
throw "Neither 'python' nor 'py' launcher is available on PATH."
