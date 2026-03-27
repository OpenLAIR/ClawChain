param(
  [int]$Port = 8888
)

$ErrorActionPreference = "Stop"

function Get-EnvOrDefault {
  param(
    [string]$Name,
    [string]$DefaultValue
  )
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    return $DefaultValue
  }
  return $value
}

function Get-OptionalEnv {
  param([string]$Name)
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    return $null
  }
  return $value
}

function Test-TruthyEnv {
  param(
    [string]$Name,
    [bool]$DefaultValue = $false
  )
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    return $DefaultValue
  }
  switch ($value.Trim().ToLowerInvariant()) {
    "1" { return $true }
    "true" { return $true }
    "yes" { return $true }
    "on" { return $true }
    default { return $false }
  }
}

$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RootDir
if ([string]::IsNullOrEmpty($env:PYTHONPATH)) {
  $env:PYTHONPATH = $RootDir
} else {
  $env:PYTHONPATH = "$RootDir;$env:PYTHONPATH"
}

$AccountId = Get-EnvOrDefault -Name "CLAWCHAIN_ACCOUNT_ID" -DefaultValue "local-operator"
$Password = Get-EnvOrDefault -Name "CLAWCHAIN_PASSWORD" -DefaultValue "local-operator"
$Workspace = Get-EnvOrDefault -Name "CLAWCHAIN_WORKSPACE" -DefaultValue $RootDir
$RootParent = Get-OptionalEnv -Name "CLAWCHAIN_ROOT_PARENT"
$RequireChain = Test-TruthyEnv -Name "CLAWCHAIN_REQUIRE_CHAIN" -DefaultValue $false
$SkipChain = Test-TruthyEnv -Name "CLAWCHAIN_SKIP_CHAIN_BOOTSTRAP" -DefaultValue $false
$AutoInstallFoundry = Test-TruthyEnv -Name "CLAWCHAIN_AUTO_INSTALL_FOUNDRY" -DefaultValue $true
$AnvilPath = Get-OptionalEnv -Name "CLAWCHAIN_ANVIL_PATH"
$ForgePath = Get-OptionalEnv -Name "CLAWCHAIN_FORGE_PATH"
$DeployerPrivateKey = Get-OptionalEnv -Name "CLAWCHAIN_DEPLOYER_PRIVATE_KEY"

$python = Get-Command python -ErrorAction SilentlyContinue
$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($python) {
  $PythonExe = $python.Source
  $PythonPrelude = @()
} elseif ($pyLauncher) {
  $PythonExe = $pyLauncher.Source
  $PythonPrelude = @("-3")
} else {
  throw "Neither 'python' nor 'py' launcher is available on PATH."
}

$WorkspacePath = (Resolve-Path -LiteralPath $Workspace).Path
$UserHome = [Environment]::GetFolderPath("UserProfile")
if ($RootParent) {
  $AccountRoot = Join-Path $RootParent $AccountId
} else {
  $AccountRoot = Join-Path (Join-Path $UserHome ".clawchain-agent") $AccountId
}
$ConfigPath = Join-Path $AccountRoot "agent-proxy.config.json"

function Invoke-ClawChain {
  param(
    [string[]]$CliArgs,
    [switch]$AllowFailure
  )
  $display = ($PythonPrelude + @("-m", "clawchain.agent_proxy_cli") + $CliArgs) -join " "
  Write-Host "[setup] $PythonExe $display"
  $commandOutput = & $PythonExe @PythonPrelude -m clawchain.agent_proxy_cli @CliArgs 2>&1
  $exitCode = $LASTEXITCODE
  foreach ($line in @($commandOutput)) {
    if ($null -ne $line) {
      Write-Host $line
    }
  }
  if (-not $AllowFailure -and $exitCode -ne 0) {
    throw "command failed with exit code $exitCode"
  }
  return $exitCode
}

if (Test-Path -LiteralPath $ConfigPath) {
  $null = Invoke-ClawChain -CliArgs @("service-stop", $ConfigPath) -AllowFailure
}

$deployArgs = @(
  "deploy",
  $AccountId,
  $Password,
  "--workspace",
  $WorkspacePath,
  "--no-start-service"
)
if ($RootParent) {
  $deployArgs += @("--root-dir", $RootParent)
}
if (-not $AutoInstallFoundry) {
  $deployArgs += "--no-auto-install-foundry"
}
if ($AnvilPath) {
  $deployArgs += @("--anvil-path", $AnvilPath)
}
if ($ForgePath) {
  $deployArgs += @("--forge-path", $ForgePath)
}
$null = Invoke-ClawChain -CliArgs $deployArgs

$chainOk = $false
if (-not $SkipChain) {
  $chainArgs = @(
    "chain-connect",
    $AccountId,
    "--bootstrap-local-evm"
  )
  if ($RootParent) {
    $chainArgs += @("--root-dir", $RootParent)
  }
  if ($DeployerPrivateKey) {
    $chainArgs += @("--deployer-private-key", $DeployerPrivateKey)
  }
  $chainExit = Invoke-ClawChain -CliArgs $chainArgs -AllowFailure
  if ($chainExit -eq 0) {
    $chainOk = $true
  } elseif ($RequireChain) {
    throw "chain bootstrap failed and CLAWCHAIN_REQUIRE_CHAIN is enabled"
  } else {
    Write-Warning "chain bootstrap failed; continuing with local setup and UI startup"
  }
}

$null = Invoke-ClawChain -CliArgs @("service-start", $ConfigPath)
$null = Invoke-ClawChain -CliArgs @("service-status", $ConfigPath)
if ($chainOk) {
  $chainStatusArgs = @("chain-status", $AccountId)
  if ($RootParent) {
    $chainStatusArgs += @("--root-dir", $RootParent)
  }
  $null = Invoke-ClawChain -CliArgs $chainStatusArgs -AllowFailure
}

Write-Host "[setup] account: $AccountId"
Write-Host "[setup] account root: $AccountRoot"
Write-Host "[setup] config path: $ConfigPath"
Write-Host "[setup] workspace: $WorkspacePath"
if ($SkipChain) {
  Write-Host "[setup] chain bootstrap: skipped"
} elseif ($chainOk) {
  Write-Host "[setup] chain bootstrap: ok"
} else {
  Write-Host "[setup] chain bootstrap: warning"
}
Write-Host "[setup] launching UI on port $Port"
& (Join-Path $RootDir 'run_clawchain_ui.cmd') $Port
exit $LASTEXITCODE
