<div align="center">
  <img src="assets/logo/clawchain-logo.svg" alt="ClawChain logo" width="128" height="128">
  <h1>ClawChain</h1>
  <p><strong>面向高权限 AI Coding Agent 的安全、可恢复、可验证运行时控制层。</strong></p>
  <p>
    ClawChain 将原本不透明的终端 Agent 会话转化为可监控、可恢复、可链上校验的执行流程。
  </p>
  <p>
    <a href="README.md">English</a> · <a href="DEVELOPER.md">开发者文档</a>
  </p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Runtime-Agent%20Safety-111827?style=for-the-badge" alt="Runtime Agent Safety" />
  <img src="https://img.shields.io/badge/Recovery-Snapshot%20Backed-0F766E?style=for-the-badge" alt="Snapshot-backed recovery" />
  <img src="https://img.shields.io/badge/Chain-EVM%20Verifiable-7C3AED?style=for-the-badge" alt="EVM verifiable" />
</p>

## Dashboard

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="ClawChain dashboard" width="1200">
</p>

这个 dashboard 是 ClawChain 的主要操作界面，用于发现会话、`Join Monitor`、查看危险操作、执行恢复、导出 proof，以及检查链状态。

## 项目简介

ClawChain 是一层面向 AI Coding Agent 的运行时安全控制层，针对的是能够直接在真实机器上执行命令的高权限 Agent。

当前阶段，它的核心目标很明确：

- 发现正在运行的 Agent 会话
- 将会话纳入受控监控路径
- 检测删除类高危操作
- 在损失永久发生前保留恢复材料
- 将被删除的文件或目录恢复回来
- 导出可读的 proof 日志
- 将关键 proof 字段锚定到 EVM，并支持后续校验

这个项目不是一个单纯的区块链演示。链只是用来增强证据完整性，真正的产品主体是围绕监控、恢复、证据和验证构建的控制平面。

## 当前能力范围

### 当前稳定支持

- Codex 是目前最成熟的端到端主路径
- Linux 和 Windows 都支持主监控流程
- 提供 Linux/macOS 和 Windows 的一键 setup 脚本
- 删除检测、快照恢复、proof 导出和 EVM 校验已经打通

### 当前有意保持收敛

- 恢复能力目前聚焦于删除类破坏操作
- 其他风险类型可以记录用于审计，但不宣称已经具备通用回滚能力
- 代码里已经有更多 agent 的兼容面，但成熟度并不完全一致

## 核心能力

- 受控的会话接管、恢复命令和 handoff 命令
- 基于 recovery vault 的删除恢复
- 面向单个会话的可读 proof 导出
- 本地加密 proof 归档
- 本地 EVM bootstrap 和链上验证
- Linux / Windows 跨平台 service 与 daemon 流程
- 会话、活动、恢复、proof 和链状态的统一 UI

## 仓库结构

- `clawchain/`
  主运行时代码，包括监控、恢复、proof、UI 和链集成。
- `contracts/`
  本地 EVM 锚定使用的 `CommitmentAnchor.sol` 及 ABI。
- `scripts/`
  smoke 脚本和验证辅助脚本。
- `demo/delete-smoke/`
  删除 / 恢复测试用的小型示例资源。
- `setup_clawchain.cmd`
  Windows 一键 setup 入口。
- `setup_clawchain.sh`
  Linux/macOS 一键 setup 入口。
- `DEVELOPER.md`
  详细开发、测试和验收文档。

## 环境要求

- Python 3.12
- `pip`
- Git
- 如果需要本地链锚定：
  - 优先使用 Foundry：`anvil`、`forge`
  - Docker 仅作为可选兜底，不是主路径

## 安装

```bash
conda create -y -n ClawChain python=3.12 pip
conda activate ClawChain
```

```bash
cd <repo-root>
pip install -r requirements.txt
pip install -e .
```

## 快速部署

### Windows

```bat
setup_clawchain.cmd 8888
```

### Linux / macOS

```bash
bash setup_clawchain.sh 8888
```

setup 脚本会自动执行这些步骤：

1. 停掉当前账号可能存在的旧 service
2. 创建或刷新账号配置
3. 尝试执行本地 EVM bootstrap
4. 启动后台 service
5. 检查 service 状态
6. 拉起 UI

默认情况下，setup 对链 bootstrap 是尽力而为模式。如果你希望链 bootstrap 失败就直接终止 setup，可以启用严格模式。

### Windows 严格模式

```bat
set CLAWCHAIN_REQUIRE_CHAIN=1
setup_clawchain.cmd 8888
```

### Linux / macOS 严格模式

```bash
CLAWCHAIN_REQUIRE_CHAIN=1 bash setup_clawchain.sh 8888
```

## 打开 UI

### 本机访问

```text
http://127.0.0.1:8888
```

### 远程 Linux 主机访问

如果你是在 SSH 会话里运行 Linux 版 setup，`run_clawchain_ui.sh` 会自动切换到适合远程访问的绑定方式，并打印正确的远程访问地址。

## 第一次完整监控流程

1. 启动或找到一个正在运行的 Codex 会话
2. 打开 ClawChain UI
3. 点击 `Join Monitor`
4. 在该会话里执行一次删除类高危操作
5. 回到 UI 确认这次操作出现在 history 中
6. 点击 `Restore`
7. 导出 proof 日志
8. 如果本地链已经 bootstrap，确认 proof 中出现 EVM 相关字段

对一份新鲜、成功上链的 proof，通常应该看到这些字段：

- `anchor_backend: "evm:31337"`
- `anchor_mode: "evm-anchored"`
- `anchor_status: "confirmed"`
- `anchor_lookup_found: true`
- `anchor_field_checks.session_id = true`
- `anchor_field_checks.batch_seq_no = true`
- `anchor_field_checks.merkle_root = true`

## 常用命令

### 单独启动 UI

```bash
python -m clawchain.agent_proxy_cli ui --host 127.0.0.1 --port 8888
```

### Windows UI 启动器

```bat
run_clawchain_ui.cmd 8888
```

### Linux/macOS UI 启动器

```bash
bash run_clawchain_ui.sh 8888
```

### 手动执行链 bootstrap

```bash
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### 查看链状态

```bash
python -m clawchain.agent_proxy_cli chain-status local-operator
```

### Smoke 验证

#### Linux / macOS

```bash
bash scripts/run_linux_smoke.sh
bash scripts/run_linux_smoke.sh --bootstrap-local-evm
```

#### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1 --bootstrap-local-evm
```

## Windows 上 Foundry 自动下载失败时的手动方案

ClawChain 在 Windows 上优先使用本地 Foundry。如果自动下载失败，通常表示当前机器无法访问 GitHub Releases，或者 release 资源下载被网络策略拦截。

默认账号 `local-operator` 对应的 ClawChain 托管 Foundry 目录是：

```text
%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin
```

ClawChain 实际只需要这两个文件：

- `anvil.exe`
- `forge.exe`

### 方案 A：用 PowerShell 自动下载最新官方 Windows 包

在 PowerShell 中执行：

```powershell
$toolRoot = Join-Path $env:USERPROFILE ".clawchain-agent\local-operator\_internal\chain\toolchains\foundry"
$binDir = Join-Path $toolRoot "bin"
$zipPath = Join-Path $env:TEMP "clawchain-foundry.zip"
$unpackDir = Join-Path $env:TEMP "clawchain-foundry-unpack"

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Remove-Item $unpackDir -Recurse -Force -ErrorAction SilentlyContinue

$release = Invoke-RestMethod -Headers @{ "User-Agent" = "clawchain-manual-foundry" } `
  -Uri "https://api.github.com/repos/foundry-rs/foundry/releases/latest"
$asset = $release.assets |
  Where-Object { $_.name -match 'win32_amd64\.zip$' } |
  Select-Object -First 1
if (-not $asset) { throw "No Windows Foundry asset found in the latest release." }

Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
Expand-Archive -Path $zipPath -DestinationPath $unpackDir -Force
Copy-Item (Get-ChildItem $unpackDir -Recurse -Filter anvil.exe | Select-Object -First 1).FullName $binDir -Force
Copy-Item (Get-ChildItem $unpackDir -Recurse -Filter forge.exe | Select-Object -First 1).FullName $binDir -Force
```

然后重新执行：

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### 方案 B：在另一台机器下载后手工拷贝

如果当前 Windows 主机完全无法访问 GitHub：

1. 在能访问网络的机器上打开：
   `https://github.com/foundry-rs/foundry/releases/latest`
2. 下载后缀为 `win32_amd64.zip` 的 Windows 资源包
3. 解压
4. 将 `anvil.exe` 和 `forge.exe` 拷贝到：
   `%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin`
5. 回到当前机器，重新执行：

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### 方案 C：你已经在别的位置安装了 Foundry

如果系统里已有 Foundry，也可以直接把路径显式告诉 ClawChain：

```bat
set CLAWCHAIN_ANVIL_PATH=C:\tools\foundry\anvil.exe
set CLAWCHAIN_FORGE_PATH=C:\tools\foundry\forge.exe
setup_clawchain.cmd 8888
```

也可以在 `deploy` 时显式传参：

```bat
python -m clawchain.agent_proxy_cli deploy local-operator local-operator ^
  --workspace E:\path\to\workspace ^
  --anvil-path C:\tools\foundry\anvil.exe ^
  --forge-path C:\tools\foundry\forge.exe ^
  --no-start-service
```

Foundry 官方参考：

- https://github.com/foundry-rs/foundry/releases/latest
- https://api.github.com/repos/foundry-rs/foundry/releases/latest
- https://getfoundry.sh/reference/forge/forge.html

## 常见问题

### UI 看起来还是旧进程

直接在同一个端口上重新运行 UI 启动命令即可。当前启动器会尝试替换占用该端口的旧进程。

### Windows setup 提示 chain bootstrap failed

先执行这个诊断命令：

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

重点看这些 JSON 字段：

- `bootstrap_diagnostics.anvil_path`
- `bootstrap_diagnostics.forge_path`
- `bootstrap_diagnostics.managed_foundry_bin_contents`
- `bootstrap_diagnostics.managed_foundry_install_error`

### 导出的 proof 还是 `local-json`

这通常说明你导出的仍然是旧会话的 proof，而不是链 bootstrap 完成之后新创建的监控会话。请新开一个被监控的会话，再重新执行一次删除、恢复和导出。

## 开发者文档

详细架构、开发流程、测试矩阵、proof 验收标准和调试说明见 [DEVELOPER.md](DEVELOPER.md)。
