<div align="center">
  <img src="assets/logo/ClawChain.png" alt="ClawChain logo" width="148">
  <h1>ClawChain</h1>
  <p><strong>面向高权限 AI Coding Agent 的安全、可恢复、可追溯运行时控制层。</strong></p>
  <p>
    ClawChain 将原本不透明的 Agent 会话转化为可监控、可恢复、可导出 proof、可链上校验的执行流程。
  </p>
  <p>
    <a href="README.md">English</a> · <a href="DEVELOPER.md">开发者文档</a>
  </p>
</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/Validated-Codex-111827?style=for-the-badge" alt="Validated Codex" />
  <img src="https://img.shields.io/badge/Validated-Claude%20Code-C2410C?style=for-the-badge" alt="Validated Claude Code" />
  <img src="https://img.shields.io/badge/Recovery-Snapshot%20Backed-0F766E?style=for-the-badge" alt="Snapshot-backed recovery" />
  <img src="https://img.shields.io/badge/Chain-EVM%2031337-7C3AED?style=for-the-badge" alt="EVM 31337" />
</p>

## Dashboard

<p align="center">
  <img src="assets/screenshots/dashboard.png" alt="ClawChain dashboard" width="1200">
</p>

这个 dashboard 是 ClawChain 的主要操作界面，用于发现会话、`Join Monitor`、查看危险操作、执行恢复、导出 proof，以及检查链状态。

## 项目概述

ClawChain 是一层面向 AI Coding Agent 的运行时安全控制层，针对的是能够直接在真实机器上执行命令的高权限 Agent。

它聚焦解决四类在真实终端环境里很难处理的问题：

- 会话执行过程不透明
- 危险操作之后证据容易丢失
- 文件或目录被破坏后恢复不完整
- 事故发生后难以做统一溯源

ClawChain 将这些会话转成一个受控运行环境，并提供：

- 受控接管与 handoff
- 危险操作捕获
- 基于 snapshot 的恢复材料保留
- 可读 proof 导出
- 可选的 EVM 锚定与校验

这个项目不是一个单纯的区块链演示。链后端的作用是增强危险操作 proof 的完整性，真正的产品主体是围绕监控、恢复、证据和验证构建的控制平面。

## 已验证的 Agent 支持

### 当前已验证

- Codex
  已打通端到端主流程，包括监控、恢复、proof 导出和链校验。
- Claude Code
  已打通真实 session 识别、受控重拉起、删除恢复、proof 导出和 EVM 校验。

### 可扩展接入路径

当前运行时已经抽象出共享的 adapter 层，用于支持更多 shell 风格 agent。后续新 agent 可以通过扩展 profile 模型接入，而不需要复制旧的 launcher 逻辑。

## 核心能力

- 发现正在运行的 Agent 会话
- 将会话纳入受控监控路径
- 在损失永久发生前检测危险操作
- 保留基于 snapshot 的恢复材料
- 恢复被影响的文件或目录
- 面向单个会话导出可读 proof 日志
- 在本地或 EVM 后端上校验 proof 字段
- 在统一 UI 中查看会话、活动、恢复、proof 和链状态

## 支持平台

- Linux
- Windows
- macOS 使用 Unix shell 启动路径

Linux 和 Windows 已经对主监控流程完成验证，包括 setup、service、UI、恢复、proof 导出和本地 EVM bootstrap。

## 仓库结构

- `clawchain/`
  运行时、监控、恢复、proof、UI、链集成和 agent adapter 逻辑。
- `assets/`
  GitHub 展示所用的 logo、图示和 dashboard 截图。
- `contracts/`
  本地 EVM 锚定使用的 `CommitmentAnchor.sol` 及 ABI。
- `scripts/`
  平台 smoke、EVM smoke 和 adapter 验证辅助脚本。
- `setup_clawchain.cmd`
  Windows 一键 setup 入口。
- `setup_clawchain.sh`
  Linux/macOS 一键 setup 入口。
- `DEVELOPER.md`
  更详细的架构、实现细节和测试文档。

## 环境要求

- Python 3.12
- `pip`
- Git
- 如果需要本地链锚定：
  - 优先使用 Foundry：`anvil`、`forge`
  - Docker 仅作为可选兜底

## 安装

```bash
conda create -y -n ClawChain python=3.12 pip
conda activate ClawChain
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

setup 会自动完成这些动作：

1. 停掉当前账号可能存在的旧 service
2. 创建或刷新账号配置
3. 在可用时执行本地 EVM bootstrap
4. 启动后台 service
5. 检查 service 状态
6. 拉起 UI

如果你希望链 bootstrap 失败就直接终止 setup，可以启用严格模式。

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

如果 setup 是在 SSH 会话中启动的，`run_clawchain_ui.sh` 会自动切换到适合远程访问的绑定方式，并打印正确的浏览器地址。

## 第一次完整监控流程

### Codex 或 Claude Code

1. 启动一个新的 Agent 会话。
2. 打开 ClawChain UI。
3. 点击 `Join Monitor`。
4. 后续只在 ClawChain 接管后的 terminal 中继续操作。
5. 执行一次删除类高危操作。
6. 回到 UI 确认这次操作出现在 history 中。
7. 点击 `Restore`。
8. 导出 proof 日志。
9. 如果本地链已经 bootstrap，确认 proof 中出现 EVM 相关字段。

对一份成功上链的 proof，通常应该看到这些字段：

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

### 手动执行链 bootstrap

```bash
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

### 查看链状态

```bash
python -m clawchain.agent_proxy_cli chain-status local-operator
```

### Claude adapter smoke

```bash
python scripts/smoke_claude_adapter.py
```

### 平台 smoke

#### Linux / macOS

```bash
bash scripts/run_linux_smoke.sh
bash scripts/run_linux_smoke.sh --bootstrap-local-evm
```

#### Windows

```bat
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1
powershell -ExecutionPolicy Bypass -File scripts/run_windows_smoke.ps1 --bootstrap-local-evm
```

### EVM smoke

```bash
bash scripts/run_evm_smoke.sh
```

## Foundry 说明

ClawChain 在所有平台上都优先使用本地 Foundry。

bootstrap 顺序如下：

1. 显式指定的 `anvil` 和 `forge` 路径
2. 当前账号目录下的托管 Foundry toolchain
3. 从官方 release 自动下载 Foundry
4. 可用时再回退到 Docker

### Windows 手动 Foundry 兜底方案

如果 Windows 上的 Foundry 自动下载失败，可以手动安装后重新执行 chain bootstrap。

#### 方式 1：直接下载官方 release 资产

打开 Foundry 最新 release 页面：

- <https://github.com/foundry-rs/foundry/releases/latest>

下载类似下面命名的 Windows 资产：

- `foundry_v<version>_win32_amd64.zip`

解压出 `anvil.exe` 和 `forge.exe`，然后任选一种方式：

- 放到系统 `PATH` 中，或
- 拷到当前账号的 ClawChain 托管 toolchain 目录

默认托管目录：

```text
%USERPROFILE%\.clawchain-agent\local-operator\_internal\chain\toolchains\foundry\bin
```

#### 方式 2：显式配置二进制路径

```bat
set CLAWCHAIN_ANVIL_PATH=C:\path\to\anvil.exe
set CLAWCHAIN_FORGE_PATH=C:\path\to\forge.exe
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

如果 bootstrap 仍然失败，可以直接运行：

```bat
python -m clawchain.agent_proxy_cli chain-connect local-operator --bootstrap-local-evm
```

然后检查 JSON 输出中的这些诊断字段：

- `bootstrap_diagnostics.anvil_path`
- `bootstrap_diagnostics.forge_path`
- `bootstrap_diagnostics.managed_foundry_bin_dir`
- `bootstrap_diagnostics.managed_foundry_bin_contents`
- `bootstrap_diagnostics.managed_foundry_install_error`

## Proof 预期

对一份新鲜上链的 session proof，通常应该满足：

- `format = clawchain-proof-log.v2`
- `exported_at` 是完整 ISO 8601 时间戳
- `session.status = monitored`
- snapshot 路径位于 `recovery-vault/recovery-snapshots`
- 恢复后的操作会显示 `restored = true`
- `proof_cards[].anchor_backend = evm:31337`
- `proof_cards[].anchor_mode = evm-anchored`
- `proof_cards[].anchor_status = confirmed`

## 进一步阅读

- [README.md](README.md)
- [DEVELOPER.md](DEVELOPER.md)
