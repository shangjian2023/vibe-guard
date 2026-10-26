# Vibe Guard (Vibe Sec Platform)

[![CI](https://github.com/dxz0069/vibe-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/dxz0069/vibe-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)

面向 Vibe Coding 范式的安全审查验证平台，以 Claude Code Skill 形式嵌入 AI 辅助开发全流程。

> **English** — Vibe Guard is a security audit & verification platform for the Vibe Coding era. It embeds into AI-assisted development as a Claude Code Skill / CLI, models the compound runtime surface (code · prompts · tools · permissions) with a four-plane graph (VRTM), runs deterministic multi-agent review with tri-state verification (vulnerable / fixed / legitimate-control), and returns AI-consumable remediation bundles instead of PDF reports.

> 仓库名为 **vibe-guard**，代码包名与文档中沿用 **vibe-sec-platform**（安装后 CLI 为 `vibe-sec`），二者指同一项目。

**版本**: v0.6.0 | **状态**: ✅ 所有阶段完成（Phase 1-5），工程验证版（本地单人 Beta），成熟度自评见 [docs/CURRENT_PROJECT_STATUS_2026-08-01.md](docs/CURRENT_PROJECT_STATUS_2026-08-01.md)

## 项目定位

- **目标用户**: 独立开发者 / 小团队
- **核心接入方式**: Claude Code Skill 优先
- **审查范围**: 传统 Web 漏洞 + 智能体特有漏洞（提示词注入、MCP 风险、越权、密钥泄露）
- **验证深度**: AI 驱动验证（静态 + 动态 + Fuzzing + 浏览器证据）
- **输出格式**: 可配置多格式（Claude Code 原生、Markdown、JSON）

## 核心特性

### 1. 确定性编排

借鉴 AutoCVE 的成熟架构，强制执行固定的审查流程：

```
Recon → Surface → Audit(并行) → Merge → Verify → Remediate → Retest
```

- 不让 LLM 决定主要阶段
- Agent 间通过 TaskHandoff 结构化交接
- 支持并行审计和验证

### 2. 智能体漏洞审查

专门针对 AI 智能体的安全审查能力：

- **提示词注入检测**: 直接注入、间接注入、越狱攻击
- **MCP 安全审计**: 不安全的 MCP Server、工具权限过大、数据泄露
- **越权访问检测**: 身份认证绕过、权限提升、角色混淆
- **密钥泄露检测**: 硬编码密钥、API Key、私钥暴露

### 3. 混合验证机制

根据风险等级自动选择验证方式：

| 风险等级 | 验证方式 |
|---------|---------|
| High (CVSS 7.0+) | 动态执行 + Fuzzing + 浏览器证据 |
| Medium (CVSS 4.0-6.9) | 静态分析 + 动态执行（沙箱） |
| Low (CVSS < 4.0) | 静态分析 |

### 4. 整改闭环

完整的审查-验证-整改-复测闭环：

- 生成 RemediationBundle（整改包）
- 提供 ai_patch_prompt（AI 修复指令）
- Skill Relay 状态机追踪整改包流转
- 自动复测验证修复效果

## 系统架构

### 五层架构

```
┌──────────────────────────────────────────────────────────────────────┐
│  L5 接入层 (Integration Layer)                                       │
│  Claude Code Skill / CLI / REST API (可选 Web UI)                    │
└──────────────────────────────────────────────────────────────────────┘
                                 ↓
┌──────────────────────────────────────────────────────────────────────┐
│  L4 编排层 (Orchestration Layer)                                     │
│  Deterministic Orchestrator + TaskHandoff + ReasoningGuard           │
└──────────────────────────────────────────────────────────────────────┘
                                 ↓
┌──────────────────────────────────────────────────────────────────────┐
│  L3 智能体层 (Agent Layer)                                           │
│  Recon / Surface / Audit / Verification / Remediation / Regression   │
└──────────────────────────────────────────────────────────────────────┘
                                 ↓
┌──────────────────────────────────────────────────────────────────────┐
│  L2 能力层 (Capability Layer)                                        │
│  RuntimeSurface / RiskChain / VerificationHarness / Skill KB         │
└──────────────────────────────────────────────────────────────────────┘
                                 ↓
┌──────────────────────────────────────────────────────────────────────┐
│  L1 基础设施层 (Infrastructure Layer)                                │
│  ToolRuntime / SessionStore / EvidenceArchive / FindingStore         │
└──────────────────────────────────────────────────────────────────────┘
```

### 核心组件

- **OrchestratorAgent**: 确定性编排器
- **ReconAgent**: 信息收集
- **SurfaceAgent**: 攻击面建模
- **AuditAgent**: 漏洞审查（支持并行）
- **VerificationAgent**: 漏洞验证
- **RemediationAgent**: 整改建议生成
- **RegressionAgent**: 回归测试

## 快速开始

### 安装

将源码包交给编程助手后，由仓库内的确定性 bootstrap 完成 Python 环境、CLI 和工具镜像准备。不要让助手自行拼装 Docker 命令。

Windows：

```powershell
scripts/setup.ps1
.venv/Scripts/vibe-sec.exe doctor --json
```

Linux/macOS：

```bash
sh scripts/setup.sh
.venv/bin/vibe-sec doctor --json
```

默认安装并校验 `vibe-sec-tools`、离线 `vibe-sec-trivy` 和精选模板 `vibe-sec-nuclei`。CodeQL 是显式可选能力：

```powershell
vibe-sec setup --include-codeql --json
```

安装和更新由 `manifests/tool-images.lock.json` 锁定。`doctor` 只报告凭据是否配置，不读取或输出 Key；只有状态为 `READY` 的镜像能力会暴露给智能体。

AST 审计通道依赖 tree-sitter 解析器，首次使用会从 GitHub 下载（`setup` 自动预热，`doctor --json` 的 `tree_sitter` 段报告就绪状态）。离线或受限网络环境：

- 设置 `VIBE_SEC_TREE_SITTER_CACHE` 指向预置解析器缓存目录，可直接拷贝已下载缓存（当前缓存位置见 `doctor --json` 输出的 `tree_sitter.cache_dir` 字段）；
- 或设置 `VIBE_SEC_DISABLE_TREE_SITTER=1` 跳过全部 AST 通道，平台自动降级到文本/正则分析，不会中断审计。

### Docker 一键部署

Docker 部署提供 Web 前端、REST API、SQLite 状态和 VRTM 快照的统一运行边界：

```powershell
scripts/deploy.ps1 -Build -Detach
```

Linux/macOS：

```bash
sh scripts/deploy.sh --build --detach
```

默认将仓库下的 `projects/` 只读挂载为容器内的 `/workspace`，访问
`http://localhost:8000`。自定义目录可设置 `VIBE_SEC_PROJECTS_PATH`；容器不会
启动靶场，默认审查路径也不会修改项目源码（显式 `model-init` 除外）。需要 LLM 时使用外部 Secret 文件：

```powershell
$env:VIBE_SEC_DEEPSEEK_API_KEY_FILE = "C:\secrets\deepseek.key"
scripts/deploy.ps1 -Build -Detach -LlmSecretFile $env:VIBE_SEC_DEEPSEEK_API_KEY_FILE
```

完整部署说明见 `docs/DEPLOYMENT.md`。默认 Compose 不挂载 Docker Socket，因此
容器扫描器仍应由已授权的宿主机 Runner 执行。

### 交给 Agent 一句话部署

将源码包交给 Codex、Claude Code 或其他具备终端权限的 Agent 后，直接发送：

> 请在当前仓库执行 `scripts/agent-one-click-deploy.ps1 -Agent codex`（Linux/macOS 执行 `sh scripts/agent-one-click-deploy.sh --agent codex`），完成 Docker 构建、启动本地 Web UI、安装 `vibe-sec` Skill，并把健康检查结果和访问地址返回给我。

脚本会自动创建 `projects/`、启动 `api` 和 `web`、安装 Skill，并等待
`/api/health` 返回 200。默认访问地址为 `http://localhost:8000`。完整边界和
其他 Agent 选项见 `docs/AGENT_ONE_CLICK_DEPLOY.md`。

开发环境可额外安装测试依赖：

```bash
pip install -e ".[dev]"
```

### 使用

#### 作为 Claude Code Skill 使用

1. 执行 `scripts/install-agent-skill.ps1 -Agent claude-code`，或 Linux/macOS 下执行 `sh scripts/install-agent-skill.sh claude-code`。
2. 编程助手按照 Skill 先运行 `vibe-sec doctor --json`，未就绪时调用仓库 bootstrap。
3. 在 Claude Code 中输入安全审查请求。

Codex 使用 `-Agent codex`；项目级安装使用 `-Agent project`。安装器默认拒绝覆盖已有 Skill，只有明确传入 `-Force` 或 `--force` 才会更新。

```
用户: 请对这个 Flask 应用进行安全审查
```

#### 作为 Python 库使用

```python
from core.orchestrator.orchestrator import OrchestratorAgent, OrchestrationConfig
from core.agents.registry import AgentRegistry
from core.llm.openai_service import OpenAIService

# 初始化
llm_service = OpenAIService(api_key="your-api-key")
registry = AgentRegistry()

# 注册 Agent
registry.register(AgentType.RECON, ReconAgent)
registry.register(AgentType.SURFACE, SurfaceAgent, dependencies=[AgentType.RECON])
registry.register(AgentType.AUDIT, AuditAgent, dependencies=[AgentType.SURFACE])

# 创建编排器
orchestrator = OrchestratorAgent(
    llm_service=llm_service,
    agent_registry=registry,
    config=OrchestrationConfig(),
)

# 执行审查
result = await orchestrator.run({
    "project_path": "/path/to/project",
    "audit_scope": {
        "web_vulns": True,
        "agent_vulns": True,
        "secret_leaks": True,
    },
    "output_format": "markdown",
})

# 获取结果
print(result.data["summary"])
print(f"发现 {len(result.data['verified_findings'])} 个漏洞")
```

## 项目结构

```
vibe-sec-platform/
├── skill/                              # Claude Code Skill 入口
│   ├── SKILL.md                        # Skill 控制文件
│   ├── metadata.json                   # Skill 元数据
│   └── references/                     # 知识库（渐进式披露）
│       ├── catalog.json                # 漏洞类别目录
│       ├── checklists/                 # 漏洞检查清单
│       │   ├── web/                    # Web 漏洞
│       │   ├── agent/                  # Agent 漏洞
│       │   └── secrets/                # 密钥泄露
│       ├── patterns/                   # 漏洞模式库
│       ├── adapters/                   # 语言适配器
│       └── examples/                   # 真实案例
│
├── core/                               # 核心基础设施
│   ├── agents/
│   │   ├── base.py                     # BaseAgent + TaskHandoff
│   │   ├── registry.py                 # Agent 注册中心
│   │   └── executor.py                 # Agent 执行器
│   ├── orchestrator/
│   │   └── orchestrator.py             # 确定性编排器
│   ├── runtime/
│   │   ├── tool_runtime.py             # 工具运行时
│   │   ├── permission_policy.py        # 权限策略
│   │   └── session_store.py            # 会话存储
│   ├── surface/
│   │   ├── runtime_surface.py          # 攻击面画像
│   │   ├── runtime_surface_graph.py    # 攻击面关系图
│   │   └── risk_chain.py               # 风险链
│   ├── reasoning/
│   │   └── reasoning_guard.py          # 推理监护
│   ├── verification/
│   │   ├── harness.py                  # 验证沙箱
│   │   ├── fuzzing.py                  # Fuzzing Harness
│   │   └── browser_executor.py         # 浏览器证据采集
│   ├── remediation/
│   │   ├── remediation_bundle.py       # 整改包生成
│   │   └── skill_relay.py              # Skill Relay 状态机
│   └── reporting/
│       ├── unified_report.py           # 统一报告生成
│       └── output_formatter.py         # 多格式输出
│
├── agents/                             # 智能体实现
│   ├── recon_agent.py
│   ├── surface_agent.py
│   ├── audit_agent.py
│   ├── verification_agent.py
│   ├── remediation_agent.py
│   └── regression_agent.py
│
├── tools/                              # 工具实现
│   ├── base.py
│   ├── file_tools.py
│   ├── analysis_tools.py
│   ├── execution_tools.py
│   └── knowledge_tools.py
│
├── api/                                # REST API (可选)
│   ├── main.py
│   ├── routes/
│   └── models/
│
├── tests/                              # 测试
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│
└── docs/                               # 文档
    ├── ARCHITECTURE.md
    ├── SKILL_DEVELOPMENT.md
    └── CONTRIBUTING.md
```

## 技术栈

- **语言**: Python 3.11+
- **Web 框架**: FastAPI（可选 REST API）
- **LLM 调用**: OpenAI 兼容 API / Anthropic Claude
- **浏览器自动化**: Playwright
- **容器化**: Docker（沙箱执行）
- **测试**: pytest
- **文档**: Markdown

## 实施路线图

### Phase 1: MVP ✅

**目标**: 实现核心审查流程，支持 Web 漏洞检测

- ✅ 项目骨架搭建
- ✅ BaseAgent 基类和 TaskHandoff
- ✅ OrchestratorAgent 确定性编排
- ✅ ReconAgent 信息收集
- ✅ AuditAgent（Web 漏洞）
- ✅ 静态分析工具
- ✅ Markdown 报告生成
- ✅ 端到端测试（5 个漏洞检测）

### Phase 2: 增强验证 ✅

**目标**: 实现混合验证机制，支持动态执行

- ✅ SurfaceAgent 攻击面建模
- ✅ RuntimeSurface + RiskChain
- ✅ 动态执行验证（Docker 沙箱）
- ✅ FuzzingHarness 模糊测试
- ✅ VerificationAgent 漏洞验证
- ✅ PermissionPolicy 权限策略
- ✅ ReasoningGuard 推理监护

### Phase 3: Agent 漏洞审查 ✅

**目标**: 支持智能体特有漏洞审查

- ✅ Agent 漏洞知识库（OWASP Top 10 for LLM + MCP 安全清单）
- ✅ 提示词注入检测（prompt_injection）
- ✅ MCP 安全审计（mcp_insecurity）
- ✅ 过度代理检测（excessive_agency）
- ✅ 密钥泄露检测（hardcoded_password）
- ✅ 多格式输出（Markdown / JSON / Claude Code / HTML）
- ✅ 端到端测试（15 个漏洞检测，覆盖 Web + Agent）

### Phase 4: 整改闭环 ✅

**目标**: 实现完整的审查-验证-整改-复测闭环

- ✅ RemediationAgent 整改建议生成（7 种修复策略）
- ✅ RemediationBundle 整改包（ai_patch_prompt + patch_constraints + retest_plan + acceptance_criteria）
- ✅ Skill Relay 状态机（draft → dispatched → acknowledged → in_progress → completed → returned）
- ✅ RegressionAgent 回归测试（漏洞修复验证 + 功能完整性 + 副作用检测）
- ✅ 完整的 7 阶段流程（Recon → Surface → Audit → Merge → Verify → Remediate → Regression）
- ✅ 端到端测试（15 个漏洞 → 15 个整改包 → 15 个回归测试报告）

### Phase 5: 优化与扩展 ✅

**目标**: 性能优化、可扩展性、社区贡献

- ✅ 缓存系统（多级缓存：内存缓存 + 文件缓存）
- ✅ 插件系统（DetectionRulePlugin / ReportFormatPlugin / VerificationPlugin / RemediationPlugin）
- ✅ REST API（FastAPI，Swagger UI / ReDoc 自动文档）
- ✅ 文档完善（API 文档 / 插件开发指南 / 架构文档）

## 借鉴来源

本项目借鉴了两个参考项目的设计：

### AutoCVE（智能体编排架构）

- 确定性 Orchestrator 编排
- TaskHandoff 结构化交接
- FindingAgent 候选队列状态机
- FinalizeFinding 终止工具
- Nudge 纠偏机制
- Skill 渐进式披露
- Fuzzing Harness 验证

### lz-secure（安全审查能力）

- RuntimeSurface 攻击面画像
- RuntimeSurfaceGraph 关系图
- RiskChain 风险链
- PermissionPolicy 权限策略
- ReasoningGuard 推理监护
- Skill Relay 状态机
- Browser Executor 证据采集
- Remediation Bundle 整改包

## 许可证

MIT License

## 贡献

欢迎贡献代码、报告问题或提出改进建议！

请参阅 [CONTRIBUTING.md](docs/CONTRIBUTING.md) 了解详情。

## 联系方式

- 项目主页: https://github.com/dxz0069/vibe-guard
- 问题反馈: https://github.com/dxz0069/vibe-guard/issues
