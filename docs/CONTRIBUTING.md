# 贡献指南

感谢关注 Vibe Guard（vibe-sec-platform）！本指南说明协作流程与本地开发环境。

## 协作流程

所有变更走 **Issue → 分支 → Pull Request → CI → Review** 流程：

1. **先开 Issue**：描述问题（Bug）或提案（Feature），等待维护者确认方向，避免重复劳动。
2. **拉分支开发**：从 `main` 拉出分支，命名建议 `feat/xxx`、`fix/xxx`、`docs/xxx`、`chore/xxx`。
3. **提交 Pull Request**：PR 描述关联对应 Issue（如 `Closes #12`），说明改动内容与验证方式。
4. **CI 必须通过**：GitHub Actions 会在 Ubuntu + Windows 双平台运行 `ruff check . --select F,E9`（错误级 lint）与全量 `pytest tests/ -q`。
5. **维护者 Review 合并**：至少一名维护者批准后合并。

### 提交信息约定

使用 Conventional Commits 风格（类型可用中文描述正文）：

```
feat: 新增 xxx 能力
fix: 修复 xxx 在 Windows 下的路径问题
docs: 修正 README 项目结构
chore: 补充治理文件
ci: 增加测试工作流
```

## 本地开发

环境要求：Python 3.11+（Windows / Linux / macOS 均可）。

```bash
# 创建独立虚拟环境
python -m venv .venv
# Windows
.venv/Scripts/activate
# Linux/macOS
source .venv/bin/activate

# 安装开发依赖
pip install -e ".[dev]"

# 运行全量测试
pytest tests/ -q

# 仅运行错误级 lint（与 CI 一致）
ruff check . --select F,E9

# 可选：完整 lint 与格式化
ruff check .
black .
```

工具镜像与运行时准备见 README「快速开始」；`vibe-sec doctor --json` 可检查本机就绪状态。

## 代码与文档约定

- **文档与代码同步**：改动涉及目录结构、CLI 参数、公共接口或配置项时，同步更新 README 与 `docs/` 相关文档。历史教训：README 中的项目结构与示例必须与实际代码一致，示例代码应可直接运行。
- **行为变更需测试**：Bug 修复附带回归测试；新能力附带覆盖其核心路径的测试。
- **跨平台**：CI 在 Ubuntu 与 Windows 双平台运行，注意路径分隔符、编码（统一 UTF-8）与时钟精度差异。
- **安全边界**：不要在代码、示例、日志或测试中引入真实凭据；密钥一律通过环境变量或 Secret 文件注入。

## 安全问题

不要通过公开 Issue 报告安全漏洞，请按 [SECURITY.md](../SECURITY.md) 的渠道私密报告。

## 目录导览

- `core/` 核心引擎；`agents/` 领域 Agent；`api/` REST API；`skill/` Claude Code Skill 入口
- 架构文档见 `docs/ARCHITECTURE.md` 与 `docs/PRODUCT_ARCHITECTURE_V2.md`
- 插件开发见 `docs/PLUGIN_DEVELOPMENT.md`
