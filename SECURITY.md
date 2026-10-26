# 安全策略

## 支持版本

| 版本 | 支持状态 |
| --- | --- |
| 0.5.x | ✅ 支持 |

## 报告漏洞

**请不要通过公开 Issue 报告安全漏洞。**

请使用 GitHub 的私密安全报告功能（仓库页 *Security → Report a vulnerability*），或直接联系维护者私密传递。报告时请尽量包含：

- 受影响的组件与文件路径
- 复现步骤或 PoC
- 影响评估与建议修复方向

我们会在确认后尽快回复，修复发布前不会公开披露细节。

## 报告范围

- **范围内**：`vibe-sec-platform` 自身代码（`core/`、`agents/`、`api/`、`skill/`、`scripts/` 等）的安全缺陷，包括审计绕过、凭据处理不当、沙箱/权限边界失效。
- **范围外**：上游扫描器（semgrep、trivy、nuclei、gitleaks、bandit、CodeQL）自身的漏洞，请报告至对应上游仓库。

## 平台自身的安全设计要点

- `vibe-sec doctor` 只报告凭据**是否已配置**，不读取、不输出任何 API Key。
- LLM 凭据通过环境变量或 Docker Secret 文件注入，不落盘、不进日志。
- 默认 Compose 部署**不挂载 Docker Socket**；容器扫描器应由已授权的宿主机 Runner 执行。
- 动态验证与整改闭环需要显式的短时效本地授权（`authorize-verification` / `approve-remediation`），高危整改包需要签名审批才能闭环。
- 审计默认路径不修改被审计项目源码（显式 `model-init` 除外），项目目录以只读方式挂载。
