# note

项目工作要点归档目录。

## 目录结构

- `research/` — 调研报告
  - [2026-10-24-开源发布调研报告.md](research/2026-10-24-开源发布调研报告.md)：开源发布前的健康检查、测试验证、竞品调研与优化路线图
- `release/` — 版本发布说明
  - [0.5.0.md](release/0.5.0.md)：v0.5.0 开源首发布说明
  - [0.6.0.md](release/0.6.0.md)：v0.6.0 离线韧性 + VAmPI 短板召回
- `report/perf/` — 性能测试报告（暂无）

## 快速事实

- 仓库：https://github.com/dxz0069/vibe-guard（包名 vibe-sec-platform，CLI 为 `vibe-sec`）
- 环境：Python ≥3.11（依赖 `tomllib` 标准库），开发依赖 `pip install -e ".[dev]"`
- 测试：`.venv/Scripts/python -m pytest tests/ -q`；Windows 首跑需注意 tree-sitter 解析器要从 GitHub 下载
- CI：`.github/workflows/ci.yml`，Ubuntu + Windows 双矩阵，门禁为 `ruff --select F,E9` + pytest
- 换行符：仓库统一 LF（见 `.gitattributes`），PowerShell 脚本保持 CRLF
- tree-sitter 离线：`VIBE_SEC_TREE_SITTER_CACHE` 共享缓存 / `VIBE_SEC_DISABLE_TREE_SITTER=1` 全降级，见 README 安装节
