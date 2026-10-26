# 项目治理

## 维护者

| 角色 | 职责 |
| --- | --- |
| 仓库所有者（@dxz0069） | 架构决策、版本发布、主干合并 |
| 团队维护者 | 功能开发、文档与治理、评测与质量保障 |

维护者列表以 GitHub 仓库协作者为准；新维护者由现有维护者提名并在本文件登记职责后生效。

## 决策机制

- **日常变更**（Bug 修复、文档、工具链）：遵循 [CONTRIBUTING.md](docs/CONTRIBUTING.md) 的 PR 流程，一名维护者批准即可合并。
- **架构级变更**（编排流程调整、接口契约变更、新增核心模块）：先开 Issue 写清动机与方案，两名维护者达成一致后再实施。
- **版本发布**：由仓库所有者执行，发布说明归档于 `note/release/`。

## 路线图

- 阶段性规划见 README「实施路线图」与 `docs/V2_IMPLEMENTATION_PLAN.md`。
- 每个版本发布时在 `note/release/<version>.md` 记录变更与已知限制。

## 贡献者成长路径

持续贡献的社区成员在获得两名维护者认可后可成为协作者（Collaborator）；贡献指南见 [CONTRIBUTING.md](docs/CONTRIBUTING.md)。
