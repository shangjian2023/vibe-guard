# 第三方组件声明

Vibe Guard 通过容器化方式集成多个开源安全工具；本项目**不修改、也不再分发**这些工具的二进制制品，镜像均从官方发布渠道构建（官方基础镜像 / 锁定版本的包管理器安装 / SHA-256 校验的官方 release 包，见 `container/*/Dockerfile`）。

## 容器化安全工具

| 工具 | 用途 | 许可证 | 集成方式 |
| --- | --- | --- | --- |
| semgrep | 静态分析 | LGPL-2.1 | pip 锁定版本装入独立容器进程，独立运行、未做链接修改 |
| trivy | 依赖/镜像漏洞扫描 | Apache-2.0 | 官方镜像制品 + 离线 DB 预下载 |
| nuclei | 服务暴露检测 | MIT | 官方 release（SHA-256 校验）+ 精选模板 |
| gitleaks | 密钥泄露扫描 | MIT | 官方镜像制品 |
| bandit | Python 静态分析 | Apache-2.0 | pip 锁定版本装入独立容器进程 |
| CodeQL（可选） | 深度代码查询 | GitHub CodeQL 条款 | 显式 `--include-codeql` 才安装，仅用于开源项目的合规用途 |

各工具许可证以上游仓库为准；semgrep 为 LGPL-2.1，本项目以独立容器进程方式调用、不对其源码进行静态/动态链接，规避 LGPL 传染路径。

## Python 运行时依赖

`pyproject.toml` 声明的运行时依赖均为主流宽松许可（MIT / Apache-2.0 / BSD 系），完整清单以该文件为准。

## 前端依赖

见 `frontend-v2/package-lock.json`（npm 自动生成的完整依赖树与许可元数据）。

## 知识库内容

`skill/references/checklists/` 与 `knowledge_base/` 中的检查清单为项目原创编写，方法论参考 OWASP 系列公开标准，遵循其引用规范。
