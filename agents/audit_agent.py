"""
Vibe Sec Platform — Audit Agent

漏洞审计 Agent，负责：
1. 基于攻击面画像进行漏洞审查
2. 支持 Web 漏洞、Agent 漏洞、密钥泄露等多种漏洞类型
3. 使用候选队列状态机管理审查进度
4. 生成结构化的 Findings
"""

import ast
import asyncio
import hashlib
import os
import re
import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from core.agents.base import (
    AgentConfig,
    AgentPattern,
    AgentResult,
    AgentType,
    BaseAgent,
    Severity,
)
from core.audit.lanes import group_findings_by_lane
from core.audit.candidate_cluster import cluster_candidates
from core.audit.models import EvidenceBundle
from core.audit.protocol_analysis import iter_protocol_signals
from core.audit.react_discovery import ReActAuditDiscovery
from core.audit.react_review import ReActFindingReviewer
from core.llm_errors import classify_llm_failure
from core.audit.scanner_signals import ContainerScannerCollector, DependencyVulnerabilityCollector
from core.audit.target_planner import AuditTargetPlanner
from core.sanitization import redact_sensitive_text


logger = logging.getLogger(__name__)


class AuditPhase(Enum):
    """审计阶段"""
    EVIDENCE_COLLECTION = "evidence_collection"
    REPORT_FINALIZATION = "report_finalization"


class CandidateStatus(str, Enum):
    """候选漏洞生命周期状态。

    使用枚举约束防止拼写错误静默失效。
    """
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    NEEDS_EVIDENCE = "needs_evidence"
    CANDIDATE_CONFIRMED = "candidate_confirmed"
    REJECTED = "rejected"

    @classmethod
    def validate(cls, value: str) -> str:
        """验证并规范化状态字符串，无效值抛出 ValueError。"""
        normalized = value.strip().lower()
        try:
            return cls(normalized).value
        except ValueError as err:
            valid = sorted(item.value for item in cls)
            raise ValueError(
                f"Invalid CandidateStatus {value!r}. Must be one of: {valid}"
            ) from err


@dataclass
class CandidateCase:
    """候选漏洞案例"""
    id: str
    vulnerability_type: str
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.5
    status: str = CandidateStatus.OPEN.value

    def __post_init__(self) -> None:
        # 构造时验证 status，拼写错误立即抛出 ValueError
        self.status = CandidateStatus.validate(self.status)


@dataclass
class AuditState:
    """审计状态"""
    phase: AuditPhase = AuditPhase.EVIDENCE_COLLECTION
    candidates: List[CandidateCase] = field(default_factory=list)
    confirmed_findings: List[Dict[str, Any]] = field(default_factory=list)
    rejected_candidates: List[Dict[str, Any]] = field(default_factory=list)


class AuditAgent(BaseAgent):
    """
    漏洞审计 Agent

    支持多种漏洞类型的审计，使用候选队列状态机管理审查进度。

    Example:
        agent = AuditAgent(
            config=AgentConfig(
                name="Audit",
                agent_type=AgentType.AUDIT,
            ),
            llm_service=llm_service,
        )

        result = await agent.run({
            "project_path": "/path/to/project",
            "audit_scope": {"web_vulns": True, "agent_vulns": False},
            "surface_handoff": "...",
        })
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        llm_service=None,
        tools=None,
        event_emitter=None,
    ):
        if config is None:
            config = AgentConfig(
                name="Audit",
                agent_type=AgentType.AUDIT,
                pattern=AgentPattern.REACT,
                max_iterations=30,
            )

        super().__init__(
            config=config,
            llm_service=llm_service,
            tools=tools,
            event_emitter=event_emitter,
        )

        self.audit_state = AuditState()
        self.finding_counter = 0

        # Web 漏洞模式（简化版）
        self.web_vulnerability_patterns = {
            "sql_injection": {
                "patterns": [
                    r'execute\(.*?\+.*?\)',
                    r'query\(.*?\+.*?\)',
                    r'raw\(.*?%.*?\)',
                    r'f".*?SELECT.*?\{.*?\}.*?"',
                    r"f'.*?SELECT.*?\{.*?\}.*?'",
                    r'execute\(.*?["\']%\w+["\']',
                    # 查询字符串在 execute 调用之外拼接（q = "...WHERE x = " + input，
                    # 含 '= "' 这类双引号收尾写法）。
                    r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"\'\n]*["\']{1,2}\s*\+\s*[\w.\[\](]',
                    r'\+\s*["\']{1,2}[^"\'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
                    # % 格式化的 SQL（"... = %s" % user_id），占位符不必紧贴引号。
                    r'\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"\'\n]*["\']{1,2}\s*%\s*[\w(\[]',
                ],
                "severity": Severity.HIGH,
                "description": "可能的 SQL 注入：用户输入直接拼接到查询中",
            },
            "mass_assignment": {
                "patterns": [
                    # 特权字段（admin/role 等）从请求数据取值：User(..., admin=data.get('admin'))
                    r'\b(?:admin|is_admin|is_superuser|is_staff|role)\s*=\s*[\w.]*\.get\(',
                    r'\b(?:admin|is_admin|is_superuser|is_staff|role)\s*=\s*(?:request|payload|body|form|args|params|json|data)\b',
                ],
                "severity": Severity.HIGH,
                "description": "可能的特权字段自赋值：请求数据未经允许清单直接写入 admin/role 等特权字段",
            },
            "plaintext_password_comparison": {
                "patterns": [
                    # 只匹配与存储凭据对象（x.password 属性）的比较，避免把
                    # 注册表单的"密码确认"比对（data['password'] == data['confirm']）误报。
                    r'\.\s*password\s*==',
                    r'==\s*\w+\.\s*password\b',
                ],
                "severity": Severity.MEDIUM,
                "description": "可能的明文密码比较：疑似未哈希存储的密码被直接比对",
            },
            "xss": {
                "patterns": [
                    r'innerHTML\s*=',
                    r'document\.write\(',
                    r'\{\{.*?\|safe.*?\}\}',
                    r'dangerouslySetInnerHTML',
                    r'\.html\(.*?\+',
                    r'\.html\(\$\(.*?\)',
                ],
                "severity": Severity.MEDIUM,
                "description": "可能的 XSS：未转义的内容渲染",
            },
            "command_injection": {
                "patterns": [
                    r'os\.system\(',
                    r'subprocess\.call\(.*shell=True',
                    r'subprocess\.Popen\(.*shell=True',
                ],
                "severity": Severity.CRITICAL,
                "description": "可能的命令注入：用户输入被用于系统命令执行",
            },
            "code_injection": {
                "patterns": [
                    # Match global dynamic-evaluation APIs only.  A generic
                    # ``exec(`` pattern also matches harmless methods such as
                    # ``RegExp.prototype.exec()``, while ``eval(`` matches
                    # names such as ``safeEval()``.
                    r'(?<![\w$.])eval\s*\(',
                    r'(?<![\w$.])(?-i:Function)\s*\([^\n]*(?:request|req\.|body|query|input|payload|params?)',
                    # A VM context is not by itself code injection.  Keep the
                    # signal when the context executes an evaluator path,
                    # rather than a fixed parser call such as XML parsing.
                    r'\bvm\.runIn(?:Context|NewContext|ThisContext)\s*\(\s*[\'\"][^\'\"]*(?:(?<![\w$.])eval|safeEval|(?-i:Function))\s*\(',
                ],
                "severity": Severity.CRITICAL,
                "description": "可能的代码注入：用户输入被用于动态代码执行",
            },
            "path_traversal": {
                "patterns": [
                    r'(?:os\.path\.join|path\.(?:join|resolve)|Path)\s*\(',
                    r'(?:open|send_file|send_from_directory|read_text|read_bytes|readFile(?:Sync)?|createReadStream|sendFile)\s*\([^\n)]*(?:request\.|req\.)',
                ],
                "severity": Severity.HIGH,
                "description": "可能的路径遍历：用户输入被用于文件路径",
            },
        }

        # Agent 特有漏洞模式（Phase 3 新增）
        self.agent_vulnerability_patterns = {
            "prompt_injection": {
                "patterns": [
                    # 直接的提示词注入风险
                    r'(user_input|user_message|query).*?\.format\(',
                    r'(prompt|message)\s*\+\s*(user|input|query)',
                    r'f["\'].*?(user_input|query|message).*?["\']',
                    # 缺少系统提示保护
                    r'(?<!ignore\s)(?<!do\snot\sfollow).*system.*prompt',
                    # 动态提示词构建
                    r'(\w+)\s*\+\s*(user|input|query|message)',
                ],
                "severity": Severity.HIGH,
                "description": "可能的提示词注入风险：用户输入被拼接到提示词中",
            },
            "mcp_insecurity": {
                "patterns": [
                    # 不安全的 MCP 工具定义
                    r'(tool|function)\s*=.*\{.*?["\']description["\'].*?(ignore|override|forget|disregard)',
                    # 缺少确认机制的工具
                    r'(tool|function).*(execute|delete|remove|drop|update).*?(?!confirm)',
                    # 过度权限
                    r'(permissions|access)\s*=\s*["\'].*\*.*["\']',
                    # 无限制的工具调用
                    r'tool.*\(\s*\)\s*.*(?:while\s+True|for\s+\w+\s+in\s+range\(.*\))',
                ],
                "severity": Severity.HIGH,
                "description": "MCP 工具安全风险：缺少安全控制机制",
            },
            "excessive_agency": {
                "patterns": [
                    # 过度自主决策
                    r'(autonomous|auto|auto_?decide|self_?determine)',
                    # 缺少人在回路
                    r'(no_?human|without_?approval|skip.*check|bypass)',
                    # 无限制的副作用
                    r'(tool|action).*(write|delete|execute|send|modify).*?(?!confirm)',
                    # 过度权限范围
                    r'(permissions|role)\s*=\s*["\']admin["\']',
                ],
                "severity": Severity.HIGH,
                "description": "过度代理风险：智能体被授予过多权限或缺少人工监督",
            },
        }

        self.workflow_vulnerability_patterns = {
            "ssrf": {
                "patterns": [
                    r"(?:requests\.(?:get|post)|httpx\.(?:get|post)|fetch)\s*\([^\n]*(?:request|user|input|url)",
                    r"urllib\.request\.urlopen\s*\([^\n]*(?:request|user|input|url)",
                ],
                "severity": Severity.HIGH,
                "description": "可能的 SSRF：外部输入控制服务端网络目标",
            },
            "unsafe_deserialization": {
                "patterns": [
                    r"pickle\.loads?\s*\(",
                    r"yaml\.load\s*\([^\n]*(?!SafeLoader)",
                    r"ObjectInputStream\s*\(",
                ],
                "severity": Severity.HIGH,
                "description": "可能的不安全反序列化：不可信数据进入对象反序列化器",
            },
            "workflow_insecurity": {
                "patterns": [
                    r"run:\s*[^\n]*\$\{\{\s*github\.event\.",
                    r"(?:exec|eval|os\.system|subprocess\.(?:run|Popen))\s*\([^\n]*(?:workflow|event|payload|input)",
                ],
                "severity": Severity.HIGH,
                "description": "可能的工作流注入：外部事件数据进入命令或代码执行节点",
            },
        }

        # 密钥泄露模式
        self.secret_patterns = {
            "hardcoded_password": {
                "patterns": [
                    r'password\s*=\s*["\'][^"\']+["\']',
                    r'passwd\s*=\s*["\'][^"\']+["\']',
                    r'pwd\s*=\s*["\'][^"\']+["\']',
                ],
                "severity": Severity.HIGH,
                "description": "硬编码的密码",
            },
            "api_key": {
                "patterns": [
                    r'api_key\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
                    r'API_KEY\s*=\s*["\'][a-zA-Z0-9]{20,}["\']',
                    r'secret_key\s*=\s*["\'][^"\']+["\']',
                ],
                "severity": Severity.HIGH,
                "description": "硬编码的 API Key 或密钥",
            },
        }

    @staticmethod
    def _llm_failure_category(error: Any) -> str:
        """Classify provider failures without retaining provider response text."""
        return classify_llm_failure(error)

    async def run(self, payload: Dict[str, Any]) -> AgentResult:
        """
        执行漏洞审计

        Args:
            payload: 包含以下字段：
                - project_path: 项目路径
                - audit_scope: 审计范围配置
                - surface_handoff: 攻击面分析的交接信息（可选）

        Returns:
            AgentResult 包含发现的漏洞
        """
        self.audit_state = AuditState()
        self.finding_counter = 0
        project_path = payload.get("project_path")
        audit_scope = payload.get("audit_scope", {"web_vulns": True, "agent_vulns": True, "secret_leaks": True})

        if not project_path:
            return AgentResult.failure_result("project_path is required")

        logger.info(f"Starting audit for project: {project_path}")
        logger.info(f"Audit scope: {audit_scope}")

        try:
            # 1. 静态分析：模式匹配
            if audit_scope.get("web_vulns", True):
                await self._scan_web_vulnerabilities(project_path)

            if audit_scope.get("secret_leaks", True):
                await self._scan_secret_leaks(project_path)

            if audit_scope.get("agent_vulns", True):
                await self._scan_agent_vulnerabilities(
                    project_path, {"prompt_injection", "excessive_agency"}
                )

            if audit_scope.get("mcp_vulns", False):
                await self._scan_agent_vulnerabilities(project_path, {"mcp_insecurity"})
                self._scan_protocol_signals(project_path, "mcp_audit")

            if audit_scope.get("workflow_vulns", False):
                await self._scan_workflow_vulnerabilities(project_path)
                self._scan_protocol_signals(project_path, "workflow_audit")

            scanner_stats = {
                "enabled": bool(payload.get("enable_container_tools", False)),
                "signal_count": 0,
                "executions": [],
                "artifact_refs": [],
                "gaps": [],
            }
            if scanner_stats["enabled"]:
                collection = await ContainerScannerCollector(
                    project_path,
                    image=str(payload.get("container_tool_image") or os.getenv(
                        "VIBE_SEC_TOOL_IMAGE", "vibe-sec-tools:latest"
                    )),
                ).collect(str(payload.get("audit_lane", "web_audit")))
                scanner_stats = {"enabled": True, **collection.to_dict()}
                self._ingest_scanner_signals(collection.signals)

            dependency_scanner_stats = {
                "enabled": bool(
                    payload.get("allow_dependency_network", False)
                    and payload.get("audit_lane") == "secrets_audit"
                ),
                "signal_count": 0,
                "executions": [],
                "artifact_refs": [],
                "gaps": [],
            }
            if dependency_scanner_stats["enabled"]:
                dependency_collection = await DependencyVulnerabilityCollector(project_path).collect()
                dependency_scanner_stats = {"enabled": True, **dependency_collection.to_dict()}
                self._ingest_scanner_signals(dependency_collection.signals)

            provider = str(getattr(self.llm_service, "provider", "")).lower()
            llm_enabled = bool(
                payload.get("use_llm", False)
                and self.llm_service
                and provider != "mock"
            )
            discovery_stats = {
                "status": "not_run",
                "candidates": 0,
                "tool_calls": 0,
                "coverage": {},
            }
            if payload.get("enable_react_discovery") and llm_enabled:
                try:
                    discovery_stats = await self._react_discover_candidates(project_path, payload)
                except Exception as error:
                    category = self._llm_failure_category(error)
                    logger.warning("LLM candidate discovery degraded: %s", category)
                    discovery_stats = {
                        "status": "degraded",
                        "reason": "llm_provider_unavailable",
                        "error_category": category,
                        "candidates": 0,
                        "tool_calls": 0,
                        "coverage": {},
                    }

            # 2. Review each deterministic or Agent-discovered candidate.
            react_review_stats = {
                "total": 0,
                "completed": 0,
                "degraded": 0,
                "failed": 0,
                "rejected": 0,
                "budget_skipped": 0,
            }
            if payload.get("enable_react_review") and llm_enabled and (
                self.audit_state.candidates or payload.get("_react_review_budget") is not None
            ):
                react_review_stats = await self._react_review_candidates(project_path, payload)
            elif llm_enabled and self.audit_state.candidates:
                await self._llm_deep_analysis(project_path, payload)

            # 3. 生成 Findings
            findings = await self._generate_findings()
            findings_by_lane = group_findings_by_lane(findings)

            # 4. 创建 TaskHandoff
            handoff = self.create_handoff(
                to_agent="verification",
                summary=f"审计完成。发现 {len(findings)} 个候选漏洞",
                work_completed=[
                    "Web 漏洞扫描",
                    "密钥泄露扫描",
                    "智能体漏洞扫描",
                    "LLM 深度分析",
                ],
                key_findings=[
                    {
                        "type": "findings_summary",
                        "total": len(findings),
                        "by_severity": self._count_by_severity(findings),
                    }
                ],
                insights=[
                    f"总共扫描了 {len(self.audit_state.candidates)} 个候选漏洞",
                    f"确认了 {len(findings)} 个漏洞",
                ],
                context_refs={
                    "findings": json.dumps(findings),
                },
            )

            return AgentResult.success_result(
                data={
                    "findings": findings,
                    "findings_by_lane": findings_by_lane,
                    "audit_summary": {
                        "total_candidates": len(self.audit_state.candidates),
                        "reportable_findings": len(findings),
                        "confirmed_findings": len([
                            finding for finding in findings
                            if finding.get("status") == "candidate_confirmed"
                        ]),
                        "needs_evidence_findings": len([
                            finding for finding in findings
                            if finding.get("status") == "needs_evidence"
                        ]),
                        "rejected_candidates": len(self.audit_state.rejected_candidates),
                        "react_reviews": react_review_stats["completed"],
                        "react_review_stats": react_review_stats,
                        "react_discovery": discovery_stats,
                        "container_scanners": scanner_stats,
                        "dependency_scanner": dependency_scanner_stats,
                        "lanes": {lane: len(items) for lane, items in findings_by_lane.items()},
                    },
                },
                handoff=handoff,
                tokens_used=0,
            )

        except Exception as e:
            logger.error(f"Audit failed: {e}", exc_info=True)
            return AgentResult.failure_result(f"Audit failed: {str(e)}")

    async def _react_discover_candidates(self, project_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        lane = str(payload.get("audit_lane", "web_audit"))
        raw_discovery_limit = payload.get("discovery_target_limit", 3)
        discovery_limit = int(3 if raw_discovery_limit is None else raw_discovery_limit)
        if discovery_limit <= 0:
            return {
                "status": "skipped",
                "reason": "discovery_target_budget_disabled",
                "candidates": 0,
                "tool_calls": 0,
                "coverage": {},
            }
        existing = [
            {
                "vulnerability_type": item.vulnerability_type,
                "file_path": item.file_path,
                "line_start": item.line_start,
                "description": item.description,
            }
            for item in self.audit_state.candidates
        ]
        planner = AuditTargetPlanner(project_path)
        targets = planner.plan(
            lane=lane,
            candidates=existing,
            surface_graph=payload.get("runtime_surface_graph", {}),
            threat_model=payload.get("threat_model", {}),
            changed_files=payload.get("changed_files", []),
            max_targets=discovery_limit,
            files_per_target=int(payload.get("discovery_files_per_target", 8) or 8),
        )
        semaphore = asyncio.Semaphore(max(1, int(payload.get("discovery_concurrency", 2) or 2)))

        async def run_target(target):
            async with semaphore:
                discovery = ReActAuditDiscovery(
                    self.llm_service,
                    project_path=project_path,
                    lane=lane,
                    surface_graph=payload.get("runtime_surface_graph", {}),
                    threat_model=payload.get("threat_model", {}),
                    target=target.to_dict(),
                    max_turns=max(2, min(
                        self.config.max_iterations,
                        int(payload.get("react_max_turns", 16) or 16),
                    )),
                    checkpoint_sink=payload.get("_react_checkpoint_sink"),
                    transition_sink=payload.get("_react_transition_sink"),
                    enable_container_tools=bool(payload.get("enable_container_tools", False)),
                    allow_dependency_network=bool(payload.get("allow_dependency_network", False)),
                )
                return await discovery.discover(
                    project_profile={
                        "prior_handoffs": payload.get("prior_handoffs", ""),
                        "audit_scope": payload.get("audit_scope", {}),
                    },
                    existing_candidates=existing,
                )

        results = await asyncio.gather(*(run_target(target) for target in targets))
        discovered = []
        existing_keys = {
            (item.vulnerability_type, item.file_path, item.line_start)
            for item in self.audit_state.candidates
        }
        clustered_candidates = cluster_candidates(
            item for result in results for item in result.candidates
        )
        for item in clustered_candidates:
            discovery_evidence = {
                "type": "agent_discovery",
                "description": item.get("description", ""),
                "artifact_refs": item.get("evidence_bundle", {}).get("artifact_refs", []),
                "metadata": item.get("discovery_metadata", {}),
            }
            existing_candidate = next((
                candidate for candidate in self.audit_state.candidates
                if candidate.vulnerability_type == item["vulnerability_type"]
                and candidate.file_path.replace("\\", "/") == item["file_path"].replace("\\", "/")
                and candidate.line_start <= item["line_end"] + 5
                and item["line_start"] <= candidate.line_end + 5
            ), None)
            if existing_candidate is not None:
                existing_candidate.evidence.extend([
                    *list(item.get("evidence", []) or []),
                    discovery_evidence,
                ])
                existing_candidate.confidence = max(existing_candidate.confidence, item["confidence"])
                continue

            key = (item["vulnerability_type"], item["file_path"], item["line_start"])
            if key in existing_keys:
                continue
            existing_keys.add(key)
            evidence = [*list(item.get("evidence", []) or []), discovery_evidence]
            discovered.append(CandidateCase(
                id=item["id"],
                vulnerability_type=item["vulnerability_type"],
                severity=Severity(item["severity"]),
                file_path=item["file_path"],
                line_start=item["line_start"],
                line_end=item["line_end"],
                description=item["description"] or item["title"],
                evidence=evidence,
                confidence=item["confidence"],
                status=CandidateStatus.NEEDS_EVIDENCE.value,
            ))
        self.audit_state.candidates = [*discovered, *self.audit_state.candidates]
        completed = sum(result.status == "completed" for result in results)
        tool_calls = sum(len(result.tool_records) for result in results)
        inventory = planner.source_inventory()
        examined_files = list(dict.fromkeys(
            file_path
            for result in results
            for file_path in result.coverage.get("files_examined", []) or []
        ))
        planned_seed_files = list(dict.fromkeys(
            file_path for target in targets for file_path in target.seed_files
        ))
        inventory_set = set(inventory)
        examined_inventory = [item for item in examined_files if item in inventory_set]
        examined_set = set(examined_inventory)
        uncovered = [item for item in inventory if item not in examined_set]
        coverage_summary = {
            "source_files_total": len(inventory),
            "planned_seed_files": len(planned_seed_files),
            "files_examined": len(examined_inventory),
            "source_coverage_ratio": len(examined_inventory) / len(inventory) if inventory else 1.0,
            "uncovered_files": len(uncovered),
            "uncovered_files_sample": uncovered[:50],
            "target_budget_exhausted": bool(
                uncovered and len(targets) >= discovery_limit
            ),
        }
        return {
            "status": "completed" if completed == len(results) else "partial",
            "candidates": len(discovered),
            "tool_calls": tool_calls,
            "targets": len(targets),
            "completed_targets": completed,
            "degraded_targets": len(results) - completed,
            "coverage": [result.coverage for result in results],
            "coverage_summary": coverage_summary,
            "summaries": [result.summary for result in results],
            "errors": [classify_llm_failure(result.error) for result in results if result.error],
        }

    async def _react_review_candidates(self, project_path: str, payload: Dict[str, Any]) -> Dict[str, int]:
        """Review candidates through observe -> tools -> evidence -> FinalizeFinding."""
        graph = payload.get("runtime_surface_graph", {})
        threat_model = payload.get("threat_model", {})
        hypotheses = list(threat_model.get("hypotheses", []))
        technique_by_vulnerability = {
            "prompt_injection": "T-PROMPT-INJECTION",
            "excessive_agency": "T-EXCESSIVE-AGENCY",
            "mcp_insecurity": "T-MCP-DESCRIPTION-INJECTION",
        }
        stats = {
            "total": 0,
            "completed": 0,
            "degraded": 0,
            "failed": 0,
            "rejected": 0,
            "budget_skipped": 0,
        }
        raw_review_limit = payload.get("react_review_limit")
        default_review_limit = min(30, max(8, len(self.audit_state.candidates)))
        limit = max(0, int(default_review_limit if raw_review_limit is None else raw_review_limit))
        semaphore = asyncio.Semaphore(max(1, int(payload.get("react_review_concurrency", 3) or 3)))
        shared_budget = payload.get("_react_review_budget")
        uses_global_selection = bool(
            shared_budget is not None
            and getattr(shared_budget, "uses_global_selection", False)
        )
        if uses_global_selection:
            selected_ids = await shared_budget.select_for_lane(
                str(payload.get("audit_lane", "default")),
                [
                    {
                        "id": candidate.id,
                        "severity": candidate.severity.value,
                        "confidence": candidate.confidence,
                        "order": index,
                    }
                    for index, candidate in enumerate(self.audit_state.candidates)
                ],
            )
            selected = [
                candidate for candidate in self.audit_state.candidates
                if candidate.id in selected_ids
            ]
            stats["budget_skipped"] = max(0, len(self.audit_state.candidates) - len(selected))
        else:
            selected = list(self.audit_state.candidates[:limit])

        async def review_one(candidate):
            if (
                shared_budget is not None
                and not uses_global_selection
                and not await shared_budget.claim()
            ):
                return candidate, None, "review_budget_exhausted"
            reviewer = ReActFindingReviewer(
                self.llm_service,
                project_path=project_path,
                surface_graph=graph,
                threat_model=threat_model,
                max_turns=max(2, min(
                    self.config.max_iterations,
                    int(payload.get("react_max_turns", 15) or 15),
                )),
                checkpoint_sink=payload.get("_react_checkpoint_sink"),
                transition_sink=payload.get("_react_transition_sink"),
                enable_container_tools=bool(payload.get("enable_container_tools", False)),
                allow_dependency_network=bool(payload.get("allow_dependency_network", False)),
            )
            candidate_payload = {
                "id": candidate.id,
                "title": candidate.description,
                "severity": candidate.severity.value,
                "vulnerability_type": candidate.vulnerability_type,
                "description": candidate.description,
                "file_path": candidate.file_path,
                "line_start": candidate.line_start,
                "line_end": candidate.line_end,
                "confidence": candidate.confidence,
                "evidence": candidate.evidence,
            }
            technique_id = technique_by_vulnerability.get(candidate.vulnerability_type)
            hypothesis = next(
                (item for item in hypotheses if item.get("technique_id") == technique_id),
                None,
            )
            try:
                async with semaphore:
                    result = await reviewer.review(candidate_payload, hypothesis=hypothesis)
                return candidate, result, None
            except Exception as error:
                return candidate, None, self._llm_failure_category(error)

        reviewed = await asyncio.gather(*(review_one(candidate) for candidate in selected))
        for candidate, result, failure_category in reviewed:
            if failure_category == "review_budget_exhausted":
                stats["budget_skipped"] += 1
                continue
            stats["total"] += 1
            if failure_category or result is None or result.status != "completed":
                stats["failed" if failure_category or result is None or result.status == "failed" else "degraded"] += 1
                candidate.status = CandidateStatus.NEEDS_EVIDENCE.value
                candidate.evidence.append({
                    "type": "react_review_gap",
                    "description": "Multi-turn review did not reach a validated FinalizeFinding action.",
                    "status": "failed" if failure_category or result is None or result.status == "failed" else "degraded",
                    "error_category": failure_category or self._llm_failure_category(result.error),
                    "tool_records": list(result.tool_records or []),
                })
                continue

            output = result.output
            stats[result.status] += 1
            verdict = str(output.get("verdict", "potential")).lower()
            if verdict == "unconfirmed":
                candidate.status = CandidateStatus.REJECTED.value
                stats["rejected"] += 1
                self.audit_state.rejected_candidates.append({
                    "id": candidate.id,
                    "vulnerability_type": candidate.vulnerability_type,
                    "file_path": candidate.file_path,
                    "line_start": candidate.line_start,
                    "reason": output.get("description", "Evidence did not support the candidate"),
                    "review_metadata": output.get("review_metadata", {}),
                })
            elif verdict in {"confirmed", "verified"}:
                candidate.status = CandidateStatus.CANDIDATE_CONFIRMED.value
            else:
                candidate.status = CandidateStatus.NEEDS_EVIDENCE.value
            if output.get("confidence") is not None:
                candidate.confidence = max(0.0, min(1.0, float(output["confidence"])))
            if output.get("severity") in {item.value for item in Severity}:
                candidate.severity = Severity(output["severity"])
            evidence_bundle = output.get("evidence_bundle", {})
            if isinstance(evidence_bundle, dict):
                candidate.evidence.extend(list(evidence_bundle.get("items", [])))
                candidate.evidence.extend({
                    "type": "react_evidence_gap",
                    "description": str(gap),
                } for gap in evidence_bundle.get("gaps", []) or [])
            candidate.evidence.append({
                "type": "react_finding_review",
                "verdict": verdict,
                "explanation": output.get("description", ""),
                "tool_records": result.tool_records,
                "review_metadata": output.get("review_metadata", {}),
            })
        return stats

    def _ingest_scanner_signals(self, signals: List[Dict[str, Any]]) -> None:
        for signal in signals:
            file_path = str(signal.get("file_path") or "")
            line_start = int(signal.get("line_start") or 1)
            line_end = int(signal.get("line_end") or line_start)
            rule_id = str(signal.get("rule_id") or signal.get("kind") or "scanner")
            vulnerability_type = self._scanner_vulnerability_type(rule_id, str(signal.get("kind", "")))
            if not file_path:
                continue
            severity = str(signal.get("severity", "medium")).lower()
            if severity not in {item.value for item in Severity}:
                severity = "medium"
            scanner_evidence = {
                "type": "scanner_signal",
                "tool_execution_id": signal.get("tool_execution_id"),
                "rule_id": rule_id,
                "artifact_refs": list(signal.get("artifact_refs", []) or []),
                "metadata": signal.get("metadata", {}),
            }
            existing = next((
                item for item in self.audit_state.candidates
                if item.vulnerability_type == vulnerability_type
                and item.file_path.replace("\\", "/").lower() == file_path.replace("\\", "/").lower()
                and item.line_start <= line_end + 5
                and line_start <= item.line_end + 5
            ), None)
            if existing is not None:
                if scanner_evidence not in existing.evidence:
                    existing.evidence.append(scanner_evidence)
                existing.confidence = max(
                    existing.confidence,
                    max(0.0, min(1.0, float(signal.get("confidence", 0.7) or 0.7))),
                )
                if self._severity_rank(Severity(severity)) > self._severity_rank(existing.severity):
                    existing.severity = Severity(severity)
                continue
            self.audit_state.candidates.append(CandidateCase(
                id=f"scanner-{len(self.audit_state.candidates)}",
                vulnerability_type=vulnerability_type,
                severity=Severity(severity),
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                description=str(signal.get("summary") or f"Scanner signal: {rule_id}"),
                evidence=[scanner_evidence],
                confidence=float(signal.get("confidence", 0.7) or 0.7),
                status=CandidateStatus.NEEDS_EVIDENCE.value,
            ))

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[severity]

    @staticmethod
    def _scanner_vulnerability_type(rule_id: str, kind: str) -> str:
        lowered = rule_id.lower()
        mappings = {
            "sql": "sql_injection",
            "xss": "xss",
            "command": "command_injection",
            "path": "path_traversal",
            "ssrf": "ssrf",
            "prompt": "prompt_injection",
            "mcp": "mcp_insecurity",
            "secret": "secret_leak",
            "api-key": "api_key",
            "osv-": "dependency_vulnerability",
        }
        for marker, value in mappings.items():
            if marker in lowered:
                return value
        if kind == "dependency_vulnerability":
            return "dependency_vulnerability"
        return "secret_leak" if kind == "secret_finding" else "scanner_finding"

    async def _scan_web_vulnerabilities(self, project_path: str) -> None:
        """扫描 Web 漏洞"""
        logger.info("Scanning web vulnerabilities")

        files_scanned = 0
        matches_found = 0

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'venv']]

            for file in files:
                if not file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.php', '.rb')):
                    continue

                file_path = os.path.join(root, file)
                files_scanned += 1
                logger.debug(f"Scanning file: {file_path}")

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    executable_call_offsets = (
                        self._python_dangerous_call_offsets(content)
                        if file.endswith('.py') else {}
                    )
                    for vuln_type, vuln_info in self.web_vulnerability_patterns.items():
                        for pattern in vuln_info["patterns"]:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                            for match in matches:
                                if (
                                    vuln_type in {"command_injection", "code_injection"}
                                    and file.endswith('.py')
                                    and match.start() not in executable_call_offsets.get(vuln_type, set())
                                ):
                                    # Regex supports every scanned language, but Python strings
                                    # and comments are not executable sinks.
                                    continue
                                is_path_traversal = vuln_type == "path_traversal"
                                if is_path_traversal and not self._is_path_traversal_signal(
                                    content, match.start(), match.end()
                                ):
                                    continue
                                matches_found += 1
                                line_num = content[:match.start()].count('\n') + 1
                                logger.debug(f"Found {vuln_type} at {file_path}:{line_num}")

                                candidate = CandidateCase(
                                    id=f"{vuln_type}-{len(self.audit_state.candidates)}",
                                    vulnerability_type=vuln_type,
                                    severity=vuln_info["severity"],
                                    file_path=os.path.relpath(file_path, project_path),
                                    line_start=line_num,
                                    line_end=line_num + match.group().count('\n'),
                                    description=vuln_info["description"],
                                    evidence=[
                                        {
                                            "type": "code_snippet",
                                            "content": match.group(),
                                            "line": line_num,
                                        }
                                    ],
                                    confidence=0.6,
                                )

                                self.audit_state.candidates.append(candidate)

                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
                    continue

        logger.info(f"Web vulnerability scan: scanned {files_scanned} files, found {matches_found} matches")
        logger.info(f"Total candidates after web scan: {len(self.audit_state.candidates)}")

    async def _scan_secret_leaks(self, project_path: str) -> None:
        """扫描密钥泄露"""
        logger.info("Scanning secret leaks")

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                if file.endswith(('.env', '.secret', '.key', '.pem')):
                    # 直接标记敏感文件
                    file_path = os.path.join(root, file)
                    candidate = CandidateCase(
                        id=f"secret_file-{len(self.audit_state.candidates)}",
                        vulnerability_type="sensitive_file",
                        severity=Severity.HIGH,
                        file_path=os.path.relpath(file_path, project_path),
                        line_start=1,
                        line_end=1,
                        description=f"发现敏感文件: {file}",
                        confidence=0.9,
                    )
                    self.audit_state.candidates.append(candidate)
                    continue

                if not file.endswith(('.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.php', '.rb', '.json', '.yaml', '.yml')):
                    continue

                file_path = os.path.join(root, file)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for secret_type, secret_info in self.secret_patterns.items():
                        for pattern in secret_info["patterns"]:
                            matches = re.finditer(pattern, content, re.IGNORECASE)

                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1

                                candidate = CandidateCase(
                                    id=f"{secret_type}-{len(self.audit_state.candidates)}",
                                    vulnerability_type=secret_type,
                                    severity=secret_info["severity"],
                                    file_path=os.path.relpath(file_path, project_path),
                                    line_start=line_num,
                                    line_end=line_num,
                                    description=secret_info["description"],
                                    evidence=[
                                        {
                                            "type": "code_snippet",
                                            "content": "[REDACTED]",
                                            "line": line_num,
                                            "secret_redacted": True,
                                            "fingerprint": hashlib.sha256(match.group().encode("utf-8")).hexdigest(),
                                            "matched_length": len(match.group()),
                                        }
                                    ],
                                    confidence=0.7,
                                )

                                self.audit_state.candidates.append(candidate)

                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
                    continue

    async def _scan_agent_vulnerabilities(
        self,
        project_path: str,
        vulnerability_types: Optional[set[str]] = None,
    ) -> None:
        """扫描智能体漏洞（增强版）"""
        logger.info("Scanning agent vulnerabilities")

        # 检查所有 Python/JavaScript/TypeScript 文件
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [
                d for d in dirs
                if not d.startswith('.')
                and d not in {
                    'node_modules', '__pycache__', 'venv', 'tests', 'test',
                    'fixtures', 'docs', 'static', 'dist', 'build',
                }
            ]

            for file in files:
                extensions = ('.py', '.js', '.jsx', '.ts', '.tsx', '.json', '.yaml', '.yml')
                if not file.endswith(extensions):
                    continue

                file_path = os.path.join(root, file)
                relative_path = Path(os.path.relpath(file_path, project_path)).as_posix()
                if self._is_ignored_agent_path(relative_path):
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # 扫描 Agent 特有漏洞模式
                    for vuln_type, vuln_info in self.agent_vulnerability_patterns.items():
                        if vulnerability_types is not None and vuln_type not in vulnerability_types:
                            continue
                        for pattern in vuln_info["patterns"]:
                            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)

                            for match in matches:
                                if vuln_type == "excessive_agency" and not self._is_unsafe_agency_signal(
                                    content, match.start(), match.end()
                                ):
                                    continue
                                line_num = content[:match.start()].count('\n') + 1

                                candidate = CandidateCase(
                                    id=f"{vuln_type}-{len(self.audit_state.candidates)}",
                                    vulnerability_type=vuln_type,
                                    severity=vuln_info["severity"],
                                    file_path=os.path.relpath(file_path, project_path),
                                    line_start=line_num,
                                    line_end=line_num + match.group().count('\n'),
                                    description=vuln_info["description"],
                                    evidence=[
                                        {
                                            "type": "code_snippet",
                                            "content": match.group(),
                                            "line": line_num,
                                        }
                                    ],
                                    confidence=0.6,
                                )

                                self.audit_state.candidates.append(candidate)

                except Exception as e:
                    logger.warning(f"Failed to scan {file_path}: {e}")
                    continue

    @staticmethod
    def _is_ignored_agent_path(relative_path: str) -> bool:
        parts = {part.lower() for part in Path(relative_path).parts}
        name = Path(relative_path).name.lower()
        return bool(parts & {"tests", "test", "fixtures", "docs", "static"}) or (
            name.startswith("test_") or name.endswith("_test.py")
        )

    @staticmethod
    def _is_path_traversal_signal(content: str, start: int, end: int) -> bool:
        """Require an untrusted value to reach a file sink through a path value.

        A literal ``../`` is common in JavaScript and TypeScript module imports.
        It is not evidence that an attacker can control a filesystem path.  This
        bounded local check deliberately asks for both a request-derived value
        and a file read/send sink before keeping a static candidate.
        """
        window_start = max(0, start - 2_000)
        window_end = min(len(content), end + 2_000)
        window = content[window_start:window_end]
        source = (
            r"(?:request\.(?:args|form|json|files|body|query_params)|"
            r"req\.(?:params|query|body|files)|"
            r"ctx\.(?:params|query|body)|"
            r"(?:user_)?input\s*\()"
        )
        sink = (
            r"(?:open|send_file|send_from_directory|read_text|read_bytes|"
            r"readFile(?:Sync)?|createReadStream|sendFile)\s*\([^\n)]*"
        )
        path_builder = r"(?:os\.path\.join|path\.(?:join|resolve)|Path)\s*\([^\n)]*"

        # Covers direct cases such as ``sendFile(req.query.path)``.
        if re.search(rf"{sink}{source}", window, re.IGNORECASE):
            return True

        source_variables = set(re.findall(
            rf"\b([A-Za-z_$][\w$]*)\s*=\s*[^\n]*(?:{source})",
            window,
            re.IGNORECASE,
        ))
        for variable in source_variables:
            reference = rf"\b{re.escape(variable)}\b"
            if re.search(rf"{sink}{reference}", window, re.IGNORECASE):
                return True

            path_variables = set(re.findall(
                rf"\b([A-Za-z_$][\w$]*)\s*=\s*{path_builder}{reference}",
                window,
                re.IGNORECASE,
            ))
            for path_variable in path_variables:
                path_reference = rf"\b{re.escape(path_variable)}\b"
                if re.search(rf"{sink}{path_reference}", window, re.IGNORECASE):
                    return True
        return False

    @staticmethod
    def _python_dangerous_call_offsets(content: str) -> Dict[str, set[int]]:
        """Return source offsets for executable dynamic-code or process calls."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return {}

        line_offsets = [0]
        for line in content.splitlines(keepends=True):
            line_offsets.append(line_offsets[-1] + len(line))
        offsets: Dict[str, set[int]] = {
            "command_injection": set(),
            "code_injection": set(),
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function_name = AuditAgent._python_call_name(node.func)
            offset = line_offsets[node.func.lineno - 1] + node.func.col_offset
            if function_name in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                offsets["code_injection"].add(offset)
            elif function_name == "os.system":
                offsets["command_injection"].add(offset)
            elif (
                function_name in {"subprocess.call", "subprocess.Popen"}
                and any(
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                    for keyword in node.keywords
                )
            ):
                offsets["command_injection"].add(offset)
        return offsets

    @staticmethod
    def _python_call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = AuditAgent._python_call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    @staticmethod
    def _is_unsafe_agency_signal(content: str, start: int, end: int) -> bool:
        """Require a privileged operation and an absent/disabled approval gate."""
        window = content[max(0, start - 700): min(len(content), end + 1_200)]
        lowered = window.lower()
        privileged = re.search(
            r"(?:permissions?|roles?|access)\s*[:=]\s*(?:['\"]?(?:admin|\*)|\[[^\]]*(?:write|delete|execute))"
            r"|(?:tool|action|execute_task|operation|command|task)[^\n]*(?:write|delete|remove|execute|send|modify|deploy)",
            lowered,
        )
        if not privileged:
            return False
        explicit_safe = re.search(
            r"(?:requires?[_ ]?(?:approval|confirmation)|human[_ ]?(?:approval|review)|approval[_ ]?required)"
            r"\s*[:=]\s*(?:true|yes|enforced|required)"
            r"|(?:allowlist|policy[_ ]?check|permission[_ ]?guard)",
            lowered,
        )
        explicit_unsafe = re.search(
            r"(?:requires?[_ ]?(?:approval|confirmation)|human[_ ]?(?:approval|review)|approval[_ ]?required)"
            r"\s*[:=]\s*(?:false|no|none)"
            r"|(?:no[_ ]?human|without[_ ]?approval|skip[_ ]?(?:check|approval)|bypass)",
            lowered,
        )
        return explicit_unsafe is not None or explicit_safe is None

    async def _scan_workflow_vulnerabilities(self, project_path: str) -> None:
        """Collect deterministic workflow, network-target, and deserialization signals."""
        logger.info("Scanning workflow vulnerabilities")
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [
                item for item in dirs
                if not item.startswith(".") or item == ".github"
            ]
            dirs[:] = [item for item in dirs if item not in {"node_modules", "__pycache__", "venv"}]
            for file in files:
                if not file.endswith((".py", ".js", ".ts", ".java", ".yaml", ".yml")):
                    continue
                file_path = os.path.join(root, file)
                try:
                    content = Path(file_path).read_text(encoding="utf-8", errors="ignore")
                except OSError as exc:
                    logger.warning("Failed to scan %s: %s", file_path, exc)
                    continue
                for vuln_type, vuln_info in self.workflow_vulnerability_patterns.items():
                    for pattern in vuln_info["patterns"]:
                        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                            line_num = content[:match.start()].count("\n") + 1
                            self.audit_state.candidates.append(CandidateCase(
                                id=f"{vuln_type}-{len(self.audit_state.candidates)}",
                                vulnerability_type=vuln_type,
                                severity=vuln_info["severity"],
                                file_path=os.path.relpath(file_path, project_path),
                                line_start=line_num,
                                line_end=line_num + match.group().count("\n"),
                                description=vuln_info["description"],
                                evidence=[{
                                    "type": "workflow_signal",
                                    "content": match.group()[:300],
                                    "line": line_num,
                                }],
                                confidence=0.65,
                            ))

    def _scan_protocol_signals(self, project_path: str, lane: str) -> None:
        """Add structured MCP/workflow signals without duplicating nearby candidates."""
        for signal in iter_protocol_signals(project_path, lane=lane):
            evidence = signal.to_evidence()
            existing = next((
                candidate for candidate in self.audit_state.candidates
                if candidate.vulnerability_type == signal.vulnerability_type
                and candidate.file_path.replace("\\", "/") == signal.file_path
                and candidate.line_start <= signal.line_end + 3
                and signal.line_start <= candidate.line_end + 3
            ), None)
            if existing is not None:
                existing.evidence.append(evidence)
                existing.confidence = max(existing.confidence, signal.confidence)
                continue
            self.audit_state.candidates.append(CandidateCase(
                id=f"{signal.vulnerability_type}-{len(self.audit_state.candidates)}",
                vulnerability_type=signal.vulnerability_type,
                severity=Severity.HIGH,
                file_path=signal.file_path,
                line_start=signal.line_start,
                line_end=signal.line_end,
                description=signal.description,
                evidence=[evidence],
                confidence=signal.confidence,
            ))

    async def _llm_deep_analysis(self, project_path: str, payload: Dict[str, Any]) -> None:
        """使用 LLM 进行深度分析"""
        logger.info("Performing LLM deep analysis")

        # 选择置信度较高的候选进行深度分析
        deep_analysis_limit = max(
            1, min(5, int(payload.get("llm_deep_analysis_limit", 2) or 2))
        )
        high_confidence_candidates = [
            c for c in self.audit_state.candidates
            if c.confidence >= 0.6
        ][:deep_analysis_limit]

        if not high_confidence_candidates:
            return

        try:
            from core.llm_service import LLMMessage

            for candidate in high_confidence_candidates:
                # 读取相关代码片段
                file_path = os.path.join(project_path, candidate.file_path)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        start = max(0, candidate.line_start - 5)
                        end = min(len(lines), candidate.line_end + 5)
                        code_snippet = redact_sensitive_text(''.join(lines[start:end]))
                except Exception:
                    code_snippet = "无法读取代码"

                prompt = f"""分析以下代码片段，判断是否存在安全漏洞：

文件: {candidate.file_path}
行号: {candidate.line_start}-{candidate.line_end}
漏洞类型: {candidate.vulnerability_type}
初步判断: {candidate.description}

代码片段:
```
{code_snippet}
```

请判断：
1. 这是否是一个真实的安全漏洞？
2. 漏洞的严重性是什么？
3. 如何修复？

用 JSON 格式回答：
{{
  "is_real_vulnerability": true/false,
  "severity": "critical/high/medium/low",
  "confidence": 0.0-1.0,
  "explanation": "...",
  "fix_suggestion": "..."
}}"""

                response = await self.llm_service.chat([
                    LLMMessage(role="user", content=prompt),
                ])

                try:
                    analysis = json.loads(response.content)
                    if analysis.get("is_real_vulnerability"):
                        candidate.confidence = analysis.get("confidence", candidate.confidence)
                        candidate.evidence.append({
                            "type": "llm_analysis",
                            "explanation": analysis.get("explanation", ""),
                            "fix_suggestion": analysis.get("fix_suggestion", ""),
                        })
                except Exception as e:
                    logger.warning("LLM analysis response parsing failed: %s", type(e).__name__)

        except Exception as e:
            logger.warning("LLM deep analysis degraded: %s", self._llm_failure_category(e))

    async def _generate_findings(self) -> List[Dict[str, Any]]:
        """Generate reportable findings while preserving review state and gaps."""
        findings = []

        for candidate in self.audit_state.candidates:
            if candidate.status == CandidateStatus.REJECTED.value or candidate.confidence < 0.5:
                continue

            self.finding_counter += 1
            evidence_gaps = [
                str(item.get("description", ""))
                for item in candidate.evidence
                if item.get("type") in {"react_review_gap", "react_evidence_gap"}
                and item.get("description")
            ]
            finding_status = {
                CandidateStatus.CANDIDATE_CONFIRMED.value: "candidate_confirmed",
                CandidateStatus.NEEDS_EVIDENCE.value: "needs_evidence",
            }.get(candidate.status, "candidate")
            evidence_bundle = EvidenceBundle(gaps=list(dict.fromkeys(evidence_gaps)))
            for evidence in candidate.evidence:
                evidence_bundle.add(evidence)
            evidence_bundle.artifact_refs = self._collect_artifact_refs(candidate.evidence)
            finding = {
                "id": f"FINDING-{self.finding_counter:03d}",
                "vulnerability_type": candidate.vulnerability_type,
                "severity": candidate.severity.value,
                "confidence": candidate.confidence,
                "title": candidate.description,
                "file_path": candidate.file_path,
                "line_start": candidate.line_start,
                "line_end": candidate.line_end,
                "description": candidate.description,
                "evidence": candidate.evidence,
                "evidence_bundle": evidence_bundle.to_dict(),
                "evidence_gaps": list(dict.fromkeys(evidence_gaps)),
                "status": finding_status,
                "review_verdict": candidate.status,
            }

            findings.append(finding)
            self.audit_state.confirmed_findings.append(finding)

        return findings

    @classmethod
    def _collect_artifact_refs(cls, value: Any) -> List[str]:
        refs: List[str] = []

        def visit(item: Any) -> None:
            if isinstance(item, dict):
                artifact_ref = item.get("artifact_ref")
                if artifact_ref:
                    refs.append(str(artifact_ref))
                artifact_id = item.get("artifact_id")
                if artifact_id:
                    refs.append(str(artifact_id))
                for ref in item.get("artifact_refs", []) or []:
                    if ref:
                        refs.append(str(ref))
                for key, nested in item.items():
                    if key not in {"artifact_ref", "artifact_id", "artifact_refs"}:
                        visit(nested)
            elif isinstance(item, (list, tuple)):
                for nested in item:
                    visit(nested)

        visit(value)
        return list(dict.fromkeys(refs))

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """按严重性统计"""
        counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            counts[severity] = counts.get(severity, 0) + 1
        return counts
