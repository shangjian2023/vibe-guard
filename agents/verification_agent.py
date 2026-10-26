"""Evidence-bound verification Agent.

The model may select checks and explain observations, but only harness-owned
predicates can produce ``verified`` or ``rejected``.  Missing infrastructure or
an absent runtime harness is always ``needs_evidence``.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agents.base import AgentConfig, AgentPattern, AgentResult, AgentType, BaseAgent
from core.audit.protocol_analysis import find_matching_protocol_signal
from core.sanitization import redact_sensitive_text, sanitize_for_persistence
from core.runtime.docker_executor import DockerExecutor
from core.runtime.browser_executor import PlaywrightExecutor
from core.tool_fabric import ArtifactStore
from core.tool_fabric.dependency_inspection import inspect_dependencies
from core.verification.react_review import ReActVerificationReviewer
from core.llm_errors import classify_llm_failure
from core.verification.poc_protocol import bind_poc_verdict, validate_poc_plan
from core.verification.types import VULNERABILITY_TYPE_ALIASES
from core.verification.service_runtime import ContainerServiceRunner, ServiceSpec
from core.verification.environment_runtime import (
    ContainerEnvironmentRunner,
    ReproductionEnvironmentPlan,
)


logger = logging.getLogger(__name__)


@dataclass
class VerificationEvidence:
    evidence_type: str
    description: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    available: bool = True
    predicate: str = ""
    outcome: str = "inconclusive"  # supported, contradicted, inconclusive, unavailable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_type": self.evidence_type,
            "description": self.description,
            "success": self.success,
            "data": self.data,
            "confidence": self.confidence,
            "available": self.available,
            "predicate": self.predicate,
            "outcome": self.outcome,
        }


class VerificationAgent(BaseAgent):
    TYPE_ALIASES = VULNERABILITY_TYPE_ALIASES
    SUPPORTED_TYPES = {
        "sql_injection", "command_injection", "xss", "path_traversal",
        "hardcoded_password", "api_key", "secret_leak", "credential_exposure",
        "dependency_vulnerability", "prompt_injection", "mcp_insecurity",
        "excessive_agency", "ssrf", "unsafe_deserialization", "workflow_insecurity",
        "authorization_bypass", "broken_access_control", "code_injection",
        "mcp_tool_poisoning", "hardcoded_secrets", "hardcoded_credentials",
        "missing_authentication", "context_manipulation", "denial_of_service",
        "mass_assignment", "plaintext_password_comparison",
    }
    STATIC_CONFIRMABLE = {
        "hardcoded_password", "api_key", "secret_leak", "credential_exposure",
        "dependency_vulnerability", "sql_injection", "command_injection", "xss",
        "path_traversal", "code_injection", "ssrf", "unsafe_deserialization",
        "prompt_injection", "mcp_insecurity", "workflow_insecurity",
        "mass_assignment", "plaintext_password_comparison",
    }

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        llm_service=None,
        tools=None,
        event_emitter=None,
    ):
        config = config or AgentConfig(
            name="Verification",
            agent_type=AgentType.VERIFICATION,
            pattern=AgentPattern.REACT,
            max_iterations=20,
        )
        super().__init__(config=config, llm_service=llm_service, tools=tools, event_emitter=event_emitter)

    async def run(self, payload: Dict[str, Any]) -> AgentResult:
        project_path = payload.get("project_path")
        findings = list(payload.get("findings_to_verify", []) or [])

        # Build the trusted-authorization dict that SafetyEnvelope.from_trusted_input()
        # expects.  The payload key "verification_authorization" carries the caller's
        # intent; we inject "_trusted_authorization_verified=True" here (in the harness
        # boundary) so that SafetyEnvelope can grant PoC-execution authority.
        # Model-supplied values inside "verification_authorization" are never promoted
        # to trusted status — only the harness calling this agent is trusted.
        raw_authorization = dict(payload.get("verification_authorization") or {})
        if raw_authorization.get("allow_poc_execution") or raw_authorization.get("allow_service_start"):
            # Caller explicitly opted in: stamp the trusted flag so SafetyEnvelope
            # recognises this as a harness-verified grant.
            raw_authorization.setdefault("_trusted_authorization_verified", True)
        service_authorization = raw_authorization

        if not project_path:
            return AgentResult.failure_result("project_path is required")
        if not Path(project_path).is_dir():
            return AgentResult.failure_result("project_path must be an existing directory")
        if not findings:
            return AgentResult.success_result(data={
                "verified_findings": [],
                "rejected_findings": [],
                "needs_evidence_findings": [],
                "verification_summary": {"total": 0, "verified": 0, "rejected": 0, "needs_evidence": 0},
            })

        verified: List[Dict[str, Any]] = []
        rejected: List[Dict[str, Any]] = []
        needs_evidence: List[Dict[str, Any]] = []
        for original in findings:
            finding = dict(original)
            raw_poc_plan = finding.get("poc_plan") or finding.get("verification_plan")
            poc_validation = validate_poc_plan(
                raw_poc_plan,
                finding=finding,
                trusted_authorization=service_authorization,
                project_root=str(project_path),
            )
            finding["poc"] = poc_validation.to_dict()
            if self._should_use_react(payload):
                react = await ReActVerificationReviewer(
                    self.llm_service,
                    verifier=self,
                    project_path=str(project_path),
                    max_turns=max(2, min(
                        12,
                        self.config.max_iterations,
                        int(payload.get("react_verification_max_turns", 12) or 12),
                    )),
                    service_authorization=service_authorization,
                ).review(finding)
                if react.status in {"completed", "degraded"} and react.output:
                    verification_bundle = dict(react.output.get("evidence_bundle", {}) or {})
                    finding.update({
                        "verification_status": react.output.get("verification_status", "needs_evidence"),
                        "verification_predicate": react.output.get("verification_predicate", ""),
                        "verification_evidence": verification_bundle,
                        "evidence_bundle": self._merge_evidence_bundle(finding, verification_bundle),
                        "verification_review": {
                            "status": react.status,
                            "metadata": react.output.get("review_metadata", {}),
                            "tool_records": react.tool_records,
                            "error_category": (
                                classify_llm_failure(react.error)
                                if react.error or react.status != "completed" else None
                            ),
                        },
                    })
                    self._append_by_status(finding, verified, rejected, needs_evidence)
                    continue
                finding["verification_review"] = {
                    "status": "failed",
                    "error_category": classify_llm_failure(react.error),
                    "tool_records": react.tool_records,
                }

            method = self._select_verification_method(finding)
            evidence = await self._verify_finding(
                str(project_path), finding, method,
                service_authorization=service_authorization,
            )
            self._bind_fallback_result(finding, evidence, method)
            self._append_by_status(finding, verified, rejected, needs_evidence)

        handoff = self.create_handoff(
            to_agent="remediation",
            summary=(
                f"Verification completed: {len(verified)} verified, {len(rejected)} rejected, "
                f"{len(needs_evidence)} need more evidence"
            ),
            work_completed=["predicate planning", "controlled evidence collection", "verdict binding"],
            key_findings=[{
                "type": "verification_summary",
                "total": len(findings),
                "verified": len(verified),
                "rejected": len(rejected),
                "needs_evidence": len(needs_evidence),
            }],
            context_refs={
                "verified_findings": json.dumps(verified),
                "rejected_findings": json.dumps(rejected),
                "needs_evidence_findings": json.dumps(needs_evidence),
            },
        )
        return AgentResult.success_result(data={
            "verified_findings": verified,
            "rejected_findings": rejected,
            "needs_evidence_findings": needs_evidence,
            "verification_summary": {
                "total": len(findings),
                "verified": len(verified),
                "rejected": len(rejected),
                "needs_evidence": len(needs_evidence),
            },
        }, handoff=handoff)

    @staticmethod
    def _append_by_status(finding, verified, rejected, needs_evidence) -> None:
        status = finding.get("verification_status", "needs_evidence")
        if status == "verified":
            verified.append(finding)
        elif status == "rejected":
            rejected.append(finding)
        elif status in {"needs_evidence", "static_only"}:
            needs_evidence.append(finding)
        else:
            finding["verification_status"] = "needs_evidence"
            needs_evidence.append(finding)

    def _should_use_react(self, payload: Dict[str, Any]) -> bool:
        if payload.get("enable_react_verification") is False:
            return False
        return self.llm_service is not None and str(getattr(self.llm_service, "provider", "mock")).lower() != "mock"

    @staticmethod
    def _select_verification_method(finding: Dict[str, Any]) -> str:
        severity = str(finding.get("severity", "medium")).lower()
        if severity in {"critical", "high"}:
            return "full"
        if severity == "medium":
            return "standard"
        return "basic"

    async def _verify_finding(
        self,
        project_path: str,
        finding: Dict[str, Any],
        method: str,
        *,
        service_authorization: Optional[Dict[str, Any]] = None,
    ) -> VerificationEvidence:
        static = await self._static_verification(project_path, finding)
        if not static.available or static.outcome == "contradicted" or method == "basic":
            return static
        if not static.success:
            return static
        # An explicitly supplied PoC plan represents a requested verification
        # depth. Even when the source predicate is statically confirmable, the
        # plan must pass the authorization/validation contract first.
        if static.data.get("can_confirm_statically") is True and not (
            finding.get("poc_plan") or finding.get("verification_plan")
        ):
            return static

        dynamic = await self._dynamic_verification(
            project_path,
            finding,
            service_authorization=service_authorization,
        )
        if not dynamic.success and str(finding.get("vulnerability_type", "")).lower() == "xss":
            browser = await self._browser_verification(
                project_path,
                finding,
                service_authorization=service_authorization,
            )
            if browser.success:
                dynamic = browser
        if not dynamic.success:
            if not (finding.get("poc_plan") or finding.get("verification_plan")):
                return static
            return self._combined(
                "combined",
                [static, dynamic],
                "Static risk evidence exists but the runtime PoC predicate was not satisfied",
                success=False,
            )
        if method == "standard" or dynamic.evidence_type == "browser":
            return self._combined("combined", [static, dynamic], "Static and dynamic predicates were satisfied")

        fuzzing = await self._fuzzing_verification(project_path, finding)
        if not fuzzing.success:
            return self._combined(
                "combined",
                [static, dynamic, fuzzing],
                "Static and dynamic predicates passed; fuzzing evidence is incomplete",
                success=False,
            )
        return self._combined("full", [static, dynamic, fuzzing], "All required verification predicates were satisfied")

    @staticmethod
    def _combined(
        evidence_type: str,
        items: List[VerificationEvidence],
        description: str,
        *,
        success: bool = True,
    ) -> VerificationEvidence:
        return VerificationEvidence(
            evidence_type,
            description,
            success,
            {"items": [item.to_dict() for item in items]},
            min(item.confidence for item in items),
            available=all(item.available for item in items),
            predicate=" AND ".join(item.predicate for item in items if item.predicate),
            outcome="supported" if success else "inconclusive",
        )

    async def _static_verification(self, project_path: str, finding: Dict[str, Any]) -> VerificationEvidence:
        file_path = str(finding.get("file_path", ""))
        line_start = int(finding.get("line_start", 0) or 0)
        line_end = int(finding.get("line_end", line_start) or line_start)
        reported_type = str(finding.get("vulnerability_type", "unknown")).lower()
        vuln_type = self.TYPE_ALIASES.get(reported_type, reported_type)
        predicate = f"Expected {reported_type} risk indicator remains at the bound source location"
        if reported_type not in self.SUPPORTED_TYPES and vuln_type not in self.SUPPORTED_TYPES:
            return VerificationEvidence(
                "static",
                f"No Harness-owned verification predicate is registered for {reported_type}",
                False,
                {"vulnerability_type": reported_type, "supported": False},
                0.0,
                available=False,
                predicate="",
                outcome="unsupported",
            )
        try:
            root = Path(project_path).resolve()
            target = (root / file_path).resolve()
            target.relative_to(root)
            lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line_start < 1 or line_start > len(lines):
                raise ValueError("line number is outside the current source file")
            start = max(1, line_start - 3)
            end = min(len(lines), max(line_start, line_end) + 3)
            raw_excerpt = "\n".join(lines[start - 1:end])
            excerpt = redact_sensitive_text(raw_excerpt)
            common = {
                "file_path": file_path,
                "line_start": start,
                "line_end": end,
                "excerpt": excerpt,
                "reported_vulnerability_type": reported_type,
                "canonical_vulnerability_type": vuln_type,
            }
            if vuln_type == "dependency_vulnerability":
                dependency_evidence = self._verify_dependency_version(root, finding)
                return VerificationEvidence(
                    "static",
                    dependency_evidence["description"],
                    dependency_evidence["success"],
                    {**common, **dependency_evidence["data"], "can_confirm_statically": dependency_evidence["success"]},
                    dependency_evidence["confidence"],
                    available=dependency_evidence["available"],
                    predicate=dependency_evidence["predicate"],
                    outcome=dependency_evidence["outcome"],
                )
            if vuln_type in {"mcp_insecurity", "workflow_insecurity"}:
                protocol_signal = find_matching_protocol_signal(project_path, finding)
                if protocol_signal is not None:
                    return VerificationEvidence(
                        "static",
                        protocol_signal.description,
                        True,
                        {
                            **common,
                            "indicator": protocol_signal.predicate,
                            "can_confirm_statically": protocol_signal.statically_confirmable,
                            "protocol_analyzer": protocol_signal.analyzer,
                            "protocol_details": protocol_signal.details,
                        },
                        protocol_signal.confidence,
                        predicate=protocol_signal.predicate,
                        outcome="supported",
                    )
                normalized = file_path.replace("\\", "/").lower()
                if vuln_type == "workflow_insecurity" and "/.github/workflows/" in f"/{normalized}":
                    return VerificationEvidence(
                        "static",
                        "The parsed workflow no longer contains the direct untrusted run-step interpolation",
                        False,
                        common,
                        0.85,
                        predicate="No parsed GitHub Actions run step directly interpolates attacker-controlled event data",
                        outcome="contradicted",
                    )
            if self._appears_fixed(raw_excerpt, vuln_type):
                return VerificationEvidence(
                    "static", "A recognized mitigation contradicts the original candidate", False,
                    common, 0.75, predicate=predicate, outcome="contradicted",
                )
            indicator = redact_sensitive_text(self._static_risk_indicator(raw_excerpt, vuln_type))
            if not indicator:
                return VerificationEvidence(
                    "static", "The source location exists but the expected risk indicator is absent", False,
                    common, 0.45, predicate=predicate, outcome="inconclusive",
                )
            can_confirm = vuln_type in self.STATIC_CONFIRMABLE
            return VerificationEvidence(
                "static", "The expected risk indicator is present", True,
                {**common, "indicator": indicator, "can_confirm_statically": can_confirm},
                0.9 if can_confirm else 0.75,
                predicate=predicate,
                outcome="supported",
            )
        except (OSError, ValueError) as exc:
            return VerificationEvidence(
                "static", f"Static verification unavailable: {exc}", False,
                {"file_path": file_path, "error": str(exc)}, 0.2,
                available=False, predicate=predicate, outcome="unavailable",
            )

    @staticmethod
    def _verify_dependency_version(root: Path, finding: Dict[str, Any]) -> Dict[str, Any]:
        evidence_items = list(finding.get("evidence", []) or [])
        evidence_items.extend(list(dict(finding.get("evidence_bundle", {}) or {}).get("items", []) or []))
        scanner = next((
            item for item in evidence_items
            if isinstance(item, dict)
            and item.get("type") == "scanner_signal"
            and isinstance(item.get("metadata"), dict)
            and item["metadata"].get("scanner") == "osv"
        ), None)
        package = dict((scanner or {}).get("metadata", {}).get("package", {}) or {})
        advisory = str((scanner or {}).get("rule_id") or finding.get("title") or "OSV advisory")
        if not package.get("name") or not package.get("version"):
            return {
                "description": "OSV package/version evidence is missing from the finding",
                "success": False,
                "available": False,
                "confidence": 0.2,
                "predicate": "The exact resolved package version remains matched to the OSV advisory",
                "outcome": "unavailable",
                "data": {"advisory": advisory},
            }
        inventory = inspect_dependencies(root, ecosystem=str(package.get("ecosystem", "")))
        current = [
            item for item in [
                *list(inventory.get("locked_dependencies", []) or []),
                *list(inventory.get("dependencies", []) or []),
            ]
            if str(item.get("name", "")).lower() == str(package["name"]).lower()
        ]
        expected = str(package["version"]).lstrip("=")
        matching = [
            item for item in current
            if str(item.get("resolved_version") or item.get("version_spec") or "").lstrip("=") == expected
        ]
        predicate = f"{package['name']} resolves to advisory-matched version {expected} for {advisory}"
        if matching:
            return {
                "description": "The exact OSV-matched dependency version remains in the current dependency graph",
                "success": True,
                "available": True,
                "confidence": 0.98,
                "predicate": predicate,
                "outcome": "supported",
                "data": {"advisory": advisory, "package": package, "current_records": matching},
            }
        return {
            "description": "The advisory-matched dependency version is absent from the current dependency graph",
            "success": False,
            "available": True,
            "confidence": 0.9,
            "predicate": predicate,
            "outcome": "contradicted",
            "data": {"advisory": advisory, "package": package, "current_records": current},
        }

    @staticmethod
    def _appears_fixed(excerpt: str, vuln_type: str) -> bool:
        lowered = excerpt.lower()
        mitigations = {
            "sql_injection": ("parameterized", "bindparam", "?", ":param"),
            "command_injection": ("shell=false", "shlex.quote", "allowlist"),
            "xss": ("escape(", "sanitize(", "textcontent"),
            "path_traversal": ("resolve()", "relative_to(", "secure_filename"),
            "prompt_injection": ("untrusted", "requires_approval", "tool_policy"),
            "mcp_insecurity": ("requires_confirmation", "allowed_tools", "permissionpolicy"),
            "excessive_agency": ("requires_approval", "human_approval", "least_privilege"),
            "ssrf": ("allowed_hosts", "allowlist", "ipaddress", "urlparse"),
            "unsafe_deserialization": ("safe_load", "safeloader", "json.loads"),
            "workflow_insecurity": ("github_env", "allowed_event", "shell=false"),
        }
        return any(marker in lowered for marker in mitigations.get(vuln_type, ()))

    @staticmethod
    def _static_risk_indicator(excerpt: str, vuln_type: str) -> str:
        patterns = {
            "sql_injection": r"(?:execute|query|raw)\s*\([^\n]*(?:f['\"]|\+|%\s*\(|\.format\()",
            "command_injection": r"(?:os\.system\s*\(|shell\s*=\s*True|subprocess\.(?:run|Popen|call)\s*\()",
            "xss": r"(?:innerHTML|dangerouslySetInnerHTML|Markup\s*\(|\|\s*safe\b)",
            "path_traversal": r"(?:open|send_file|read_text|read_bytes)\s*\([^\n]*(?:request|input|param|path)",
            "hardcoded_password": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}",
            "api_key": r"(?i)(?:api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{8,}",
            "secret_leak": r"(?i)(?:secret|token|private[_-]?key|client[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}",
            "credential_exposure": r"(?i)(?:password|passwd|credential|username)\s*[:=]\s*['\"][^'\"]{4,}",
            "code_injection": (
                r"(?i)(?:(?<![\w$.])(?:eval|(?-i:Function))\s*\([^\n]*"
                r"(?:request|user|input|param|payload|code)|"
                r"\bvm\.runIn(?:Context|NewContext|ThisContext)\s*\([^\n]*"
                r"(?:request|user|input|param|payload|code))"
            ),
            "prompt_injection": r"(?i)(?:prompt|messages)[^\n]*(?:request|user_input|external|content)",
            "mcp_insecurity": r"(?i)(?:mcp|tool)[^\n]*(?:permissions?\s*[:=]\s*['\"]?\*|execute_command|shell)",
            "excessive_agency": r"(?i)(?:permissions?\s*[:=]\s*['\"]?(?:admin|\*)|auto(?:nomous)?[^\n]*(?:execute|approve))",
            "ssrf": r"(?i)(?:requests\.(?:get|post)|httpx\.(?:get|post)|urlopen|fetch)\s*\([^\n]*(?:request|user|input|url)",
            "unsafe_deserialization": r"(?i)(?:pickle\.loads?\s*\(|yaml\.load\s*\([^\n]*(?!SafeLoader)|ObjectInputStream\s*\()",
            "workflow_insecurity": r"(?i)(?:run:\s*[^\n]*\$\{\{\s*github\.event\.|(?:exec|eval|os\.system|subprocess\.(?:run|Popen))\s*\([^\n]*(?:workflow|event|payload|input))",
        }
        pattern = patterns.get(vuln_type)
        if not pattern:
            return "source_location_present"
        match = re.search(pattern, excerpt)
        return match.group(0)[:200] if match else ""

    async def _dynamic_verification(
        self,
        project_path: str,
        finding: Dict[str, Any],
        *,
        service_authorization: Optional[Dict[str, Any]] = None,
    ) -> VerificationEvidence:
        raw_plan = finding.get("poc_plan") or finding.get("verification_plan")
        validation = validate_poc_plan(
            raw_plan,
            finding=finding,
            trusted_authorization=service_authorization,
            project_root=str(project_path),
        )
        predicate = validation.plan.predicate if validation.plan else "Explicit PoC controls satisfy a bounded predicate"
        if not validation.executable or validation.plan is None:
            return VerificationEvidence(
                "dynamic", "PoC plan is absent, invalid, or not authorized", False,
                {"poc_validation": validation.to_dict()}, 0.2,
                available=False, predicate=predicate, outcome="unavailable",
            )
        plan = validation.plan
        positive = plan.positive_control.harness
        negative = plan.negative_control.harness
        environment_evidence: Dict[str, Any] = {}
        if plan.environment.get("services"):
            try:
                environment_plan = ReproductionEnvironmentPlan.from_dict(plan.environment)
            except (TypeError, ValueError) as exc:
                return VerificationEvidence(
                    "dynamic", f"Invalid reproduction environment: {exc}", False,
                    {"poc_validation": validation.to_dict(), "error": str(exc)}, 0.2,
                    available=False, predicate=predicate, outcome="unavailable",
                )
            environment_runner = ContainerEnvironmentRunner()
            environment_handle = await environment_runner.start(
                environment_plan,
                project_root=project_path,
            )
            if not environment_handle.ready:
                return VerificationEvidence(
                    "dynamic", environment_handle.error or "Reproduction environment did not become ready", False,
                    {
                        "poc_validation": validation.to_dict(),
                        "environment_status": environment_handle.status,
                        "service_logs": environment_handle.service_logs,
                    }, 0.2,
                    available=False, predicate=predicate, outcome="unavailable",
                )
            try:
                positive_run = await environment_runner.run_control(
                    environment_handle,
                    ["python", "-c", DockerExecutor._build_verification_script(
                        plan.vulnerability_type, plan.target_code, positive,
                        oracle_id=plan.oracle_id, target_path=plan.target_binding.path,
                    )],
                    project_root=project_path,
                    image=plan.image,
                    timeout_seconds=validation.envelope.max_duration_seconds,
                )
                negative_run = await environment_runner.run_control(
                    environment_handle,
                    ["python", "-c", DockerExecutor._build_verification_script(
                        plan.vulnerability_type, plan.target_code, negative,
                        oracle_id=plan.oracle_id, target_path=plan.target_binding.path,
                    )],
                    project_root=project_path,
                    image=plan.image,
                    timeout_seconds=validation.envelope.max_duration_seconds,
                )
                positive_result = self._parse_environment_control(positive_run)
                negative_result = self._parse_environment_control(negative_run)
                environment_evidence = {
                    "target_url": environment_handle.base_url,
                    "topology": sorted(environment_handle.containers),
                    "network_policy": "internal bridge; no host ports; no outbound route",
                    "service_logs": await environment_runner.logs(environment_handle),
                }
            finally:
                await environment_runner.stop(environment_handle)
        else:
            executor = DockerExecutor(image=plan.image)
            positive_result = await executor.verify_vulnerability(
                plan.vulnerability_type, plan.target_code, positive,
                oracle_id=plan.oracle_id,
                target_path=plan.target_binding.path,
                project_path=project_path,
            )
            negative_result = await executor.verify_vulnerability(
                plan.vulnerability_type, plan.target_code, negative,
                oracle_id=plan.oracle_id,
                target_path=plan.target_binding.path,
                project_path=project_path,
            )
        unavailable = any(item.get("status") == "needs_evidence" for item in (positive_result, negative_result))
        positive_matched = positive_result.get("verified") is True
        negative_matched = negative_result.get("verified") is True
        poc_result = bind_poc_verdict(
            validation,
            positive_matched=positive_matched,
            negative_matched=negative_matched,
        )
        success = poc_result["verdict"] == "verified" and not unavailable
        return VerificationEvidence(
            "dynamic",
            "Runtime positive and negative controls satisfied" if success else "Runtime controls did not satisfy the predicate",
            success,
            {
                "poc_result": poc_result,
                "positive_control": positive_result,
                "negative_control": negative_result,
                "environment": environment_evidence,
            },
            0.9 if success else 0.4,
            available=not unavailable,
            predicate=predicate,
            outcome="supported" if success else ("unavailable" if unavailable else "inconclusive"),
        )

    @staticmethod
    def _parse_environment_control(run) -> Dict[str, Any]:
        if not run.success:
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "VIBE_SEC_VERIFIED is exactly true",
                "explanation": redact_sensitive_text(run.error or run.stderr or "Harness execution failed"),
                "evidence": redact_sensitive_text(run.stdout),
                "execution_status": run.status,
            }
        try:
            payload = json.loads(next(
                line for line in reversed(run.stdout.splitlines()) if line.strip()
            ))
        except (json.JSONDecodeError, StopIteration):
            return {
                "verified": False,
                "status": "needs_evidence",
                "verification_predicate": "VIBE_SEC_VERIFIED is exactly true",
                "explanation": "Harness did not emit the required JSON terminal result",
                "evidence": redact_sensitive_text(run.stdout),
            }
        payload = sanitize_for_persistence(payload)
        payload["verified"] = payload.get("verified") is True
        payload["status"] = "verified" if payload["verified"] else "needs_evidence"
        return payload

    async def _fuzzing_verification(self, project_path: str, finding: Dict[str, Any]) -> VerificationEvidence:
        del project_path
        plan = dict(finding.get("verification_plan") or {})
        harness = str(plan.get("fuzz_harness", ""))
        marker = str(plan.get("fuzz_success_marker", "VIBE_SEC_FUZZ_REACHED"))
        predicate = f"Fuzz harness exits zero and emits {marker!r}"
        if not harness:
            return VerificationEvidence(
                "fuzzing", "No explicit fuzz harness was supplied", False,
                {"required_field": "fuzz_harness"}, 0.2,
                available=False, predicate=predicate, outcome="unavailable",
            )
        executor = DockerExecutor(image=str(plan.get("image", "python:3.12-slim")))
        result = await executor.execute_python(harness, timeout=int(plan.get("fuzz_timeout", 30) or 30))
        success = result.success and marker in result.stdout
        return VerificationEvidence(
            "fuzzing", "Fuzz predicate satisfied" if success else "Fuzz predicate was not satisfied", success,
            {
                "exit_code": result.exit_code,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-4000:],
                "execution_status": result.status,
                "output_truncated": result.output_truncated,
            },
            0.85 if success else 0.35,
            available=result.status not in {"unavailable", "timed_out"},
            predicate=predicate,
            outcome="supported" if success else ("unavailable" if result.status in {"unavailable", "timed_out"} else "contradicted"),
        )

    async def _browser_verification(
        self,
        project_path: str,
        finding: Dict[str, Any],
        *,
        service_authorization: Optional[Dict[str, Any]] = None,
    ) -> VerificationEvidence:
        browser_plan = dict((finding.get("verification_plan") or {}).get("browser") or {})
        predicate = "Browser positive control executes the XSS marker and the negative control does not"
        service_plan = dict(browser_plan.get("service") or {})
        required = {"selector", "positive_payload", "negative_payload"}
        if not service_plan:
            required.add("url")
        if not required.issubset(browser_plan):
            return VerificationEvidence(
                "browser", "No complete browser verification plan was supplied", False,
                {"required_fields": sorted(required)}, 0.2,
                available=False, predicate=predicate, outcome="unavailable",
            )
        service_runner = None
        service_handle = None
        url = str(browser_plan.get("url", ""))
        if service_plan:
            if (
                service_plan.get("authorized") is not True
                or not service_authorization
                or service_authorization.get("allow_service_start") is not True
            ):
                return VerificationEvidence(
                    "browser", "Container service startup was not authorized by the trusted control plane", False,
                    {
                        "required": [
                            "browser.service.authorized=true",
                            "verification_authorization.allow_service_start=true",
                        ],
                    }, 0.2,
                    available=False, predicate=predicate, outcome="unavailable",
                )
            try:
                if service_plan.get("services"):
                    spec = ReproductionEnvironmentPlan.from_dict(service_plan)
                    service_runner = ContainerEnvironmentRunner()
                else:
                    spec = ServiceSpec(
                        image=str(service_plan.get("image", "")),
                        command=list(service_plan.get("command", []) or []),
                        container_port=int(service_plan.get("container_port", 0) or 0),
                        health_path=str(service_plan.get("health_path", "/")),
                        host_port=int(service_plan.get("host_port", 0) or 0),
                        startup_timeout_seconds=float(service_plan.get("startup_timeout_seconds", 30) or 30),
                        environment=dict(service_plan.get("environment", {}) or {}),
                    )
                    service_runner = ContainerServiceRunner()
            except (TypeError, ValueError) as exc:
                return VerificationEvidence(
                    "browser", f"Invalid service startup plan: {exc}", False,
                    {"error": str(exc)}, 0.2,
                    available=False, predicate=predicate, outcome="unavailable",
                )
            service_handle = await service_runner.start(spec, project_root=project_path)
            if not service_handle.ready:
                return VerificationEvidence(
                    "browser", service_handle.error or "Service failed to become ready", False,
                    {"service_status": service_handle.status, "service_logs": service_handle.logs}, 0.2,
                    available=False, predicate=predicate, outcome="unavailable",
                )
            url = service_handle.base_url + str(browser_plan.get("path", "/"))
        try:
            result = await PlaywrightExecutor().execute_xss_controls(
                url=url,
                selector=str(browser_plan["selector"]),
                positive_payload=str(browser_plan["positive_payload"]),
                negative_payload=str(browser_plan["negative_payload"]),
                marker=str(browser_plan.get("marker", "__VIBE_SEC_XSS__")),
                submit_selector=browser_plan.get("submit_selector"),
                timeout_ms=int(browser_plan.get("timeout_ms", 15_000) or 15_000),
            )
        finally:
            if service_runner and service_handle:
                service_logs = await service_runner.logs(service_handle)
                await service_runner.stop(service_handle)
        result_payload = sanitize_for_persistence(result.to_dict())
        if service_handle:
            result_payload["service"] = {
                "status": service_handle.status,
                "base_url": service_handle.base_url,
                "health_url": service_handle.health_url,
                "logs": service_logs,
                "network_policy": "ephemeral internal bridge; one loopback-only published target; no outbound route",
                "topology": sorted(getattr(service_handle, "containers", {}).keys()),
            }
        browser_evidence = list(result_payload.get("evidence", []) or [])
        if browser_evidence:
            store = ArtifactStore(
                str(Path(tempfile.gettempdir()) / "vibe-sec-artifacts"),
                session_id=f"browser-{finding.get('id', 'unknown')}",
            )
            refs = []
            for index, item in enumerate(browser_evidence, 1):
                artifact = store.put_text(
                    redact_sensitive_text(str(item.get("content", ""))),
                    producer="run_browser_verification",
                    artifact_type=f"browser_{item.get('type', 'evidence')}",
                    file_name=f"browser-{index}.txt",
                    metadata={"url": item.get("url"), "evidence_type": item.get("type")},
                )
                refs.append({
                    "type": item.get("type"),
                    "artifact_ref": artifact.artifact_id,
                    "path": artifact.path,
                    "sha256": artifact.sha256,
                    "size_bytes": artifact.size_bytes,
                })
            result_payload["evidence"] = refs
        success = result.success and result.predicate_satisfied
        return VerificationEvidence(
            "browser",
            "Browser positive and negative controls satisfied" if success else (result.error or "Browser controls did not satisfy the predicate"),
            success,
            result_payload,
            0.95 if success else 0.35,
            available=result.status == "completed",
            predicate=result.predicate or predicate,
            outcome="supported" if success else (
                "unavailable" if result.status in {"unavailable", "blocked"} else "inconclusive"
            ),
        )

    @classmethod
    def _bind_fallback_result(cls, finding: Dict[str, Any], evidence: VerificationEvidence, method: str) -> None:
        can_confirm_static = bool(evidence.data.get("can_confirm_statically", False))
        if evidence.success and evidence.evidence_type != "static":
            status = "verified"
            gaps: List[str] = []
        elif evidence.success and can_confirm_static:
            status = "static_only"
            gaps = [
                "Static source predicate passed; controlled runtime evidence is still required for exploit confirmation",
            ]
        elif evidence.outcome == "contradicted" and evidence.available:
            status = "rejected"
            gaps = []
        else:
            status = "needs_evidence"
            gaps = [
                evidence.description,
                f"Required verification depth for this finding was {method}",
            ]
        finding["verification_status"] = status
        finding["verification_predicate"] = evidence.predicate
        finding["verification_evidence"] = evidence.to_dict()
        verification_bundle = {
            "items": [evidence.to_dict()],
            "gaps": list(dict.fromkeys(gaps)),
            "level": {"static": 1, "combined": 3, "full": 4}.get(evidence.evidence_type, 1),
        }
        finding["evidence_bundle"] = cls._merge_evidence_bundle(finding, verification_bundle)

    @staticmethod
    def _merge_evidence_bundle(
        finding: Dict[str, Any],
        verification_bundle: Dict[str, Any],
    ) -> Dict[str, Any]:
        discovery_bundle = dict(finding.get("evidence_bundle", {}) or {})
        discovery_items = list(discovery_bundle.get("items", []) or [])
        verification_items = list(verification_bundle.get("items", []) or [])

        items: List[Dict[str, Any]] = []
        seen = set()
        for item in [*discovery_items, *verification_items]:
            if not isinstance(item, dict):
                continue
            normalized = sanitize_for_persistence(item)
            marker = json.dumps(normalized, ensure_ascii=False, sort_keys=True, default=str)
            if marker in seen:
                continue
            seen.add(marker)
            items.append(normalized)

        artifact_refs = set(str(item) for item in discovery_bundle.get("artifact_refs", []) or [] if item)
        artifact_refs.update(str(item) for item in finding.get("artifact_refs", []) or [] if item)
        artifact_refs.update(str(item) for item in verification_bundle.get("artifact_refs", []) or [] if item)
        tool_execution_ids = set(
            str(item) for item in discovery_bundle.get("tool_execution_ids", []) or [] if item
        )
        tool_execution_ids.update(
            str(item) for item in verification_bundle.get("tool_execution_ids", []) or [] if item
        )

        def collect_refs(value: Any) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    if key in {"artifact_ref", "artifact_id"} and nested:
                        artifact_refs.add(str(nested))
                    elif key == "artifact_refs" and isinstance(nested, list):
                        artifact_refs.update(str(item) for item in nested if item)
                    elif key in {"tool_execution_id", "execution_id"} and nested:
                        tool_execution_ids.add(str(nested))
                    collect_refs(nested)
            elif isinstance(value, list):
                for nested in value:
                    collect_refs(nested)

        collect_refs(items)
        discovery_level = int(discovery_bundle.get("level", 0) or 0)
        verification_level = int(verification_bundle.get("level", 0) or 0)
        merged = dict(verification_bundle)
        merged.update({
            "items": items,
            "gaps": list(dict.fromkeys(str(item) for item in verification_bundle.get("gaps", []) or [])),
            "level": max(discovery_level, verification_level),
            "artifact_refs": sorted(artifact_refs),
            "tool_execution_ids": sorted(tool_execution_ids),
        })
        discovery_gaps = list(dict.fromkeys(
            str(item) for item in discovery_bundle.get("gaps", []) or []
        ))
        if discovery_gaps:
            merged["discovery_gaps"] = discovery_gaps
        return merged
