"""Generate normalized, coding-agent-ready remediation packages."""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.agents.base import AgentConfig, AgentPattern, AgentResult, AgentType, BaseAgent
from core.remediation.tree_snapshot import build_tree_snapshot
from core.tool_fabric import ArtifactStore


logger = logging.getLogger(__name__)


class PatchStrategy(str, Enum):
    PARAMETERIZED_QUERY = "parameterized_query"
    INPUT_VALIDATION = "input_validation"
    SANITIZATION = "sanitization"
    ACCESS_CONTROL = "access_control"
    CONFIGURATION_FIX = "configuration_fix"
    ARCHITECTURE_CHANGE = "architecture_change"
    CODE_REFACTOR = "code_refactor"


@dataclass
class PatchConstraint:
    type: str
    description: str
    required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, "description": self.description, "required": self.required}


@dataclass
class RetestStep:
    step_number: int
    description: str
    action: str
    expected_result: str
    control_type: str = "positive"
    predicate: str = ""
    control_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "description": self.description,
            "action": self.action,
            "expected_result": self.expected_result,
            "control_type": self.control_type,
            "predicate": self.predicate or self.expected_result,
            "control_id": self.control_id or f"{self.control_type}-{self.step_number}",
        }


@dataclass(frozen=True)
class RemediationProfile:
    strategy: PatchStrategy
    objective: str
    controls: tuple[str, ...]
    exploit_case: str
    behavior_case: str
    expected_surface_change: str


@dataclass
class RemediationBundle:
    finding_id: str
    vulnerability_type: str
    title: str
    severity: str
    file_path: str
    line_start: int
    line_end: int
    ai_patch_prompt: str
    patch_strategy: PatchStrategy
    patch_constraints: List[PatchConstraint] = field(default_factory=list)
    retest_plan: List[RetestStep] = field(default_factory=list)
    acceptance_criteria: List[str] = field(default_factory=list)
    before_code: str = ""
    after_code: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    evidence_bundle: Optional[Dict[str, Any]] = None
    risk_chain: Optional[Dict[str, Any]] = None
    verification_status: str = "needs_evidence"
    expected_surface_change: str = ""
    change_scope: Dict[str, Any] = field(default_factory=dict)
    approval_gate: Dict[str, Any] = field(default_factory=dict)
    baseline_snapshot_ref: Optional[Dict[str, Any]] = None
    surface_node_ids: List[str] = field(default_factory=list)
    risk_hypothesis_ids: List[str] = field(default_factory=list)
    runtime_risk_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        tests = [item.to_dict() for item in self.retest_plan]
        return {
            "schema": "vibe-sec.remediation-bundle",
            "schema_version": "2.0",
            "package_id": f"REMEDIATION-{self.finding_id or 'unknown'}",
            "finding_id": self.finding_id,
            "finding_title": self.title,
            "finding_severity": self.severity,
            "vulnerability_type": self.vulnerability_type,
            "title": self.title,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "ai_patch_prompt": self.ai_patch_prompt,
            "patch_strategy": self.patch_strategy.value,
            "patch_constraints": [item.to_dict() for item in self.patch_constraints],
            "change_scope": self.change_scope,
            "approval_gate": self.approval_gate,
            "baseline_snapshot_ref": self.baseline_snapshot_ref,
            "surface_node_ids": self.surface_node_ids,
            "risk_hypothesis_ids": self.risk_hypothesis_ids,
            "runtime_risk_context": self.runtime_risk_context,
            "retest_plan": tests,
            "positive_retest_cases": [item for item in tests if item["control_type"] == "positive"],
            "negative_retest_cases": [item for item in tests if item["control_type"] == "negative"],
            "acceptance_criteria": self.acceptance_criteria,
            "expected_surface_change": self.expected_surface_change,
            "before_code": self.before_code,
            "after_code": self.after_code,
            "evidence": self.evidence,
            "evidence_bundle": self.evidence_bundle,
            "risk_chain": self.risk_chain,
            "verification_status": self.verification_status,
            "state": "draft",
            "fix_result": None,
            "metadata": {
                "vulnerability_type": self.vulnerability_type,
                "source": "remediation_agent",
                "closure_requires_retest": True,
                "proposal_only": self.verification_status != "verified",
                "affected_file": self.file_path,
                "expected_surface_change": self.expected_surface_change,
                "change_scope": self.change_scope,
                "approval_gate": self.approval_gate,
                "baseline_snapshot_ref": self.baseline_snapshot_ref,
                "surface_node_ids": self.surface_node_ids,
                "risk_hypothesis_ids": self.risk_hypothesis_ids,
                "runtime_risk_context": self.runtime_risk_context,
            },
        }


PROFILES: Dict[str, RemediationProfile] = {
    "sql_injection": RemediationProfile(
        PatchStrategy.PARAMETERIZED_QUERY,
        "Remove SQL structure control from untrusted data.",
        ("Use parameterized queries or typed ORM filters.", "Keep authorization checks before the query."),
        "An injection payload is treated only as a parameter value and cannot alter the query plan.",
        "Valid identifiers still return the authorized record set.",
        "The untrusted-input edge terminates at a parameter binding boundary before the database sink.",
    ),
    "command_injection": RemediationProfile(
        PatchStrategy.CODE_REFACTOR,
        "Remove shell interpretation and constrain command arguments.",
        ("Use an argument vector with shell disabled.", "Allowlist executable operations and validate each argument."),
        "Shell metacharacters cannot create an additional command or side effect.",
        "An approved command with valid arguments still completes.",
        "The model/user-controlled input edge no longer reaches a shell or process sink without an allowlist gate.",
    ),
    "code_injection": RemediationProfile(
        PatchStrategy.CODE_REFACTOR,
        "Remove dynamic evaluation of untrusted expressions and use a typed operation allowlist.",
        ("Do not pass request or model input to eval, exec, or dynamic Function constructors.", "Parse only the approved operation grammar and reject everything else."),
        "An attacker-controlled expression is rejected before dynamic code evaluation or side effects.",
        "A supported calculation or named operation still returns the intended result.",
        "The untrusted-input edge terminates at a typed parser or allowlist before the code-execution capability.",
    ),
    "xss": RemediationProfile(
        PatchStrategy.SANITIZATION,
        "Apply context-correct output encoding and remove unsafe HTML sinks.",
        ("Prefer text rendering APIs.", "Sanitize only when trusted HTML is a product requirement."),
        "Markup payloads render as inert text and no script-capable DOM node is created.",
        "Expected plain text and approved markup continue to render correctly.",
        "The untrusted-content edge reaches an encoding or sanitization boundary before the browser sink.",
    ),
    "path_traversal": RemediationProfile(
        PatchStrategy.INPUT_VALIDATION,
        "Bind file access to an approved root and reject traversal or alternate-path forms.",
        ("Resolve the candidate path before access.", "Verify the resolved path remains under the approved root."),
        "Traversal and absolute-path payloads are rejected before filesystem access.",
        "A valid in-root file remains readable with the same authorization semantics.",
        "The filesystem sink is preceded by canonicalization, root containment, and authorization gates.",
    ),
    "hardcoded_password": RemediationProfile(
        PatchStrategy.CONFIGURATION_FIX,
        "Remove the credential from source and rotate it.",
        ("Load the value from an approved secret provider.", "Prevent secret values from entering logs or client bundles."),
        "Repository and build artifacts contain no live credential value or recoverable derivative.",
        "The application starts successfully when the secret is supplied through the approved provider.",
        "The credential becomes a privileged external asset rather than a source-code node.",
    ),
    "api_key": RemediationProfile(
        PatchStrategy.CONFIGURATION_FIX,
        "Remove the key from source, rotate it, and use an approved secret provider.",
        ("Fail closed when the secret is absent.", "Redact the key from logs and tool output."),
        "Source, history, logs, and client artifacts do not expose the key.",
        "Authorized runtime configuration can still obtain the rotated key.",
        "The key moves behind a secret-provider trust boundary with no client-side exposure edge.",
    ),
    "mass_assignment": RemediationProfile(
        PatchStrategy.INPUT_VALIDATION,
        "Stop binding request fields directly onto privileged model attributes.",
        ("Use an explicit field allowlist for user-driven construction.", "Force server-side defaults for admin/role flags."),
        "A crafted registration or update payload cannot grant itself privileged flags.",
        "Ordinary registration and profile updates keep working with the allowlist.",
        "The request-data edge reaches the model only through an allowlist that excludes privileged fields.",
    ),
    "plaintext_password_comparison": RemediationProfile(
        PatchStrategy.CONFIGURATION_FIX,
        "Store only password hashes and verify with a constant-time comparison.",
        ("Hash at write time with a memory-hard KDF.", "Compare via a dedicated password verifier, never ==."),
        "The stored credential is a salted hash and the comparison leaks no usable secret.",
        "Login with the correct password still succeeds after migration.",
        "The credential store holds no recoverable plaintext edge, and comparison happens inside a verifier boundary.",
    ),
    "prompt_injection": RemediationProfile(
        PatchStrategy.ARCHITECTURE_CHANGE,
        "Treat external content as data and enforce policy at every model-to-tool boundary.",
        ("Separate trusted instructions from untrusted content structurally.", "Require policy checks and approval for consequential tools."),
        "Injected instructions cannot change tool policy, reveal protected context, or authorize an action.",
        "Benign external content remains available for the intended model task.",
        "Untrusted prompt/content nodes cannot reach privileged tool nodes without a policy and approval boundary.",
    ),
    "mcp_insecurity": RemediationProfile(
        PatchStrategy.ACCESS_CONTROL,
        "Constrain MCP tools, resources, roots, transport identity, and consequential actions.",
        ("Use explicit capabilities instead of wildcard permissions.", "Validate tool arguments and treat descriptions/results as untrusted."),
        "An untrusted tool description or argument cannot expand capability or access an out-of-scope resource.",
        "Approved MCP clients can still invoke the least-privilege operation.",
        "MCP transport, resource, and tool edges gain identity, scope, argument-validation, and approval gates.",
    ),
    "excessive_agency": RemediationProfile(
        PatchStrategy.ACCESS_CONTROL,
        "Reduce autonomous authority and add approval for consequential actions.",
        ("Issue minimum-scope credentials.", "Add policy, rate, budget, and human approval gates."),
        "The agent cannot perform a destructive or high-impact action without explicit authorization.",
        "Low-risk approved operations remain available within the defined scope and budget.",
        "Privileged-action edges become gated, auditable, revocable, and bounded by least privilege.",
    ),
    "ssrf": RemediationProfile(
        PatchStrategy.INPUT_VALIDATION,
        "Prevent untrusted input from selecting arbitrary network destinations.",
        ("Allowlist schemes and destination hosts.", "Resolve and reject private, loopback, link-local, and metadata addresses before each request and redirect."),
        "Private, loopback, metadata, alternate-encoding, DNS-rebinding, and redirect targets are rejected before connection.",
        "An allowlisted public destination remains reachable with the intended method and timeout.",
        "The untrusted URL edge gains canonicalization, destination policy, redirect revalidation, and bounded egress controls.",
    ),
    "unsafe_deserialization": RemediationProfile(
        PatchStrategy.CODE_REFACTOR,
        "Remove object-capable deserialization from untrusted data.",
        ("Use a data-only format and typed schema validation.", "If legacy loading is unavoidable, use a strict allowlist and isolate the parser."),
        "A payload containing object constructors or gadget metadata is rejected without code execution or side effects.",
        "A valid data-only payload still produces the expected typed object.",
        "The external-data edge terminates at a data-only parser and schema boundary before object construction.",
    ),
    "workflow_insecurity": RemediationProfile(
        PatchStrategy.CONFIGURATION_FIX,
        "Stop untrusted event fields from becoming workflow shell or code syntax.",
        ("Move event values through environment variables and quote their use.", "Minimize workflow token permissions and avoid privileged triggers for untrusted revisions."),
        "Metacharacters in attacker-controlled event fields remain inert data and cannot add a shell command.",
        "The expected workflow action still runs for a benign event value with least-privilege permissions.",
        "The event-data edge reaches a quoted data channel and permission boundary before the workflow execution sink.",
    ),
    "dependency_vulnerability": RemediationProfile(
        PatchStrategy.CONFIGURATION_FIX,
        "Upgrade or replace the exact affected dependency version using the project's native resolver.",
        (
            "Select a fixed version supported by the advisory and project compatibility constraints.",
            "Regenerate and commit the lockfile; do not edit transitive lock entries by hand.",
        ),
        "A fresh vulnerability query no longer matches the resolved package version to the advisory.",
        "Dependency resolution and the relevant project test suite complete with the upgraded lock graph.",
        "The dependency asset points to a non-affected resolved version with updated manifest and lock provenance.",
    ),
}


GENERIC_PROFILE = RemediationProfile(
    PatchStrategy.CODE_REFACTOR,
    "Remove the evidenced unsafe path while preserving intended behavior.",
    ("Fix the cause at the earliest enforceable trust boundary.", "Do not suppress the finding without changing the unsafe behavior."),
    "The original adversarial input no longer satisfies the finding's verification predicate.",
    "A representative valid input preserves the intended behavior.",
    "The risk path is removed or gains a concrete validation, authorization, or isolation boundary.",
)


class RemediationAgent(BaseAgent):
    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        llm_service=None,
        tools=None,
        event_emitter=None,
    ):
        config = config or AgentConfig(
            name="Remediation",
            agent_type=AgentType.REMEDIATION,
            pattern=AgentPattern.PLAN_AND_EXECUTE,
            max_iterations=10,
        )
        super().__init__(config=config, llm_service=llm_service, tools=tools, event_emitter=event_emitter)

    async def run(self, payload: Dict[str, Any]) -> AgentResult:
        findings = list(payload.get("verified_findings", []) or [])
        snapshot_ref = self._capture_baseline_snapshot(payload)
        bundles = [
            self._generate_remediation_bundle(finding, baseline_snapshot_ref=snapshot_ref)
            for finding in findings
        ]
        serialized = [bundle.to_dict() for bundle in bundles]
        if not bundles:
            return AgentResult.success_result(data={"remediation_bundles": [], "summary": {"total": 0}})
        handoff = self.create_handoff(
            to_agent="regression",
            summary=f"Generated {len(bundles)} evidence-bound remediation packages",
            work_completed=["root-cause strategy", "positive and negative retest plan", "closure criteria"],
            key_findings=[{
                "type": "remediation_summary",
                "total_bundles": len(bundles),
                "by_strategy": self._count_by_strategy(bundles),
            }],
            context_refs={"remediation_bundles": json.dumps(serialized)},
        )
        return AgentResult.success_result(data={
            "remediation_bundles": serialized,
            "summary": {"total": len(bundles), "by_strategy": self._count_by_strategy(bundles)},
        }, handoff=handoff)

    def _generate_remediation_bundle(
        self,
        finding: Dict[str, Any],
        *,
        baseline_snapshot_ref: Optional[Dict[str, Any]] = None,
    ) -> RemediationBundle:
        vuln_type = str(finding.get("vulnerability_type", "unknown")).lower()
        profile = PROFILES.get(vuln_type, GENERIC_PROFILE)
        status = str(finding.get("verification_status", "needs_evidence"))
        evidence_bundle = dict(finding.get("evidence_bundle") or {})
        verification_predicate = str(finding.get("verification_predicate", "")).strip()
        approval_gate = self._approval_gate(finding)
        prompt = self._build_patch_prompt(
            finding, profile, status, verification_predicate, approval_gate,
        )
        retests = [
            RetestStep(
                1,
                "Re-run the original exploit or adversarial case",
                "test_exploit",
                profile.exploit_case,
                "negative",
                profile.exploit_case,
                "negative-exploit",
            ),
            RetestStep(
                2,
                "Run a valid behavior control",
                "test_expected_behavior",
                profile.behavior_case,
                "positive",
                profile.behavior_case,
                "positive-behavior",
            ),
            RetestStep(
                3,
                "Run focused project tests and inspect the changed runtime surface",
                "check_side_effects",
                "Relevant tests pass and the expected runtime-surface change is present.",
                "positive",
                profile.expected_surface_change,
                "positive-surface",
            ),
        ]
        acceptance = [
            profile.exploit_case,
            profile.behavior_case,
            profile.expected_surface_change,
            "No new high-impact permission, network, filesystem, browser, or tool edge is introduced.",
            "Post-fix evidence is attached before the finding is marked closed.",
        ]
        if approval_gate["required"]:
            acceptance.append("A human operator explicitly approves any high-impact scope or authority change.")
        return RemediationBundle(
            finding_id=str(finding.get("id", "")),
            vulnerability_type=vuln_type,
            title=str(finding.get("title", vuln_type.replace("_", " ").title())),
            severity=str(finding.get("severity", "medium")),
            file_path=str(finding.get("file_path", "")),
            line_start=int(finding.get("line_start", 0) or 0),
            line_end=int(finding.get("line_end", 0) or 0),
            ai_patch_prompt=prompt,
            patch_strategy=profile.strategy,
            patch_constraints=[
                PatchConstraint("preserve_behavior", "Preserve the documented valid behavior and public interface."),
                PatchConstraint("least_privilege", "Do not add broader permissions or bypass an existing policy gate."),
                PatchConstraint("evidence_bound", "Keep the fix scoped to the evidenced source and runtime risk path."),
                *(
                    [PatchConstraint("human_confirmation", "Wait for human approval before expanding production scope or authority.")]
                    if approval_gate["required"] else []
                ),
            ],
            retest_plan=retests,
            acceptance_criteria=acceptance,
            evidence=list(finding.get("evidence", []) or []),
            evidence_bundle=evidence_bundle,
            risk_chain=finding.get("risk_chain"),
            verification_status=status,
            expected_surface_change=profile.expected_surface_change,
            change_scope=self._build_change_scope(finding),
            approval_gate=approval_gate,
            baseline_snapshot_ref=baseline_snapshot_ref,
            surface_node_ids=list(finding.get("surface_node_ids", []) or []),
            risk_hypothesis_ids=list(finding.get("risk_hypothesis_ids", []) or []),
            runtime_risk_context=dict(finding.get("runtime_risk_context") or {}),
        )

    @staticmethod
    def _approval_gate(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Require an explicit human decision before an agent changes high-impact boundaries."""
        severity = str(finding.get("severity", "medium")).lower()
        vulnerability_type = str(finding.get("vulnerability_type", "")).lower()
        runtime_context = dict(finding.get("runtime_risk_context") or {})
        consequential_types = {
            "prompt_injection", "indirect_prompt_injection", "excessive_agency",
            "mcp_insecurity", "workflow_insecurity", "authorization_bypass",
            "broken_access_control", "command_injection", "ssrf",
        }
        reasons = []
        if severity in {"critical", "high"}:
            reasons.append(f"{severity}_severity")
        if vulnerability_type in consequential_types:
            reasons.append(f"consequential_{vulnerability_type}")
        if runtime_context.get("control_gaps"):
            reasons.append("runtime_control_gap")
        return {
            "required": bool(reasons),
            "reasons": reasons,
            "approved_by": None,
            "approval_evidence_required": bool(reasons),
            "scope_expansion_requires_approval": True,
            "authority_expansion_forbidden": True,
        }

    @staticmethod
    def _capture_baseline_snapshot(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        project_path = str(payload.get("project_path", ""))
        if not project_path:
            return None
        try:
            snapshot = build_tree_snapshot(project_path)
            session_id = str(payload.get("session_id") or "local")
            store = ArtifactStore(
                str(Path(tempfile.gettempdir()) / "vibe-sec-artifacts"),
                session_id=f"remediation-{session_id}",
            )
            artifact = store.put_json(
                snapshot,
                producer="remediation_agent",
                artifact_type="tree_snapshot",
                file_name="tree-snapshot.json",
                metadata={"tree_digest": snapshot["tree_digest"], "file_count": snapshot["file_count"]},
            )
            return {
                "artifact_ref": artifact.artifact_id,
                "path": artifact.path,
                "sha256": artifact.sha256,
                "tree_digest": snapshot["tree_digest"],
                "file_count": snapshot["file_count"],
            }
        except (OSError, ValueError):
            return None

    @staticmethod
    def _build_change_scope(finding: Dict[str, Any]) -> Dict[str, Any]:
        affected = str(finding.get("file_path", "")).replace("\\", "/").lstrip("./")
        related = [
            str(item).replace("\\", "/").lstrip("./")
            for item in finding.get("related_files", []) or []
            if str(item).strip()
        ]
        allowed_files = list(dict.fromkeys(item for item in [affected, *related] if item))
        return {
            "required_files": [affected] if affected else [],
            "allowed_files": allowed_files,
            "allowed_globs": [
                "tests/**",
                "test/**",
                "**/tests/**",
                "**/test/**",
                "**/test_*.py",
                "**/*_test.py",
                "**/*.test.js",
                "**/*.test.jsx",
                "**/*.test.ts",
                "**/*.test.tsx",
                "**/*.spec.js",
                "**/*.spec.jsx",
                "**/*.spec.ts",
                "**/*.spec.tsx",
            ],
            "requires_approval_for_expansion": True,
            "forbidden_changes": [
                "Do not add wildcard permissions, new privileged tools, or unaudited network egress.",
                "Do not remove an existing authentication, authorization, approval, or audit control.",
            ],
            "risk_hypothesis_ids": list(
                dict(finding.get("runtime_risk_context") or {}).get("risk_hypothesis_ids", []) or []
            ),
        }

    @staticmethod
    def _build_patch_prompt(
        finding: Dict[str, Any],
        profile: RemediationProfile,
        status: str,
        predicate: str,
        approval_gate: Dict[str, Any],
    ) -> str:
        evidence_gaps = list((finding.get("evidence_bundle") or {}).get("gaps", []) or [])
        lines = [
            f"Fix security finding {finding.get('id', 'unknown')}: {finding.get('title', 'Untitled finding')}.",
            f"Location: {finding.get('file_path', '')}:{finding.get('line_start', 0)}-{finding.get('line_end', 0)}.",
            f"Verification status: {status}.",
            f"Objective: {profile.objective}",
            "Required controls:",
            *[f"- {control}" for control in profile.controls],
            "Constraints:",
            "- Preserve intended behavior and existing public interfaces unless the security boundary requires an explicit change.",
            "- Do not hide, suppress, or merely rename the risky operation.",
            "- Add focused tests for both the adversarial case and a valid behavior control.",
            "- Keep source changes within change_scope; request explicit approval before modifying other production files.",
        ]
        if predicate:
            lines.append(f"Original verification predicate: {predicate}")
        if evidence_gaps:
            lines.append("Open evidence gaps must be resolved during retest: " + "; ".join(map(str, evidence_gaps)))
        risk_context = dict(finding.get("runtime_risk_context") or {})
        if risk_context.get("risk_hypothesis_ids"):
            lines.append("Runtime risk hypotheses: " + ", ".join(risk_context["risk_hypothesis_ids"]))
        if risk_context.get("control_gaps"):
            lines.append("Runtime control gaps to address: " + "; ".join(risk_context["control_gaps"]))
        if approval_gate.get("required"):
            lines.append(
                "Human confirmation is required before expanding production-file scope or changing a high-impact authority boundary."
            )
        if status != "verified":
            lines.append("Treat this package as a bounded remediation proposal until post-fix verification closes the evidence gaps.")
        return "\n".join(lines)

    @staticmethod
    def _count_by_strategy(bundles: List[RemediationBundle]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for bundle in bundles:
            key = bundle.patch_strategy.value
            counts[key] = counts.get(key, 0) + 1
        return counts
