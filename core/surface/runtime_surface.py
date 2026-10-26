"""Structured extraction of the composite runtime surface.

The surface is intentionally a normalized inventory with source provenance.  It
does not claim that co-located objects are connected; security-relevant edges
are created later by :class:`RuntimeSurfaceGraph` from explicit references and
bounded provenance rules.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..tool_fabric.framework_semantics import analyze_framework_semantics

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover - declared dependency, failure is recorded in coverage.
    get_parser = None

from ..languages.tree_sitter_gateway import parser_for

try:
    import yaml
except ImportError:  # pragma: no cover - declared dependency, failure is recorded in coverage.
    yaml = None

from ..sanitization import redact_sensitive_text


logger = logging.getLogger(__name__)

# Some Tree-sitter grammar builds can terminate the interpreter on malformed or
# complex source. Keep the portable extractor as the default and make native
# parsing an explicit opt-in until the grammar/runtime combination is proven.
_NATIVE_TREE_SITTER_ENABLED = os.getenv("VIBE_SEC_ENABLE_TREE_SITTER") == "1"

_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_FRAMEWORK_ONLY_SUFFIXES = {".java", ".go"}
_CONFIG_SUFFIXES = {".json", ".yaml", ".yml"}
_IGNORED_DIRS = {".git", ".idea", ".vscode", "node_modules", "__pycache__", "venv", ".venv", "dist", "build"}
_MAX_FILE_BYTES = 1_000_000
_OPENAPI_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
_DANGEROUS_OPERATIONS = {
    "eval", "exec", "system", "popen", "subprocess", "spawn", "execsync",
    "unlink", "rmtree", "remove", "delete", "drop", "writefile", "shell",
}
_APPROVAL_MARKERS = {"approval", "approve", "confirm", "authorize", "permission", "policy"}
_SENSITIVE_NAME_MARKERS = {"token", "secret", "password", "credential", "session", "cookie", "key"}


class EntryType(Enum):
    HTTP_ROUTE = "http_route"
    API_ENDPOINT = "api_endpoint"
    CLI_COMMAND = "cli_command"
    MESSAGE_HANDLER = "message_handler"
    TOOL_ENTRY = "tool_entry"


class TrustBoundary(Enum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_VALIDATION = "data_validation"
    NETWORK = "network"
    PROCESS = "process"


@dataclass
class PageEntry:
    path: str
    method: str
    entry_type: EntryType
    file_path: str
    line_start: int
    line_end: int
    handler_function: Optional[str] = None
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    authentication_required: bool = False
    # ``False`` only says extraction did not see a local guard.  The state
    # records whether that is unknown, declared, or backed by runtime evidence.
    authentication_state: str = "unknown"
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["entry_type"] = self.entry_type.value
        return value


@dataclass
class PromptConfig:
    name: str
    type: str
    content: str
    file_path: str
    line_start: int
    has_input_validation: bool = False
    has_injection_protection: bool = False
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["content"] = redact_sensitive_text(self.content[:200])
        return value


@dataclass
class ModelInvocation:
    name: str
    provider: str
    operation: str
    file_path: str
    line_start: int
    line_end: int
    prompt_refs: List[str] = field(default_factory=list)
    tool_enabled: bool = False
    streaming: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolProfile:
    name: str
    description: str
    file_path: str
    line_start: int
    permissions: List[str] = field(default_factory=list)
    requires_confirmation: bool = False
    dangerous_operations: List[str] = field(default_factory=list)
    risk_level: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class McpCapability:
    name: str
    capability_type: str
    server: str
    description: str
    file_path: str
    line_start: int
    line_end: int
    registration: str
    dynamic_registration: bool = False
    transport: Optional[str] = None
    uri_template: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    authorization: str = "unknown"
    consequential_operations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PermissionProfile:
    permission_type: str
    description: str
    file_path: str
    line_start: int
    enforced: bool = True
    bypass_risks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserSink:
    sink_type: str
    expression: str
    file_path: str
    line_start: int
    line_end: int
    dangerous: bool = True
    sanitization_detected: bool = False
    input_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StorageAsset:
    name: str
    storage_type: str
    operation: str
    file_path: str
    line_start: int
    line_end: int
    sensitive: bool = False
    access_control: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExternalContentInput:
    name: str
    source_type: str
    expression: str
    file_path: str
    line_start: int
    line_end: int
    trust_zone: str = "untrusted"
    target_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowNode:
    workflow_name: str
    node_name: str
    node_type: str
    file_path: str
    line_start: int
    line_end: int
    trigger: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    untrusted_inputs: List[str] = field(default_factory=list)
    permissions: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TrustBoundaryDefinition:
    boundary_type: TrustBoundary
    description: str
    source: str
    target: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    validation_mechanism: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        value = asdict(self)
        value["boundary_type"] = self.boundary_type.value
        return value


@dataclass
class CodeBlock:
    block_type: str
    name: str
    file_path: str
    line_start: int
    line_end: int
    contains_user_input: bool = False
    contains_dangerous_operations: bool = False
    calls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuntimeSurface:
    project_path: str
    page_entries: List[PageEntry] = field(default_factory=list)
    prompt_configs: List[PromptConfig] = field(default_factory=list)
    model_invocations: List[ModelInvocation] = field(default_factory=list)
    tool_profiles: List[ToolProfile] = field(default_factory=list)
    mcp_capabilities: List[McpCapability] = field(default_factory=list)
    permission_profiles: List[PermissionProfile] = field(default_factory=list)
    browser_sinks: List[BrowserSink] = field(default_factory=list)
    storage_assets: List[StorageAsset] = field(default_factory=list)
    external_content_inputs: List[ExternalContentInput] = field(default_factory=list)
    workflow_nodes: List[WorkflowNode] = field(default_factory=list)
    trust_boundaries: List[TrustBoundaryDefinition] = field(default_factory=list)
    code_blocks: List[CodeBlock] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_path": self.project_path,
            "page_entries": [item.to_dict() for item in self.page_entries],
            "prompt_configs": [item.to_dict() for item in self.prompt_configs],
            "model_invocations": [item.to_dict() for item in self.model_invocations],
            "tool_profiles": [item.to_dict() for item in self.tool_profiles],
            "mcp_capabilities": [item.to_dict() for item in self.mcp_capabilities],
            "permission_profiles": [item.to_dict() for item in self.permission_profiles],
            "browser_sinks": [item.to_dict() for item in self.browser_sinks],
            "storage_assets": [item.to_dict() for item in self.storage_assets],
            "external_content_inputs": [item.to_dict() for item in self.external_content_inputs],
            "workflow_nodes": [item.to_dict() for item in self.workflow_nodes],
            "trust_boundaries": [item.to_dict() for item in self.trust_boundaries],
            "code_blocks": [item.to_dict() for item in self.code_blocks],
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_entries": len(self.page_entries),
            "total_prompts": len(self.prompt_configs),
            "total_models": len(self.model_invocations),
            "total_tools": len(self.tool_profiles),
            "total_mcp_capabilities": len(self.mcp_capabilities),
            "total_permissions": len(self.permission_profiles),
            "total_browser_sinks": len(self.browser_sinks),
            "total_storage_assets": len(self.storage_assets),
            "total_external_inputs": len(self.external_content_inputs),
            "total_workflow_nodes": len(self.workflow_nodes),
            "total_trust_boundaries": len(self.trust_boundaries),
            "total_code_blocks": len(self.code_blocks),
            "entry_types": sorted({item.entry_type.value for item in self.page_entries}),
            "high_risk_tools": sum(item.risk_level in {"high", "critical"} for item in self.tool_profiles),
            "unprotected_entries": sum(
                not item.authentication_required
                and item.authentication_state in {"runtime_observed", "verified"}
                for item in self.page_entries
            ),
            "authentication_unknown_entries": sum(
                item.authentication_state == "unknown" for item in self.page_entries
            ),
        }


class RuntimeSurfaceBuilder:
    """Build a source-grounded runtime inventory with bounded extraction."""

    def __init__(self, project_path: str):
        self.project_path = str(Path(project_path).resolve())
        self.surface = RuntimeSurface(project_path=self.project_path)
        self._coverage = {
            "files_considered": 0,
            "files_parsed": 0,
            "parse_failures": [],
            "skipped_large_files": [],
            "extractors": {
                "python_ast": True,
                "tree_sitter": get_parser is not None and _NATIVE_TREE_SITTER_ENABLED,
                "javascript_fallback": False,
                "yaml": yaml is not None,
            },
        }
        self._tree_sitter_failed = get_parser is None or not _NATIVE_TREE_SITTER_ENABLED
        self._parser_cache: Dict[str, Any] = {}

    async def build(self, recon_data: Optional[Dict[str, Any]] = None) -> RuntimeSurface:
        root = Path(self.project_path)
        if not root.is_dir():
            raise ValueError(f"Project path is not a directory: {self.project_path}")
        for path in self._iter_files(root):
            self._coverage["files_considered"] += 1
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    self._coverage["skipped_large_files"].append(path.relative_to(root).as_posix())
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
                relative = path.relative_to(root).as_posix()
                if path.suffix.lower() == ".py":
                    self._extract_python(relative, content)
                elif path.suffix.lower() in _SOURCE_SUFFIXES:
                    self._extract_javascript(relative, content, path.suffix.lower())
                elif path.suffix.lower() in _FRAMEWORK_ONLY_SUFFIXES:
                    pass
                elif path.suffix.lower() in _CONFIG_SUFFIXES:
                    self._extract_config(relative, content, path.suffix.lower())
                self._coverage["files_parsed"] += 1
            except (OSError, SyntaxError, ValueError) as exc:
                self._coverage["parse_failures"].append({
                    "file_path": path.relative_to(root).as_posix(),
                    "error": type(exc).__name__,
                })
        framework_report = analyze_framework_semantics(root, max_file_bytes=_MAX_FILE_BYTES)
        self._merge_framework_semantics(framework_report.to_dict())
        self._infer_trust_boundaries()
        self._deduplicate()
        self.surface.metadata["extraction_coverage"] = self._coverage
        self.surface.metadata["framework_semantics"] = framework_report.to_dict()
        if recon_data:
            self.surface.metadata["recon_data"] = {
                "tech_stack": recon_data.get("tech_stack", {}),
                "entry_points": recon_data.get("entry_points", []),
            }
        logger.info("RuntimeSurface built: %s", self.surface.get_summary())
        return self.surface

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES | _FRAMEWORK_ONLY_SUFFIXES | _CONFIG_SUFFIXES:
                continue
            if any(part in _IGNORED_DIRS for part in path.relative_to(root).parts):
                continue
            yield path

    def _merge_framework_semantics(self, report: Dict[str, Any]) -> None:
        graph_frameworks = {"nest", "next", "spring", "go-http", "gin", "echo", "chi"}
        for item in report.get("observations", []) or []:
            if item.get("framework") not in graph_frameworks:
                continue
            semantic_type = str(item.get("semantic_type", ""))
            details = dict(item.get("details") or {})
            file_path = str(item.get("file_path", ""))
            line_start = int(item.get("line_start", 1) or 1)
            line_end = int(item.get("line_end", line_start) or line_start)
            operation = str(item.get("operation", "framework_operation"))
            framework = str(item.get("framework", "unknown"))
            if semantic_type == "route":
                self.surface.page_entries.append(PageEntry(
                    path=str(details.get("route") or "<dynamic-route>"),
                    method=str(details.get("method") or "ANY"),
                    entry_type=EntryType.API_ENDPOINT,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    handler_function=str(item.get("symbol", "")) or None,
                    description=f"{framework} framework route",
                ))
            elif semantic_type in {"authentication_guard", "authorization_guard", "validation"}:
                permission_type = {
                    "authentication_guard": "authentication",
                    "authorization_guard": "authorization",
                    "validation": "data_validation",
                }[semantic_type]
                self.surface.permission_profiles.append(PermissionProfile(
                    permission_type=permission_type,
                    description=f"{framework}: {operation}",
                    file_path=file_path,
                    line_start=line_start,
                    enforced=True,
                ))
            elif semantic_type == "untrusted_input":
                self.surface.external_content_inputs.append(ExternalContentInput(
                    name=operation,
                    source_type="framework_request",
                    expression=str(item.get("symbol") or operation),
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                ))
            elif semantic_type in {"orm_operation", "sql_sink"}:
                self.surface.storage_assets.append(StorageAsset(
                    name=operation,
                    storage_type="database",
                    operation="raw_query" if semantic_type == "sql_sink" else "orm_operation",
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    access_control="unknown",
                ))
            elif semantic_type == "code_execution_sink":
                self.surface.tool_profiles.append(ToolProfile(
                    name=operation,
                    description=f"{framework} process execution capability",
                    file_path=file_path,
                    line_start=line_start,
                    dangerous_operations=["process_execution"],
                    risk_level="high",
                ))

    def _extract_python(self, file_path: str, content: str) -> None:
        tree = ast.parse(content)
        lines = content.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                node_text = _python_source(node, content)
                calls = sorted({
                    _python_name(child.func) for child in ast.walk(node)
                    if isinstance(child, ast.Call) and _python_name(child.func)
                })
                self.surface.code_blocks.append(CodeBlock(
                    block_type="class" if isinstance(node, ast.ClassDef) else "function",
                    name=node.name,
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    contains_user_input=_contains_any(node_text, ("request.", "input(", "sys.argv", "event")),
                    contains_dangerous_operations=bool(_dangerous_names(calls)),
                    calls=calls[:50],
                ))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._extract_python_function(file_path, content, node)
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                self._extract_python_assignment(file_path, node)
            if isinstance(node, ast.Call):
                self._extract_python_call(file_path, content, node)
            if isinstance(node, ast.Attribute):
                expression = _python_name(node)
                source_type = _python_external_source(expression)
                if source_type:
                    self.surface.external_content_inputs.append(ExternalContentInput(
                        name=expression, source_type=source_type, expression=expression,
                        file_path=file_path, line_start=node.lineno,
                        line_end=getattr(node, "end_lineno", node.lineno),
                    ))

        # Flask/FastAPI authentication commonly lives between route and handler.
        for entry in [item for item in self.surface.page_entries if item.file_path == file_path]:
            nearby = "\n".join(lines[max(0, entry.line_start - 2): min(len(lines), entry.line_end + 3)]).lower()
            entry.authentication_required = any(marker in nearby for marker in _APPROVAL_MARKERS | {"login_required", "requires_auth"})
            if entry.authentication_required:
                entry.authentication_state = "static_observed"

    def _extract_python_function(self, file_path: str, content: str, node: ast.AST) -> None:
        assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        decorators = [
            (_python_name(item.func), item) if isinstance(item, ast.Call) else (_python_name(item), item)
            for item in node.decorator_list
        ]
        for name, decorator in decorators:
            short = name.rsplit(".", 1)[-1].lower()
            if short in {"route", "get", "post", "put", "delete", "patch", "websocket"}:
                args = decorator.args if isinstance(decorator, ast.Call) else []
                path = _python_literal(args[0]) if args else "<dynamic-route>"
                method = short.upper() if short != "route" else _python_route_method(decorator)
                self.surface.page_entries.append(PageEntry(
                    path=path or "<dynamic-route>", method=method,
                    entry_type=EntryType.API_ENDPOINT if short != "route" else EntryType.HTTP_ROUTE,
                    file_path=file_path, line_start=decorator.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno), handler_function=node.name,
                ))
            if short in {"tool", "mcp_tool", "resource", "mcp_resource"}:
                self._add_python_mcp(file_path, content, node, name, decorator, short)

        calls = [_python_name(child.func) for child in ast.walk(node) if isinstance(child, ast.Call)]
        dangerous = _dangerous_names(calls)
        if node.name.endswith("_tool") or node.name.endswith("Tool"):
            self.surface.tool_profiles.append(ToolProfile(
                name=node.name, description=ast.get_docstring(node) or f"Tool: {node.name}",
                file_path=file_path, line_start=node.lineno,
                requires_confirmation=_has_approval_marker(_python_source(node, content)),
                dangerous_operations=dangerous,
                risk_level=_risk_level(dangerous),
            ))
        for name, decorator in decorators:
            lowered = name.lower()
            if any(marker in lowered for marker in ("login_required", "requires_auth", "permission_required", "role_required", "authorize")):
                permission_type = "authentication" if "auth" in lowered or "login" in lowered else "authorization"
                self.surface.permission_profiles.append(PermissionProfile(
                    permission_type=permission_type, description=f"Decorator: {name}",
                    file_path=file_path, line_start=decorator.lineno, enforced=True,
                ))

    def _add_python_mcp(
        self,
        file_path: str,
        content: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        registration: str,
        decorator: ast.AST,
        short: str,
    ) -> None:
        call = decorator if isinstance(decorator, ast.Call) else None
        description = ast.get_docstring(node) or ""
        name = node.name
        uri_template = None
        if call:
            for keyword in call.keywords:
                if keyword.arg == "description":
                    description = _python_literal(keyword.value) or description
                elif keyword.arg == "name":
                    name = _python_literal(keyword.value) or name
            if short in {"resource", "mcp_resource"} and call.args:
                uri_template = _python_literal(call.args[0]) or None
        node_text = _python_source(node, content)
        calls = [_python_name(child.func) for child in ast.walk(node) if isinstance(child, ast.Call)]
        dangerous = _dangerous_names(calls)
        authorization = "enforced" if _has_approval_marker(node_text) else "unknown"
        self.surface.mcp_capabilities.append(McpCapability(
            name=name, capability_type="resource" if "resource" in short else "tool",
            server=registration.rsplit(".", 1)[0] or "mcp", description=description,
            file_path=file_path, line_start=node.lineno,
            line_end=getattr(node, "end_lineno", node.lineno), registration=registration,
            dynamic_registration=False, uri_template=uri_template,
            authorization=authorization, consequential_operations=dangerous,
        ))
        if "resource" not in short:
            self.surface.tool_profiles.append(ToolProfile(
                name=name, description=description or f"MCP tool: {name}", file_path=file_path,
                line_start=node.lineno, requires_confirmation=authorization == "enforced",
                dangerous_operations=dangerous, risk_level=_risk_level(dangerous),
            ))

    def _extract_python_assignment(self, file_path: str, node: ast.Assign | ast.AnnAssign) -> None:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        for target in targets:
            name = _python_name(target)
            literal = _python_literal(value)
            if literal and any(marker in name.lower() for marker in ("prompt", "system_message", "instructions")):
                self.surface.prompt_configs.append(PromptConfig(
                    name=name, type="system" if "system" in name.lower() else "template",
                    content=literal, file_path=file_path, line_start=node.lineno,
                    has_input_validation=False,
                    has_injection_protection=_contains_any(literal.lower(), ("do not follow", "untrusted content", "ignore instructions in")),
                ))

    def _extract_python_call(self, file_path: str, content: str, node: ast.Call) -> None:
        name = _python_name(node.func)
        lowered = name.lower()
        if any(marker in lowered for marker in ("chat.completions.create", "responses.create", "messages.create", "generate_content", "invoke_model")):
            source = _python_source(node, content)
            provider = "openai" if "chat.completions" in lowered or "responses" in lowered else "anthropic" if "messages" in lowered else "unknown"
            self.surface.model_invocations.append(ModelInvocation(
                name=f"{name}@{node.lineno}", provider=provider, operation=name,
                file_path=file_path, line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                prompt_refs=_prompt_refs(source), tool_enabled="tools" in source,
                streaming="stream" in source,
            ))
        source_type = _python_external_source(name)
        if source_type:
            expression = _python_source(node, content)[:300]
            self.surface.external_content_inputs.append(ExternalContentInput(
                name=name, source_type=source_type, expression=expression,
                file_path=file_path, line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                target_refs=_prompt_refs(expression),
            ))
        storage = _python_storage(name, node)
        if storage:
            storage_type, operation, asset_name = storage
            self.surface.storage_assets.append(StorageAsset(
                name=asset_name, storage_type=storage_type, operation=operation,
                file_path=file_path, line_start=node.lineno,
                line_end=getattr(node, "end_lineno", node.lineno),
                sensitive=_is_sensitive_name(asset_name),
            ))

    def _extract_javascript(self, file_path: str, content: str, suffix: str) -> None:
        if self._tree_sitter_failed:
            self._record_javascript_fallback(file_path, "tree_sitter_unavailable")
            self._extract_javascript_fallback(file_path, content)
            return
        language = "tsx" if suffix in {".tsx", ".jsx"} else "typescript" if suffix in {".ts", ".mts", ".cts"} else "javascript"
        source = content.encode("utf-8", errors="replace")
        try:
            parser = self._parser_cache.get(language)
            if parser is None:
                parser = parser_for(language)
                self._parser_cache[language] = parser
            if parser is None:
                # 下载被阻断（离线/受限网络），走既有降级路径。
                self._tree_sitter_failed = True
                self._coverage["extractors"]["tree_sitter"] = False
                self._record_javascript_fallback(file_path, "tree_sitter_unavailable")
                self._extract_javascript_fallback(file_path, content)
                return
            tree = parser.parse(source)
        except Exception as exc:  # Parser packs can fail while downloading native grammars.
            self._tree_sitter_failed = True
            self._coverage["extractors"]["tree_sitter"] = False
            self._record_javascript_fallback(
                file_path,
                f"tree_sitter_runtime_unavailable:{type(exc).__name__}",
            )
            self._extract_javascript_fallback(file_path, content)
            return
        if tree.root_node.has_error:
            self._coverage["parse_failures"].append({"file_path": file_path, "error": "tree_sitter_partial_parse"})
        for node in _walk_ts(tree.root_node):
            if node.type in {"function_declaration", "method_definition", "arrow_function", "function_expression"}:
                name = _ts_function_name(source, node)
                if name:
                    text = _ts_text(source, node)
                    calls = sorted(set(_ts_calls(source, node)))
                    self.surface.code_blocks.append(CodeBlock(
                        block_type="function", name=name, file_path=file_path,
                        line_start=node.start_point.row + 1, line_end=node.end_point.row + 1,
                        contains_user_input=_contains_any(text, ("req.", "request.", "event.", "location.")),
                        contains_dangerous_operations=bool(_dangerous_names(calls)), calls=calls[:50],
                    ))
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                name = _ts_text(source, name_node)
                literal = _ts_string(source, value_node)
                if literal and any(marker in name.lower() for marker in ("prompt", "systemmessage", "instructions")):
                    self.surface.prompt_configs.append(PromptConfig(
                        name=name, type="system" if "system" in name.lower() else "template",
                        content=literal, file_path=file_path, line_start=node.start_point.row + 1,
                        has_injection_protection=_contains_any(literal.lower(), ("do not follow", "untrusted content", "ignore instructions in")),
                    ))
                if value_node is not None:
                    value_text = _ts_text(source, value_node)
                    source_type = _javascript_external_source(value_text)
                    if not source_type and value_node.type in {"await_expression", "call_expression"}:
                        source_type = _javascript_external_source(value_text.replace("await ", "").split("(", 1)[0])
                    if source_type:
                        self.surface.external_content_inputs.append(ExternalContentInput(
                            name=name, source_type=source_type, expression=value_text[:300],
                            file_path=file_path, line_start=node.start_point.row + 1,
                            line_end=node.end_point.row + 1,
                            target_refs=_prompt_refs(value_text),
                        ))
            if node.type == "call_expression":
                self._extract_ts_call(file_path, source, node)
            if node.type in {"assignment_expression", "augmented_assignment_expression"}:
                self._extract_ts_assignment(file_path, source, node)
            if node.type == "member_expression":
                expression = _ts_text(source, node)
                source_type = _javascript_external_source(expression)
                if source_type:
                    self.surface.external_content_inputs.append(ExternalContentInput(
                        name=expression, source_type=source_type, expression=expression,
                        file_path=file_path, line_start=node.start_point.row + 1,
                        line_end=node.end_point.row + 1,
                    ))

    def _record_javascript_fallback(self, file_path: str, error: str) -> None:
        self._coverage["extractors"]["javascript_fallback"] = True
        record = {"file_path": file_path, "error": error, "fallback": "local_line_analysis"}
        if record not in self._coverage["parse_failures"]:
            self._coverage["parse_failures"].append(record)

    def _extract_javascript_fallback(self, file_path: str, content: str) -> None:
        """Keep a bounded local surface when native parser packs are unavailable."""
        lines = content.splitlines()
        for line_number, line in enumerate(lines, 1):
            function_match = re.search(
                r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|"
                r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>",
                line,
            )
            if function_match:
                name = function_match.group(1) or function_match.group(2)
                self.surface.code_blocks.append(CodeBlock(
                    block_type="function",
                    name=name,
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    contains_user_input=_contains_any(line, ("req.", "request.", "event.", "location.")),
                    contains_dangerous_operations=bool(_dangerous_names([line])),
                    calls=[],
                ))

            prompt_match = re.search(
                r"\b(?:const|let|var)\s+([\w$]*(?:prompt|message|instructions)[\w$]*)\s*=\s*(['\"])(.*?)\2",
                line,
                re.IGNORECASE,
            )
            if prompt_match:
                name, literal = prompt_match.group(1), prompt_match.group(3)
                self.surface.prompt_configs.append(PromptConfig(
                    name=name,
                    type="system" if "system" in name.lower() else "template",
                    content=literal,
                    file_path=file_path,
                    line_start=line_number,
                    has_injection_protection=_contains_any(
                        literal.lower(),
                        ("do not follow", "untrusted content", "ignore instructions in"),
                    ),
                ))

            route_match = re.search(
                r"\b(?:app|router|server)\.(get|post|put|patch|delete)\s*\(\s*(['\"])(.*?)\2",
                line,
                re.IGNORECASE,
            )
            if route_match:
                self.surface.page_entries.append(PageEntry(
                    path=route_match.group(3),
                    method=route_match.group(1).upper(),
                    entry_type=EntryType.HTTP_ROUTE,
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                ))

            if re.search(r"\b(?:chat\.completions|responses|messages)\.create\s*\(", line):
                operation = re.search(r"([\w$.]+\.create)\s*\(", line)
                name = operation.group(1) if operation else "model.create"
                nearby = "\n".join(lines[line_number - 1:min(len(lines), line_number + 5)])
                self.surface.model_invocations.append(ModelInvocation(
                    name=f"{name}@{line_number}",
                    provider="openai" if "responses" in name or "chat.completions" in name else "anthropic",
                    operation=name,
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    prompt_refs=_prompt_refs(nearby),
                    tool_enabled="tools" in nearby,
                    streaming="stream" in nearby,
                ))

            sink_match = re.search(r"\.?(innerHTML|outerHTML|srcdoc)\s*=", line)
            if sink_match:
                self.surface.browser_sinks.append(BrowserSink(
                    sink_type=sink_match.group(1),
                    expression=line.strip()[:300],
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    sanitization_detected=_contains_any(line.lower(), ("sanitize", "dompurify", "escape")),
                    input_refs=_identifier_refs(line.split("=", 1)[-1]),
                ))

            storage_match = re.search(
                r"\b(localStorage|sessionStorage)\.(setItem|getItem|removeItem)\s*\(\s*(['\"])(.*?)\3",
                line,
            )
            if storage_match:
                asset_name = storage_match.group(4)
                self.surface.storage_assets.append(StorageAsset(
                    name=asset_name,
                    storage_type=storage_match.group(1),
                    operation=storage_match.group(2),
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    sensitive=_is_sensitive_name(asset_name),
                ))

            source_type = _javascript_external_source(line)
            if not source_type and re.search(
                r"\b[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\.(?:json|text|formData)\s*\(",
                line,
            ):
                source_type = "network_response"
            if source_type:
                assignment = re.search(
                    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=",
                    line,
                )
                self.surface.external_content_inputs.append(ExternalContentInput(
                    name=assignment.group(1) if assignment else line.strip()[:120],
                    source_type=source_type,
                    expression=line.strip()[:300],
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    target_refs=_prompt_refs(line),
                ))

        for match in re.finditer(
            r"(?P<server>[A-Za-z_$][\w$]*)\.(?P<registration>registerTool|tool)\s*\(\s*"
            r"(?P<quote>['\"])(?P<name>.*?)(?P=quote)",
            content,
        ):
            line_number = content.count("\n", 0, match.start()) + 1
            snippet = content[match.start():match.start() + 800]
            description_match = re.search(r"description\s*:\s*(['\"])(.*?)\1", snippet, re.DOTALL)
            dangerous = _dangerous_names(re.findall(r"\b([A-Za-z_$][\w$.]*)\s*\(", snippet))
            name = match.group("name")
            description = description_match.group(2) if description_match else "MCP tool registration"
            self.surface.mcp_capabilities.append(McpCapability(
                name=name,
                capability_type="tool",
                server=match.group("server"),
                description=description,
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                registration=f"{match.group('server')}.{match.group('registration')}",
                consequential_operations=dangerous,
            ))
            self.surface.tool_profiles.append(ToolProfile(
                name=name,
                description=description,
                file_path=file_path,
                line_start=line_number,
                dangerous_operations=dangerous,
                risk_level=_risk_level(dangerous),
            ))

    def _extract_ts_call(self, file_path: str, source: bytes, node: Any) -> None:
        function = node.child_by_field_name("function")
        name = _ts_expression_name(source, function)
        short = name.rsplit(".", 1)[-1]
        args_node = node.child_by_field_name("arguments")
        args = list(args_node.named_children) if args_node is not None else []
        line_start, line_end = node.start_point.row + 1, node.end_point.row + 1
        if short.lower() in {"get", "post", "put", "delete", "patch", "use"} and name.split(".", 1)[0] in {"app", "router", "server"}:
            path = _ts_string(source, args[0]) if args else ""
            if path:
                handler = _ts_function_name(source, args[-1]) if args else None
                self.surface.page_entries.append(PageEntry(
                    path=path, method=short.upper(), entry_type=EntryType.HTTP_ROUTE,
                    file_path=file_path, line_start=line_start, line_end=line_end,
                    handler_function=handler,
                    authentication_required=any(_has_approval_marker(_ts_text(source, arg)) for arg in args[1:-1]),
                    authentication_state=(
                        "static_observed"
                        if any(_has_approval_marker(_ts_text(source, arg)) for arg in args[1:-1])
                        else "unknown"
                    ),
                ))
        if short in {"tool", "registerTool", "resource", "registerResource"}:
            capability_type = "resource" if "resource" in short.lower() else "tool"
            capability_name = _ts_string(source, args[0]) if args else ""
            description = _ts_property_string(source, args, "description")
            handler = next((arg for arg in reversed(args) if arg.type in {"arrow_function", "function_expression"}), None)
            handler_text = _ts_text(source, handler)
            dangerous = _dangerous_names(_ts_calls(source, handler)) if handler is not None else []
            authorization = "enforced" if _has_approval_marker(handler_text) else "unknown"
            server = name.rsplit(".", 1)[0] or "mcp"
            self.surface.mcp_capabilities.append(McpCapability(
                name=capability_name or f"dynamic@{line_start}", capability_type=capability_type,
                server=server, description=description, file_path=file_path,
                line_start=line_start, line_end=line_end, registration=name,
                dynamic_registration=not bool(capability_name),
                uri_template=capability_name if capability_type == "resource" else None,
                authorization=authorization, consequential_operations=dangerous,
            ))
            if capability_type == "tool":
                self.surface.tool_profiles.append(ToolProfile(
                    name=capability_name or f"dynamic@{line_start}",
                    description=description or "MCP tool registration", file_path=file_path,
                    line_start=line_start, requires_confirmation=authorization == "enforced",
                    dangerous_operations=dangerous, risk_level=_risk_level(dangerous),
                ))
        lowered = name.lower()
        if any(marker in lowered for marker in ("chat.completions.create", "responses.create", "messages.create", "generatecontent", "invokemodel")):
            text = _ts_text(source, node)
            provider = "openai" if "chat.completions" in lowered or "responses" in lowered else "anthropic" if "messages" in lowered else "unknown"
            self.surface.model_invocations.append(ModelInvocation(
                name=f"{name}@{line_start}", provider=provider, operation=name,
                file_path=file_path, line_start=line_start, line_end=line_end,
                prompt_refs=_prompt_refs(text), tool_enabled="tools" in text,
                streaming="stream" in text,
            ))
        if short in {"insertAdjacentHTML", "write", "writeln"} and ("document." in name or short == "insertAdjacentHTML"):
            text = _ts_text(source, node)
            self.surface.browser_sinks.append(BrowserSink(
                sink_type=short, expression=text[:300], file_path=file_path,
                line_start=line_start, line_end=line_end,
                sanitization_detected=_contains_any(text.lower(), ("sanitize", "dompurify", "escape")),
                input_refs=_identifier_refs(text),
            ))
        source_type = _javascript_external_source(name)
        if source_type or short in {"fetch", "json", "text", "formData"}:
            text = _ts_text(source, node)
            self.surface.external_content_inputs.append(ExternalContentInput(
                name=name, source_type=source_type or "network_response", expression=text[:300],
                file_path=file_path, line_start=line_start, line_end=line_end,
                target_refs=_prompt_refs(text),
            ))
        storage = _javascript_storage(name, args, source)
        if storage:
            storage_type, operation, asset_name = storage
            self.surface.storage_assets.append(StorageAsset(
                name=asset_name, storage_type=storage_type, operation=operation,
                file_path=file_path, line_start=line_start, line_end=line_end,
                sensitive=_is_sensitive_name(asset_name),
            ))

    def _extract_ts_assignment(self, file_path: str, source: bytes, node: Any) -> None:
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        left_text = _ts_text(source, left)
        sink_type = left_text.rsplit(".", 1)[-1]
        if sink_type not in {"innerHTML", "outerHTML", "srcdoc", "href", "src"}:
            return
        right_text = _ts_text(source, right)
        self.surface.browser_sinks.append(BrowserSink(
            sink_type=sink_type, expression=_ts_text(source, node)[:300], file_path=file_path,
            line_start=node.start_point.row + 1, line_end=node.end_point.row + 1,
            dangerous=sink_type in {"innerHTML", "outerHTML", "srcdoc", "href", "src"},
            sanitization_detected=_contains_any(right_text.lower(), ("sanitize", "dompurify", "escape")),
            input_refs=_identifier_refs(right_text),
        ))

    def _extract_config(self, file_path: str, content: str, suffix: str) -> None:
        if suffix == ".json":
            payload = json.loads(content)
        else:
            if yaml is None:
                raise ValueError("PyYAML unavailable")
            payload = yaml.safe_load(content)
        if not isinstance(payload, dict):
            return
        if _is_workflow_path(file_path) and isinstance(payload.get("jobs"), dict):
            self._extract_workflow(file_path, content, payload)
        if isinstance(payload.get("paths"), dict) and (
            "openapi" in payload or "swagger" in payload
        ):
            self._extract_openapi(file_path, content, payload)
        servers = payload.get("mcpServers") or payload.get("mcp_servers")
        if isinstance(servers, dict):
            for server_name, config in servers.items():
                config = config if isinstance(config, dict) else {}
                transport = "stdio" if config.get("command") else "http" if config.get("url") else None
                permissions = _string_list(config.get("permissions") or config.get("capabilities"))
                self.surface.mcp_capabilities.append(McpCapability(
                    name=str(server_name), capability_type="server", server=str(server_name),
                    description=str(config.get("description", "")), file_path=file_path,
                    line_start=_line_for_token(content, str(server_name)),
                    line_end=_line_for_token(content, str(server_name)), registration="configuration",
                    transport=transport, permissions=permissions,
                    authorization="enforced" if any(key in config for key in ("auth", "authentication", "headers")) else "unknown",
                ))

    def _extract_openapi(self, file_path: str, content: str, payload: Dict[str, Any]) -> None:
        root_security = payload.get("security")
        for route_path, path_item in payload["paths"].items():
            if not isinstance(route_path, str) or not isinstance(path_item, dict):
                continue
            path_parameters = _openapi_parameters(path_item.get("parameters"))
            for method, operation in path_item.items():
                if str(method).lower() not in _OPENAPI_HTTP_METHODS or not isinstance(operation, dict):
                    continue
                operation_id = str(operation.get("operationId") or "")
                handler_function, handler_path, handler_line = self._openapi_handler_target(
                    operation_id, file_path
                )
                line_start = _line_for_token(content, operation_id or route_path)
                security = operation.get("security", root_security)
                parameters = path_parameters + _openapi_parameters(operation.get("parameters"))
                declared_public = "security" in operation and operation.get("security") == []
                self.surface.page_entries.append(PageEntry(
                    path=route_path,
                    method=str(method).upper(),
                    entry_type=EntryType.API_ENDPOINT,
                    file_path=handler_path,
                    line_start=handler_line,
                    line_end=handler_line,
                    handler_function=handler_function,
                    parameters=parameters,
                    authentication_required=bool(security),
                    authentication_state=(
                        "declared_public" if declared_public else "declared" if security else "unknown"
                    ),
                    description=(
                        f"OpenAPI operation {operation_id} declared in {file_path}:{line_start}"
                        if operation_id
                        else f"OpenAPI operation declared in {file_path}:{line_start}"
                    ),
                ))
                for parameter in parameters:
                    location = str(parameter.get("in") or "request")
                    name = str(parameter.get("name") or "value")
                    self.surface.external_content_inputs.append(ExternalContentInput(
                        name=f"request.{location}.{name}",
                        source_type="http_request",
                        expression=f"OpenAPI {location} parameter {name}",
                        file_path=handler_path,
                        line_start=handler_line,
                        line_end=handler_line,
                        target_refs=[handler_function] if handler_function else [],
                    ))
                if isinstance(operation.get("requestBody"), dict):
                    self.surface.external_content_inputs.append(ExternalContentInput(
                        name="request.body",
                        source_type="http_request",
                        expression="OpenAPI request body",
                        file_path=handler_path,
                        line_start=handler_line,
                        line_end=handler_line,
                        target_refs=[handler_function] if handler_function else [],
                    ))

    def _openapi_handler_target(self, operation_id: str, config_path: str) -> tuple[Optional[str], str, int]:
        if not operation_id:
            return None, config_path, 1
        module, separator, function_name = operation_id.rpartition(".")
        handler_function = function_name if separator else operation_id
        if not separator:
            return handler_function, config_path, _line_for_token("", handler_function)
        candidate = Path(*module.split(".")).with_suffix(".py")
        project_root = Path(self.project_path)
        if not (project_root / candidate).is_file():
            return handler_function, config_path, 1
        handler_path = candidate.as_posix()
        for block in self.surface.code_blocks:
            if block.file_path == handler_path and block.name == handler_function:
                return handler_function, handler_path, block.line_start
        return handler_function, handler_path, 1

    def _extract_workflow(self, file_path: str, content: str, payload: Dict[str, Any]) -> None:
        workflow_name = str(payload.get("name") or Path(file_path).stem)
        triggers = payload.get("on", payload.get(True, "unknown"))
        trigger_text = ",".join(triggers) if isinstance(triggers, list) else str(triggers)
        workflow_permissions = payload.get("permissions") if isinstance(payload.get("permissions"), dict) else {}
        for job_name, job in payload["jobs"].items():
            if not isinstance(job, dict):
                continue
            job_permissions = job.get("permissions") if isinstance(job.get("permissions"), dict) else workflow_permissions
            job_line = _line_for_token(content, str(job_name))
            self.surface.workflow_nodes.append(WorkflowNode(
                workflow_name=workflow_name, node_name=str(job_name), node_type="job",
                file_path=file_path, line_start=job_line, line_end=job_line,
                trigger=trigger_text, capabilities=_workflow_capabilities(job),
                untrusted_inputs=_untrusted_workflow_inputs(json.dumps(job, default=str)),
                permissions=dict(job_permissions),
            ))
            for index, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    continue
                step_name = str(step.get("name") or step.get("id") or step.get("uses") or f"step-{index}")
                step_text = json.dumps(step, default=str)
                step_line = _line_for_token(content, str(step.get("name") or step.get("uses") or step.get("run", ""))[:80])
                self.surface.workflow_nodes.append(WorkflowNode(
                    workflow_name=workflow_name, node_name=f"{job_name}/{step_name}", node_type="step",
                    file_path=file_path, line_start=step_line, line_end=step_line,
                    trigger=trigger_text, capabilities=_workflow_capabilities(step),
                    untrusted_inputs=_untrusted_workflow_inputs(step_text),
                    permissions=dict(job_permissions),
                ))

    def _infer_trust_boundaries(self) -> None:
        for entry in self.surface.page_entries:
            self.surface.trust_boundaries.append(TrustBoundaryDefinition(
                boundary_type=TrustBoundary.AUTHENTICATION,
                description=f"External request enters {entry.method} {entry.path}",
                source="external_user", target=f"entry:{entry.method}:{entry.path}",
                file_path=entry.file_path, line_start=entry.line_start,
                validation_mechanism="authentication_check" if entry.authentication_required else None,
            ))
        for capability in self.surface.mcp_capabilities:
            self.surface.trust_boundaries.append(TrustBoundaryDefinition(
                boundary_type=TrustBoundary.AUTHORIZATION,
                description=f"MCP {capability.capability_type} authorization boundary",
                source=f"mcp:{capability.server}", target=f"mcp:{capability.name}",
                file_path=capability.file_path, line_start=capability.line_start,
                validation_mechanism="local_policy_or_approval" if capability.authorization == "enforced" else None,
            ))
        for workflow in self.surface.workflow_nodes:
            if workflow.node_type == "job":
                self.surface.trust_boundaries.append(TrustBoundaryDefinition(
                    boundary_type=TrustBoundary.PROCESS,
                    description=f"Workflow trigger enters job {workflow.node_name}",
                    source=f"workflow_trigger:{workflow.trigger}", target=f"workflow:{workflow.node_name}",
                    file_path=workflow.file_path, line_start=workflow.line_start,
                    validation_mechanism=None if workflow.untrusted_inputs else "workflow_expression_boundary",
                ))

    def _deduplicate(self) -> None:
        collections = (
            "page_entries", "prompt_configs", "model_invocations", "tool_profiles", "mcp_capabilities",
            "permission_profiles", "browser_sinks", "storage_assets", "external_content_inputs",
            "workflow_nodes", "trust_boundaries", "code_blocks",
        )
        for name in collections:
            values = getattr(self.surface, name)
            seen = set()
            unique = []
            for value in values:
                payload = value.to_dict()
                key = json.dumps(payload, sort_keys=True, default=str)
                if key not in seen:
                    seen.add(key)
                    unique.append(value)
            setattr(self.surface, name, unique)


def _python_name(node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_name(node.value)
        return f"{prefix}.{node.attr}".strip(".")
    if isinstance(node, ast.Subscript):
        return _python_name(node.value)
    return ""


def _python_literal(node: Optional[ast.AST]) -> str:
    return str(node.value) if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


def _python_source(node: ast.AST, content: str) -> str:
    return ast.get_source_segment(content, node) or ""


def _python_route_method(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return "GET"
    for keyword in node.keywords:
        if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
            methods = [_python_literal(item).upper() for item in keyword.value.elts if _python_literal(item)]
            return ",".join(methods) or "GET"
    return "GET"


def _openapi_parameters(value: Any) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        return []
    parameters = []
    for item in value:
        if not isinstance(item, dict) or "$ref" in item:
            continue
        name = item.get("name")
        location = item.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            continue
        parameter = {
            "name": name,
            "in": location,
            "required": bool(item.get("required")),
        }
        if isinstance(item.get("schema"), dict):
            parameter["schema"] = dict(item["schema"])
        elif "type" in item:
            parameter["type"] = item["type"]
        parameters.append(parameter)
    return parameters


def _python_external_source(name: str) -> Optional[str]:
    lowered = name.lower()
    if lowered.startswith(("request.args", "request.form", "request.json", "request.files", "request.body", "request.query_params")):
        return "http_request"
    if lowered.startswith(("os.environ", "sys.argv", "input")):
        return "process_input"
    if lowered.endswith((".recv", ".receive", ".read_message")):
        return "message"
    if lowered.startswith(("requests.get", "requests.post", "httpx.get", "httpx.post")):
        return "network_response"
    return None


def _python_storage(name: str, node: ast.Call) -> Optional[tuple[str, str, str]]:
    lowered = name.lower()
    if lowered in {"open", "path.open", "path.write_text", "path.read_text", "path.write_bytes", "path.read_bytes"}:
        first = _python_literal(node.args[0]) if node.args else "dynamic_file"
        operation = "write" if "write" in lowered or any(_python_literal(arg).startswith(("w", "a")) for arg in node.args[1:2]) else "read"
        return "file", operation, first or "dynamic_file"
    if lowered.endswith((".execute", ".executemany", ".query", ".find", ".save")):
        first = _python_literal(node.args[0]) if node.args else "dynamic_query"
        operation = "write" if re.search(r"(?i)\b(insert|update|delete|drop|create)\b", first) else "read"
        return "database", operation, _sql_asset_name(first)
    return None


def _walk_ts(node: Any) -> Iterable[Any]:
    if node is None:
        return
    # Source repositories can contain deeply nested generated TypeScript.  An
    # explicit stack keeps traversal bounded by heap memory instead of Python's
    # recursion depth and preserves the original preorder traversal.
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        children = current.children
        pending.extend(reversed(children))


def _ts_text(source: bytes, node: Any) -> str:
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _ts_string(source: bytes, node: Any) -> str:
    if node is None or node.type not in {"string", "template_string"}:
        return ""
    raw = _ts_text(source, node)
    return raw[1:-1] if len(raw) >= 2 and raw[0] in {'"', "'", "`"} else raw


def _ts_expression_name(source: bytes, node: Any) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier", "this", "super"}:
        return _ts_text(source, node)
    if node.type in {"member_expression", "subscript_expression"}:
        obj = node.child_by_field_name("object")
        prop = node.child_by_field_name("property") or node.child_by_field_name("index")
        return f"{_ts_expression_name(source, obj)}.{_ts_expression_name(source, prop)}".strip(".")
    return _ts_text(source, node)


def _ts_function_name(source: bytes, node: Any) -> str:
    if node is None:
        return ""
    name = node.child_by_field_name("name")
    if name is not None:
        return _ts_text(source, name)
    parent = node.parent
    if parent is not None and parent.type == "variable_declarator":
        return _ts_text(source, parent.child_by_field_name("name"))
    if parent is not None and parent.type in {"pair", "method_definition"}:
        return _ts_text(source, parent.child_by_field_name("name") or parent.child_by_field_name("key"))
    return ""


def _ts_calls(source: bytes, node: Any) -> List[str]:
    if node is None:
        return []
    return [
        _ts_expression_name(source, child.child_by_field_name("function"))
        for child in _walk_ts(node) if child.type == "call_expression"
    ]


def _ts_property_string(source: bytes, nodes: Iterable[Any], name: str) -> str:
    for root in nodes:
        for node in _walk_ts(root):
            if node.type not in {"pair", "property_signature"}:
                continue
            key = _ts_text(source, node.child_by_field_name("key")).strip("'\"")
            if key == name:
                return _ts_string(source, node.child_by_field_name("value"))
    return ""


def _javascript_external_source(expression: str) -> Optional[str]:
    lowered = expression.lower()
    if lowered.startswith(("req.body", "req.query", "req.params", "request.body", "request.formdata")):
        return "http_request"
    if lowered.startswith(("event.data", "message.data", "window.location", "document.location", "document.cookie")):
        return "browser_or_message"
    if lowered in {"fetch", "response.json", "response.text"} or lowered.endswith((".json", ".text", ".formdata")):
        return "network_response"
    return None


def _javascript_storage(name: str, args: List[Any], source: bytes) -> Optional[tuple[str, str, str]]:
    lowered = name.lower()
    if lowered.startswith(("localstorage.", "sessionstorage.")):
        storage_type = "local_storage" if lowered.startswith("localstorage") else "session_storage"
        operation = "write" if lowered.endswith((".setitem", ".removeitem", ".clear")) else "read"
        asset_name = _ts_string(source, args[0]) if args else "dynamic_key"
        return storage_type, operation, asset_name or "dynamic_key"
    if lowered.startswith("indexeddb."):
        asset_name = _ts_string(source, args[0]) if args else "dynamic_database"
        return "indexed_db", "open", asset_name or "dynamic_database"
    if lowered.startswith("document.cookie"):
        return "cookie", "write", "document.cookie"
    return None


def _dangerous_names(names: Iterable[str]) -> List[str]:
    return sorted({
        name for name in names if any(marker in name.lower().replace("_", "") for marker in _DANGEROUS_OPERATIONS)
    })


def _risk_level(operations: List[str]) -> str:
    if any(any(marker in operation.lower() for marker in ("eval", "exec", "system", "spawn", "drop", "rmtree")) for operation in operations):
        return "critical"
    if operations:
        return "high"
    return "low"


def _has_approval_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _APPROVAL_MARKERS)


def _contains_any(value: str, markers: Iterable[str]) -> bool:
    return any(marker in value for marker in markers)


def _prompt_refs(text: str) -> List[str]:
    return sorted(set(re.findall(r"\b[A-Za-z_$][\w$]*(?:prompt|message|instruction)[\w$]*\b", text, re.IGNORECASE)))[:20]


def _identifier_refs(text: str) -> List[str]:
    ignored = {"innerHTML", "outerHTML", "srcdoc", "document", "window", "sanitize", "DOMPurify"}
    return sorted({item for item in re.findall(r"\b[A-Za-z_$][\w$]*\b", text) if item not in ignored})[:20]


def _is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _SENSITIVE_NAME_MARKERS)


def _sql_asset_name(query: str) -> str:
    match = re.search(r"(?i)\b(?:from|into|update|table)\s+([A-Za-z_][\w.]*)", query)
    return match.group(1) if match else "dynamic_query"


def _is_workflow_path(file_path: str) -> bool:
    normalized = f"/{file_path.replace(chr(92), '/').lower()}"
    return "/.github/workflows/" in normalized


def _workflow_capabilities(value: Dict[str, Any]) -> List[str]:
    text = json.dumps(value, default=str).lower()
    capabilities = []
    checks = {
        "code_execution": ("run", "shell", "script"),
        "network": ("curl", "wget", "http://", "https://", "uses"),
        "file_write": (">", "write", "upload-artifact", "download-artifact"),
        "credentials": ("secrets.", "token", "credential"),
        "deployment": ("deploy", "kubectl", "terraform", "aws ", "gcloud"),
    }
    for capability, markers in checks.items():
        if any(marker in text for marker in markers):
            capabilities.append(capability)
    return capabilities


def _untrusted_workflow_inputs(text: str) -> List[str]:
    pattern = re.compile(r"\$\{\{\s*github\.(?:head_ref|event\.[^}\s]+)[^}]*}}", re.IGNORECASE)
    return sorted(set(match.group(0) for match in pattern.finditer(text)))


def _line_for_token(content: str, token: str) -> int:
    if not token:
        return 1
    index = content.find(token)
    return content[: max(index, 0)].count("\n") + 1


def _string_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        return [f"{key}:{nested}" for key, nested in value.items()]
    return []
