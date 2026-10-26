"""Structured MCP and workflow analysis shared by discovery and verification."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    import esprima
except ImportError:  # pragma: no cover - dependency is declared, but failures stay explicit.
    esprima = None

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover - dependency is declared, but failures stay explicit.
    get_parser = None

from ..languages.tree_sitter_gateway import parser_for

try:
    import yaml
except ImportError:  # pragma: no cover - dependency is declared, but failures stay explicit.
    yaml = None


_APPROVAL_MARKERS = ("approval", "approve", "confirm", "authorize", "permission", "policy")
_DANGEROUS_CALLS = {
    "eval", "exec", "os.system", "os.remove", "os.unlink", "shutil.rmtree",
    "subprocess.call", "subprocess.Popen", "subprocess.run", "Path.unlink",
}
_SENSITIVE_RESOURCE_CALLS = {
    "open", "Path.open", "Path.read_text", "Path.read_bytes",
    "sqlite3.connect", "cursor.execute", "connection.execute",
}
_DANGEROUS_JAVASCRIPT_CALLS = {
    "eval", "Function", "exec", "execSync", "spawn", "spawnSync",
    "child_process.exec", "child_process.execSync", "child_process.spawn",
    "child_process.spawnSync", "fs.rm", "fs.rmSync", "fs.unlink", "fs.unlinkSync",
    "fs.writeFile", "fs.writeFileSync",
}
_SENSITIVE_JAVASCRIPT_RESOURCE_CALLS = {
    "fs.readFile", "fs.readFileSync", "fs.createReadStream",
    "readFile", "readFileSync", "createReadStream",
    "db.query", "db.execute", "collection.find", "collection.findOne",
}
_DESCRIPTION_INJECTION = re.compile(
    r"(?i)(?:ignore|disregard)\s+(?:all\s+)?(?:(?:previous|prior)(?:\s+system)?|system)\s+instructions?|"
    r"override\s+(?:the\s+)?(?:system|developer|tool)\s+instructions?",
)
_UNTRUSTED_GITHUB_EXPRESSION = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.(?:issue|pull_request|comment|review|discussion|"
    r"head_commit|commits))\b[^}]*}}",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProtocolSignal:
    vulnerability_type: str
    file_path: str
    line_start: int
    line_end: int
    description: str
    predicate: str
    confidence: float
    statically_confirmable: bool
    analyzer: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_evidence(self) -> Dict[str, Any]:
        return {
            "type": "protocol_signal",
            "analyzer": self.analyzer,
            "predicate": self.predicate,
            "statically_confirmable": self.statically_confirmable,
            "details": self.details,
            "line": self.line_start,
        }


def analyze_protocol_file(project_root: str, file_path: str) -> List[ProtocolSignal]:
    root = Path(project_root).resolve()
    target = (root / file_path).resolve()
    target.relative_to(root)
    if not target.is_file():
        return []
    relative = target.relative_to(root).as_posix()
    content = target.read_text(encoding="utf-8", errors="ignore")
    signals: List[ProtocolSignal] = []
    if target.suffix.lower() == ".py":
        signals.extend(_analyze_mcp_python(relative, content))
    if target.suffix.lower() in {".js", ".jsx", ".mjs", ".cjs"}:
        signals.extend(_analyze_mcp_javascript(relative, content))
    if target.suffix.lower() in {".ts", ".tsx", ".mts", ".cts"}:
        signals.extend(_analyze_mcp_typescript(relative, content))
    if target.suffix.lower() in {".json", ".yaml", ".yml"}:
        signals.extend(_analyze_mcp_config(relative, content, target.suffix.lower()))
    if _is_github_workflow(relative, target.suffix.lower()):
        signals.extend(_analyze_github_workflow(relative, content))
    return signals


def iter_protocol_signals(project_root: str, *, lane: str) -> Iterable[ProtocolSignal]:
    root = Path(project_root).resolve()
    for target in root.rglob("*"):
        if not target.is_file() or any(
            part in {".git", "node_modules", "__pycache__", "venv", ".venv"}
            for part in target.relative_to(root).parts
        ):
            continue
        relative = target.relative_to(root).as_posix()
        suffix = target.suffix.lower()
        if lane == "mcp_audit" and suffix not in {
            ".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
            ".json", ".yaml", ".yml",
        }:
            continue
        if lane == "workflow_audit" and not _is_github_workflow(relative, suffix):
            continue
        try:
            for signal in analyze_protocol_file(str(root), relative):
                if lane == "mcp_audit" and signal.vulnerability_type == "mcp_insecurity":
                    yield signal
                elif lane == "workflow_audit" and signal.vulnerability_type == "workflow_insecurity":
                    yield signal
        except (OSError, ValueError, SyntaxError, json.JSONDecodeError):
            continue


def find_matching_protocol_signal(
    project_root: str,
    finding: Dict[str, Any],
) -> Optional[ProtocolSignal]:
    file_path = str(finding.get("file_path", ""))
    vulnerability_type = str(finding.get("vulnerability_type", "")).lower()
    line_start = int(finding.get("line_start", 0) or 0)
    matches = [
        signal for signal in analyze_protocol_file(project_root, file_path)
        if signal.vulnerability_type == vulnerability_type
    ]
    if not matches:
        return None
    best = min(matches, key=lambda signal: abs(signal.line_start - line_start))
    line_end = int(finding.get("line_end", line_start) or line_start)
    if line_start > 0 and not (line_start <= best.line_end + 5 and best.line_start <= line_end + 5):
        return None
    return best


def _analyze_mcp_python(file_path: str, content: str) -> List[ProtocolSignal]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    signals: List[ProtocolSignal] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = [_call_name(item.func if isinstance(item, ast.Call) else item) for item in node.decorator_list]
        registration_kind = next((
            "resource" if "resource" in name.rsplit(".", 1)[-1] else "tool"
            for name in decorators
            if name.rsplit(".", 1)[-1] in {"tool", "mcp_tool", "resource", "mcp_resource"}
        ), None)
        if registration_kind is None:
            continue
        consequential_calls = _DANGEROUS_CALLS | (
            _SENSITIVE_RESOURCE_CALLS if registration_kind == "resource" else set()
        )
        calls = sorted({
            name for child in ast.walk(node)
            if isinstance(child, ast.Call)
            for name in [_call_name(child.func)]
            if name in consequential_calls or name.rsplit(".", 1)[-1] in consequential_calls
        })
        names = {_call_name(child) for child in ast.walk(node) if isinstance(child, (ast.Name, ast.Attribute))}
        has_approval = any(marker in name.lower() for marker in _APPROVAL_MARKERS for name in names)
        if calls and not has_approval:
            signals.append(ProtocolSignal(
                vulnerability_type="mcp_insecurity",
                file_path=file_path,
                line_start=int(node.lineno),
                line_end=int(getattr(node, "end_lineno", node.lineno)),
                description=f"MCP {registration_kind} reaches a consequential operation without a local approval or policy gate.",
                predicate=f"The decorated MCP {registration_kind} contains a consequential call and no local approval/policy guard",
                confidence=0.82,
                statically_confirmable=False,
                analyzer="mcp_python_ast",
                details={
                    "capability_name": node.name,
                    "capability_type": registration_kind,
                    "dangerous_calls": calls,
                    "approval_guard_found": False,
                },
            ))

        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            if call is None:
                continue
            for keyword in call.keywords:
                if keyword.arg == "description" and isinstance(keyword.value, ast.Constant):
                    description = str(keyword.value.value)
                    match = _DESCRIPTION_INJECTION.search(description)
                    if match:
                        signals.append(ProtocolSignal(
                            vulnerability_type="mcp_insecurity",
                            file_path=file_path,
                            line_start=int(getattr(decorator, "lineno", node.lineno)),
                            line_end=int(getattr(decorator, "end_lineno", node.lineno)),
                            description="MCP tool description contains an instruction-override directive.",
                            predicate="A local MCP tool description contains a direct instruction-override directive",
                            confidence=0.95,
                            statically_confirmable=True,
                            analyzer="mcp_python_ast",
                            details={"tool_name": node.name, "matched_directive": match.group(0)},
                        ))
    return signals


def _analyze_mcp_javascript(file_path: str, content: str) -> List[ProtocolSignal]:
    if esprima is None or not _looks_like_mcp_javascript(content):
        return []
    try:
        tree = esprima.parseModule(content, {"loc": True, "tolerant": True, "jsx": True}).toDict()
    except Exception:
        return []
    signals: List[ProtocolSignal] = []
    registration_names = {"tool", "registerTool", "resource", "registerResource"}
    for node in _walk_javascript_nodes(tree):
        if node.get("type") != "CallExpression":
            continue
        registration = _javascript_expression_name(node.get("callee") or {})
        registration_kind = registration.rsplit(".", 1)[-1]
        if registration_kind not in registration_names:
            continue
        arguments = list(node.get("arguments", []) or [])
        tool_name = _javascript_literal(arguments[0]) if arguments else ""
        descriptions = [
            value for argument in arguments for value in _javascript_property_literals(argument, "description")
        ]
        line_start, line_end = _javascript_lines(node)
        dynamic_registration = not bool(tool_name)
        for description in descriptions:
            match = _DESCRIPTION_INJECTION.search(description)
            if not match:
                continue
            signals.append(ProtocolSignal(
                vulnerability_type="mcp_insecurity",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                description="MCP JavaScript registration contains an instruction-override directive.",
                predicate="A parsed MCP SDK registration description contains a direct instruction-override directive",
                confidence=0.95,
                statically_confirmable=True,
                analyzer="mcp_javascript_ast",
                details={
                    "tool_name": tool_name or None,
                    "registration": registration,
                    "matched_directive": match.group(0),
                    "dynamic_registration": not bool(tool_name),
                },
            ))

        handlers = [
            argument for argument in arguments
            if isinstance(argument, dict) and argument.get("type") in {
                "FunctionExpression", "ArrowFunctionExpression",
            }
        ]
        for handler in handlers[-1:]:
            consequential_calls = _DANGEROUS_JAVASCRIPT_CALLS | (
                _SENSITIVE_JAVASCRIPT_RESOURCE_CALLS
                if registration_kind in {"resource", "registerResource"}
                else set()
            )
            dangerous_calls = sorted({
                name
                for child in _walk_javascript_nodes(handler.get("body") or {})
                if child.get("type") in {"CallExpression", "NewExpression"}
                for name in [_javascript_expression_name(child.get("callee") or {})]
                if name in consequential_calls
                or name.rsplit(".", 1)[-1] in consequential_calls
            })
            names = {
                _javascript_expression_name(child)
                for child in _walk_javascript_nodes(handler)
                if child.get("type") in {"Identifier", "MemberExpression"}
            }
            has_approval = any(marker in name.lower() for marker in _APPROVAL_MARKERS for name in names)
            if dangerous_calls and not has_approval:
                signals.append(ProtocolSignal(
                    vulnerability_type="mcp_insecurity",
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    description="MCP JavaScript tool reaches a consequential operation without a local approval or policy gate.",
                    predicate="The parsed MCP SDK handler contains a consequential call and no local approval/policy guard",
                    confidence=0.82,
                    statically_confirmable=False,
                    analyzer="mcp_javascript_ast",
                    details={
                        "tool_name": tool_name or None,
                        "registration": registration,
                        "dangerous_calls": dangerous_calls,
                        "approval_guard_found": False,
                        "dynamic_registration": not bool(tool_name),
                    },
                ))
        if dynamic_registration and not handlers:
            signals.append(ProtocolSignal(
                vulnerability_type="mcp_insecurity",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                description="MCP capability is registered without a statically resolvable identity or handler boundary.",
                predicate="A parsed MCP SDK registration has no static capability identity and no local handler available for authorization analysis",
                confidence=0.55,
                statically_confirmable=False,
                analyzer="mcp_javascript_ast",
                details={
                    "registration": registration,
                    "dynamic_registration": True,
                    "authorization_scope": "unresolved",
                },
            ))
    return signals


def _analyze_mcp_typescript(file_path: str, content: str) -> List[ProtocolSignal]:
    if get_parser is None or not _looks_like_mcp_javascript(content):
        return []
    source = content.encode("utf-8", errors="replace")
    parser_name = "tsx" if Path(file_path).suffix.lower() == ".tsx" else "typescript"
    parser = parser_for(parser_name)
    if parser is None:
        # 解析器未缓存且下载被阻断时降级，不击穿 MCP 审计通道。
        return []
    tree = parser.parse(source)
    registration_names = {"tool", "registerTool", "resource", "registerResource"}
    signals: List[ProtocolSignal] = []
    for node in _walk_tree_sitter_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
        registration = _tree_sitter_expression_name(source, node.child_by_field_name("function"))
        registration_kind = registration.rsplit(".", 1)[-1]
        if registration_kind not in registration_names:
            continue
        arguments_node = node.child_by_field_name("arguments")
        arguments = list(arguments_node.named_children) if arguments_node is not None else []
        tool_name = _tree_sitter_string(source, arguments[0]) if arguments else ""
        line_start = int(node.start_point.row) + 1
        line_end = int(node.end_point.row) + 1
        dynamic_registration = not bool(tool_name)
        descriptions = [
            value for argument in arguments
            for value in _tree_sitter_property_strings(source, argument, "description")
        ]
        for description in descriptions:
            match = _DESCRIPTION_INJECTION.search(description)
            if match:
                signals.append(ProtocolSignal(
                    vulnerability_type="mcp_insecurity",
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    description="MCP TypeScript registration contains an instruction-override directive.",
                    predicate="A parsed TypeScript MCP SDK registration description contains a direct instruction-override directive",
                    confidence=0.95,
                    statically_confirmable=True,
                    analyzer="mcp_typescript_ast",
                    details={
                        "tool_name": tool_name or None,
                        "registration": registration,
                        "matched_directive": match.group(0),
                        "dynamic_registration": not bool(tool_name),
                    },
                ))
        handlers = [
            argument for argument in arguments
            if argument.type in {"arrow_function", "function_expression"}
        ]
        for handler in handlers[-1:]:
            consequential_calls = _DANGEROUS_JAVASCRIPT_CALLS | (
                _SENSITIVE_JAVASCRIPT_RESOURCE_CALLS
                if registration_kind in {"resource", "registerResource"}
                else set()
            )
            dangerous_calls = sorted({
                name
                for child in _walk_tree_sitter_nodes(handler)
                if child.type in {"call_expression", "new_expression"}
                for name in [_tree_sitter_expression_name(
                    source,
                    child.child_by_field_name("function") or child.child_by_field_name("constructor"),
                )]
                if name in consequential_calls
                or name.rsplit(".", 1)[-1] in consequential_calls
            })
            names = {
                _tree_sitter_expression_name(source, child)
                for child in _walk_tree_sitter_nodes(handler)
                if child.type in {"identifier", "property_identifier", "member_expression"}
            }
            has_approval = any(marker in name.lower() for marker in _APPROVAL_MARKERS for name in names)
            if dangerous_calls and not has_approval:
                signals.append(ProtocolSignal(
                    vulnerability_type="mcp_insecurity",
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    description="MCP TypeScript tool reaches a consequential operation without a local approval or policy gate.",
                    predicate="The parsed TypeScript MCP SDK handler contains a consequential call and no local approval/policy guard",
                    confidence=0.82,
                    statically_confirmable=False,
                    analyzer="mcp_typescript_ast",
                    details={
                        "tool_name": tool_name or None,
                        "registration": registration,
                        "dangerous_calls": dangerous_calls,
                        "approval_guard_found": False,
                        "dynamic_registration": not bool(tool_name),
                    },
                ))
        if dynamic_registration and not handlers:
            signals.append(ProtocolSignal(
                vulnerability_type="mcp_insecurity",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                description="MCP TypeScript capability is registered without a statically resolvable identity or handler boundary.",
                predicate="A parsed TypeScript MCP SDK registration has no static capability identity and no local handler available for authorization analysis",
                confidence=0.55,
                statically_confirmable=False,
                analyzer="mcp_typescript_ast",
                details={
                    "registration": registration,
                    "dynamic_registration": True,
                    "authorization_scope": "unresolved",
                },
            ))
    return signals


def _analyze_mcp_config(file_path: str, content: str, suffix: str) -> List[ProtocolSignal]:
    if not _looks_like_mcp_config(file_path, content):
        return []
    try:
        payload = json.loads(content) if suffix == ".json" else _load_yaml(content)
    except (ValueError, json.JSONDecodeError):
        return []
    signals: List[ProtocolSignal] = []
    if isinstance(payload, dict):
        servers = payload.get("mcpServers") or payload.get("mcp_servers")
        if isinstance(servers, dict):
            for server_name, raw_config in servers.items():
                config = raw_config if isinstance(raw_config, dict) else {}
                url = config.get("url")
                has_transport_auth = any(
                    key in config for key in ("auth", "authentication", "authorization", "headers", "token")
                )
                if isinstance(url, str) and url.startswith(("http://", "https://")) and not has_transport_auth:
                    line = _line_for_token(content, url)
                    signals.append(ProtocolSignal(
                        vulnerability_type="mcp_insecurity",
                        file_path=file_path,
                        line_start=line,
                        line_end=line,
                        description="Remote MCP transport has no explicit authentication or identity configuration.",
                        predicate="A parsed remote MCP server URL has no adjacent authentication, authorization, header, or token configuration",
                        confidence=0.72,
                        statically_confirmable=False,
                        analyzer="mcp_config",
                        details={
                            "server_name": str(server_name),
                            "transport": "http",
                            "url_scheme": url.split(":", 1)[0],
                            "transport_auth_found": False,
                        },
                    ))
    for key_path, key, value in _walk_mapping(payload):
        lowered = str(key).lower()
        if lowered in {"permissions", "permission", "access", "capabilities", "allowed_tools"} and _is_wildcard(value):
            line = _line_for_token(content, str(key))
            signals.append(ProtocolSignal(
                vulnerability_type="mcp_insecurity",
                file_path=file_path,
                line_start=line,
                line_end=line,
                description="MCP configuration grants wildcard capability or access.",
                predicate="The parsed MCP configuration contains a wildcard permission/capability grant",
                confidence=0.95,
                statically_confirmable=True,
                analyzer="mcp_config",
                details={"config_path": ".".join(key_path), "field": str(key), "value": value},
            ))
        if lowered == "description" and isinstance(value, str):
            match = _DESCRIPTION_INJECTION.search(value)
            if match:
                line = _line_for_token(content, match.group(0))
                signals.append(ProtocolSignal(
                    vulnerability_type="mcp_insecurity",
                    file_path=file_path,
                    line_start=line,
                    line_end=line,
                    description="MCP description contains an instruction-override directive.",
                    predicate="The parsed MCP description contains a direct instruction-override directive",
                    confidence=0.95,
                    statically_confirmable=True,
                    analyzer="mcp_config",
                    details={"config_path": ".".join(key_path), "matched_directive": match.group(0)},
                ))
    return signals


def _analyze_github_workflow(file_path: str, content: str) -> List[ProtocolSignal]:
    try:
        payload = _load_yaml(content)
    except ValueError:
        return []
    if not isinstance(payload, dict) or not isinstance(payload.get("jobs"), dict):
        return []
    signals: List[ProtocolSignal] = []
    for job_name, job in payload["jobs"].items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        for index, step in enumerate(job["steps"]):
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            run = step["run"]
            match = _UNTRUSTED_GITHUB_EXPRESSION.search(run)
            if not match:
                continue
            line = _line_for_token(content, match.group(0))
            signals.append(ProtocolSignal(
                vulnerability_type="workflow_insecurity",
                file_path=file_path,
                line_start=line,
                line_end=line + run.count("\n"),
                description="Untrusted GitHub event data is directly interpolated into a shell run step.",
                predicate="Parsed GitHub Actions run step directly interpolates an attacker-controlled event expression",
                confidence=0.95,
                statically_confirmable=True,
                analyzer="github_actions_yaml",
                details={"job": str(job_name), "step_index": index, "expression": match.group(0)},
            ))
    return signals


def _load_yaml(content: str) -> Any:
    if yaml is None:
        raise ValueError("PyYAML is unavailable")
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML: {exc}") from exc


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _walk_mapping(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str, Any]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            current = (*path, str(key))
            yield current, str(key), nested
            yield from _walk_mapping(nested, current)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_mapping(nested, (*path, str(index)))


def _is_wildcard(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip() == "*"
    if isinstance(value, list):
        return any(str(item).strip() == "*" for item in value)
    return False


def _looks_like_mcp_config(file_path: str, content: str) -> bool:
    lowered = f"{file_path}\n{content[:5000]}".lower()
    return any(marker in lowered for marker in ("mcpservers", "mcp_servers", "mcp", '"tools"', "tools:"))


def _is_github_workflow(file_path: str, suffix: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    return suffix in {".yaml", ".yml"} and "/.github/workflows/" in f"/{normalized}"


def _line_for_token(content: str, token: str) -> int:
    index = content.lower().find(token.lower())
    return content[:max(0, index)].count("\n") + 1


def _looks_like_mcp_javascript(content: str) -> bool:
    lowered = content[:100_000].lower()
    return any(marker in lowered for marker in (
        "@modelcontextprotocol/", "mcpserver", "mcp.server", ".registertool(",
        ".registerresource(", "fastmcp",
    ))


def _walk_javascript_nodes(value: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(value, dict):
        if value.get("type"):
            yield value
        for key, nested in value.items():
            if key != "loc":
                yield from _walk_javascript_nodes(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_javascript_nodes(nested)


def _javascript_expression_name(node: Dict[str, Any]) -> str:
    node_type = node.get("type")
    if node_type == "Identifier":
        return str(node.get("name", ""))
    if node_type == "Literal":
        return str(node.get("value", ""))
    if node_type == "MemberExpression":
        prefix = _javascript_expression_name(node.get("object") or {})
        suffix = _javascript_expression_name(node.get("property") or {})
        return f"{prefix}.{suffix}".strip(".")
    return ""


def _javascript_literal(node: Any) -> str:
    if not isinstance(node, dict):
        return ""
    if node.get("type") == "Literal" and isinstance(node.get("value"), str):
        return str(node["value"])
    return ""


def _javascript_property_literals(node: Any, property_name: str) -> List[str]:
    values = []
    if isinstance(node, list):
        for nested in node:
            values.extend(_javascript_property_literals(nested, property_name))
        return values
    if not isinstance(node, dict):
        return values
    if node.get("type") == "Property":
        key = _javascript_expression_name(node.get("key") or {})
        value = _javascript_literal(node.get("value") or {})
        if key == property_name and value:
            values.append(value)
    for key, nested in node.items():
        if key != "loc":
            values.extend(_javascript_property_literals(nested, property_name))
    return values


def _javascript_lines(node: Dict[str, Any]) -> tuple[int, int]:
    location = dict(node.get("loc", {}) or {})
    start = int(dict(location.get("start", {}) or {}).get("line", 1) or 1)
    end = int(dict(location.get("end", {}) or {}).get("line", start) or start)
    return start, end


def _walk_tree_sitter_nodes(node: Any) -> Iterable[Any]:
    if node is None:
        return
    yield node
    for child in node.children:
        yield from _walk_tree_sitter_nodes(child)


def _tree_sitter_text(content: bytes, node: Any) -> str:
    if node is None:
        return ""
    return content[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _tree_sitter_expression_name(content: bytes, node: Any) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier", "this", "super"}:
        return _tree_sitter_text(content, node)
    if node.type == "member_expression":
        prefix = _tree_sitter_expression_name(content, node.child_by_field_name("object"))
        suffix = _tree_sitter_expression_name(content, node.child_by_field_name("property"))
        return f"{prefix}.{suffix}".strip(".")
    return _tree_sitter_text(content, node)


def _tree_sitter_string(content: bytes, node: Any) -> str:
    if node is None or node.type not in {"string", "template_string"}:
        return ""
    raw = _tree_sitter_text(content, node)
    return raw[1:-1] if len(raw) >= 2 and raw[0] in {'"', "'", "`"} else raw


def _tree_sitter_property_strings(
    content: bytes,
    node: Any,
    property_name: str,
) -> List[str]:
    values = []
    for child in _walk_tree_sitter_nodes(node):
        if child.type not in {"pair", "property_signature"}:
            continue
        key = _tree_sitter_text(content, child.child_by_field_name("key")).strip("'\"")
        value = _tree_sitter_string(content, child.child_by_field_name("value"))
        if key == property_name and value:
            values.append(value)
    return values
