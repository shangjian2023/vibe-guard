"""Framework-aware security semantics with source provenance and honest coverage."""

from __future__ import annotations

import ast
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover - dependency is declared but optional at runtime
    get_parser = None

from ..languages.tree_sitter_gateway import parser_for


_NATIVE_TREE_SITTER_ENABLED = os.getenv("VIBE_SEC_ENABLE_TREE_SITTER") == "1"


SUPPORTED_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go"}
IGNORED_DIRECTORIES = {
    ".git", "node_modules", "vendor", "venv", ".venv", "__pycache__", "dist", "build", ".next",
}


@dataclass(frozen=True)
class FrameworkObservation:
    framework: str
    semantic_type: str
    operation: str
    file_path: str
    line_start: int
    line_end: int
    symbol: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.9
    parser: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FrameworkSemanticReport:
    observations: List[FrameworkObservation] = field(default_factory=list)
    risk_paths: List[Dict[str, Any]] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract": "vibe-sec.framework-semantics.v1",
            "frameworks": sorted({item.framework for item in self.observations}),
            "observations": [item.to_dict() for item in self.observations],
            "risk_paths": list(self.risk_paths),
            "coverage": dict(self.coverage),
        }


def analyze_framework_semantics(
    project_root: Path,
    *,
    file_path: str = "",
    framework: str = "",
    max_files: int = 2_000,
    max_results: int = 1_000,
    max_file_bytes: int = 1_000_000,
) -> FrameworkSemanticReport:
    root = project_root.resolve()
    paths = _selected_files(root, file_path, max_files)
    observations: List[FrameworkObservation] = []
    failures: List[Dict[str, str]] = []
    parsed_files: List[str] = []
    truncated = False
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > max_file_bytes:
                failures.append({"file_path": relative, "error": "file_too_large"})
                continue
            content = path.read_text(encoding="utf-8", errors="replace")
            if path.suffix.lower() == ".py":
                items = _analyze_python(relative, content)
            else:
                items, parser_failure = _analyze_tree_sitter_lines(
                    relative,
                    content,
                    path.suffix.lower(),
                )
                if parser_failure:
                    failures.append({"file_path": relative, "error": parser_failure})
            parsed_files.append(relative)
            if framework:
                items = [item for item in items if item.framework == framework.lower()]
            observations.extend(items)
            if len(observations) >= max_results:
                observations = observations[:max_results]
                truncated = True
                break
        except (OSError, SyntaxError, ValueError) as exc:
            failures.append({"file_path": relative, "error": type(exc).__name__})
    risk_paths = _build_risk_paths(observations)
    frameworks = sorted({item.framework for item in observations})
    gaps: List[str] = []
    if failures:
        gaps.append(f"{len(failures)} supported source files could not be semantically parsed")
    if truncated:
        gaps.append("Framework observations were truncated at max_results")
    if not frameworks:
        gaps.append("No supported framework semantics were detected in the selected scope")
    return FrameworkSemanticReport(
        observations=observations,
        risk_paths=risk_paths,
        coverage={
            "files_considered": len(paths),
            "files_parsed": len(parsed_files),
            "parsed_files": parsed_files,
            "parse_failures": failures,
            "observation_count": len(observations),
            "risk_path_count": len(risk_paths),
            "truncated": truncated,
            "gaps": gaps,
            "semantic_scope": (
                "Python AST function binding; Tree-sitter syntax validation plus framework-specific "
                "line provenance for JavaScript/TypeScript, Java, and Go"
            ),
        },
    )


def _selected_files(root: Path, file_path: str, max_files: int) -> List[Path]:
    if file_path:
        target = (root / file_path).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError("file_path escapes project root") from exc
        if not target.is_file() or target.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise ValueError("file_path must identify a supported source file")
        return [target]
    selected = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        selected.append(path)
        if len(selected) >= max_files:
            break
    return selected


def _analyze_python(file_path: str, content: str) -> List[FrameworkObservation]:
    tree = ast.parse(content)
    imports = " ".join(
        [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        + [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    ).lower()
    frameworks = []
    if "django" in imports:
        frameworks.append("django")
    if "fastapi" in imports:
        frameworks.append("fastapi")
    if "flask" in imports:
        frameworks.append("flask")
    if not frameworks:
        return []
    observations: List[FrameworkObservation] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            observations.extend(_python_function_observations(file_path, content, node, frameworks))
        if isinstance(node, ast.Call):
            name = _python_name(node.func)
            short = name.rsplit(".", 1)[-1].lower()
            if "django" in frameworks and short in {"path", "re_path"}:
                route = _literal(node.args[0]) if node.args else "<dynamic-route>"
                observations.append(_observation(
                    "django", "route", f"url.{short}", file_path, node,
                    details={"route": route or "<dynamic-route>", "registration": name},
                    parser="python_ast",
                ))
    return observations


def _python_function_observations(
    file_path: str,
    content: str,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    frameworks: Sequence[str],
) -> List[FrameworkObservation]:
    result: List[FrameworkObservation] = []
    decorators = [
        _python_name(item.func) if isinstance(item, ast.Call) else _python_name(item)
        for item in node.decorator_list
    ]
    function_text = ast.get_source_segment(content, node) or ""
    lowered = function_text.lower()
    calls = [_python_name(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)]
    attributes = [_python_name(item) for item in ast.walk(node) if isinstance(item, ast.Attribute)]
    for framework in frameworks:
        route_decorated = any(
            decorator.rsplit(".", 1)[-1].lower()
            in {"route", "get", "post", "put", "delete", "patch", "websocket", "api_view", "action"}
            for decorator in decorators
        )
        for decorator in decorators:
            short = decorator.rsplit(".", 1)[-1].lower()
            if short in {"route", "get", "post", "put", "delete", "patch", "websocket", "api_view", "action"}:
                result.append(_observation(
                    framework, "route", f"decorator.{short}", file_path, node,
                    symbol=node.name, details={"decorator": decorator}, parser="python_ast",
                ))
            if any(marker in decorator.lower() for marker in (
                "login_required", "permission_required", "user_passes_test", "requires_auth", "authorize",
            )):
                kind = "authorization_guard" if "permission" in decorator.lower() or "authorize" in decorator.lower() else "authentication_guard"
                result.append(_observation(
                    framework, kind, decorator, file_path, node,
                    symbol=node.name, parser="python_ast",
                ))
        if route_decorated and framework in {"fastapi", "flask"}:
            for argument in node.args.args:
                if argument.arg not in {"self", "cls"}:
                    result.append(_observation(
                        framework, "untrusted_input", f"handler_parameter:{argument.arg}", file_path, node,
                        symbol=node.name,
                        details={"framework_binding": "request_or_dependency_parameter"},
                        parser="python_ast",
                    ))
        if framework == "fastapi" and any(
            isinstance(item, ast.Call) and _python_name(item.func).endswith(("Depends", "Security"))
            for item in ast.walk(node.args)
        ):
            result.append(_observation(
                framework, "authorization_guard", "dependency_injection_guard", file_path, node,
                symbol=node.name, parser="python_ast",
            ))
        source_markers = [
            value for value in attributes
            if any(marker in value.lower() for marker in (
                "request.args", "request.form", "request.json", "request.values", "request.get_json",
                "request.query_params", "request.path_params", "request.headers", "request.cookies",
                "request.get", "request.post", "request.data",
            ))
        ]
        for marker in sorted(set(source_markers)):
            result.append(_observation(
                framework, "untrusted_input", marker, file_path, node,
                symbol=node.name, parser="python_ast",
            ))
        for call in sorted(set(calls)):
            lowered_call = call.lower()
            if any(marker in lowered_call for marker in (
                ".objects.filter", ".objects.get", ".objects.create", ".objects.update",
                "session.query", "session.execute", ".select", ".where",
            )):
                result.append(_observation(
                    framework, "orm_operation", call, file_path, node,
                    symbol=node.name, details={"parameterized_by_default": ".raw" not in lowered_call},
                    parser="python_ast",
                ))
            if any(marker in lowered_call for marker in (
                ".objects.raw", ".objects.extra", "cursor.execute", "connection.execute", "text",
            )):
                result.append(_observation(
                    framework, "sql_sink", call, file_path, node,
                    symbol=node.name, details={"dynamic_expression": _has_dynamic_call_argument(node, call)},
                    parser="python_ast",
                ))
            if any(marker in lowered_call for marker in (
                "os.system", "subprocess.run", "subprocess.popen", "subprocess.call", "eval", "exec",
            )):
                result.append(_observation(
                    framework, "code_execution_sink", call, file_path, node,
                    symbol=node.name, parser="python_ast",
                ))
        if any(marker in lowered for marker in ("basemodel", "serializer(", "validate_", "forms.form")):
            result.append(_observation(
                framework, "validation", "schema_or_form_validation", file_path, node,
                symbol=node.name, parser="python_ast",
            ))
    return result


_FRAMEWORK_MARKERS = {
    ".js": {"express": ("express",), "next": ("next/", "nextrequest"), "nest": ("@nestjs/",)},
    ".jsx": {"express": ("express",), "next": ("next/", "nextrequest"), "nest": ("@nestjs/",)},
    ".ts": {"express": ("express",), "next": ("next/", "nextrequest"), "nest": ("@nestjs/",)},
    ".tsx": {"express": ("express",), "next": ("next/", "nextrequest"), "nest": ("@nestjs/",)},
    ".java": {"spring": ("org.springframework", "@restcontroller", "@controller")},
    ".go": {"go-http": ("net/http",), "gin": ("gin-gonic/gin",), "echo": ("labstack/echo",), "chi": ("go-chi/chi",)},
}


_LINE_RULES = {
    "express": [
        ("route", r"\b(?:app|router)\.(get|post|put|patch|delete|all)\s*\(", "http_route"),
        ("middleware", r"\b(?:app|router)\.use\s*\(", "middleware"),
        ("untrusted_input", r"\breq\.(body|query|params|headers|cookies)\b", "request_input"),
        ("authorization_guard", r"\b(auth|authorize|requireRole|requirePermission|isAdmin)\b", "auth_guard"),
        ("sql_sink", r"\b(?:query|execute|\$queryRawUnsafe)\s*\(", "database_query"),
        ("code_execution_sink", r"\b(?:exec|execSync|spawn)\s*\(", "process_execution"),
    ],
    "nest": [
        ("route", r"@(Get|Post|Put|Patch|Delete)\s*\(", "controller_route"),
        ("authorization_guard", r"@(UseGuards|Roles|SetMetadata)\s*\(", "guard_decorator"),
        ("untrusted_input", r"@(Body|Query|Param|Headers)\s*\(", "decorated_input"),
        ("orm_operation", r"\b(?:repository|prisma|entityManager)\.(find|findOne|save|update|delete|query)\s*\(", "orm_call"),
        ("sql_sink", r"\b(?:query|\$queryRawUnsafe)\s*\(", "raw_query"),
    ],
    "next": [
        ("route", r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", "route_handler"),
        ("untrusted_input", r"\b(?:req\.body|request\.json\s*\(|searchParams|getServerSession)\b", "request_input"),
        ("authorization_guard", r"\b(?:getServerSession|auth\s*\(|withAuth|middleware)\b", "auth_guard"),
        ("sql_sink", r"\b(?:query|execute|\$queryRawUnsafe)\s*\(", "database_query"),
    ],
    "spring": [
        ("route", r"@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b", "controller_route"),
        ("untrusted_input", r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\b", "request_input"),
        ("authorization_guard", r"@(PreAuthorize|Secured|RolesAllowed)\b", "method_security"),
        ("validation", r"@(Valid|Validated)\b", "bean_validation"),
        ("orm_operation", r"\b(?:repository|entityManager)\.(find|save|persist|merge)\s*\(", "orm_call"),
        ("sql_sink", r"\b(?:jdbcTemplate|entityManager)\.(query|update|createNativeQuery)\s*\(", "database_query"),
        ("code_execution_sink", r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\b", "process_execution"),
    ],
    "go-http": [
        ("route", r"\bhttp\.(Handle|HandleFunc)\s*\(", "http_route"),
        ("untrusted_input", r"\br\.(FormValue|PathValue)|r\.URL\.Query\s*\(", "request_input"),
        ("sql_sink", r"\b(?:db|tx)\.(Query|QueryRow|Exec)\s*\(", "database_query"),
        ("code_execution_sink", r"\bexec\.Command(?:Context)?\s*\(", "process_execution"),
    ],
    "gin": [
        ("route", r"\b(?:router|r|group)\.(GET|POST|PUT|PATCH|DELETE|Any)\s*\(", "http_route"),
        ("middleware", r"\b(?:router|r|group)\.Use\s*\(", "middleware"),
        ("untrusted_input", r"\bc\.(Query|Param|PostForm|GetHeader|ShouldBind|BindJSON)\s*\(", "request_input"),
        ("authorization_guard", r"\b(Auth|Authorize|RequireRole|JWT)\w*\s*\(", "auth_guard"),
        ("sql_sink", r"\b(?:db|tx)\.(Raw|Exec|Query)\s*\(", "database_query"),
    ],
    "echo": [
        ("route", r"\b(?:e|g)\.(GET|POST|PUT|PATCH|DELETE|Any)\s*\(", "http_route"),
        ("middleware", r"\b(?:e|g)\.Use\s*\(", "middleware"),
        ("untrusted_input", r"\bc\.(QueryParam|Param|FormValue|Bind|Request)\s*\(", "request_input"),
        ("authorization_guard", r"\b(?:JWT|KeyAuth|Auth|Authorize)\w*\s*\(", "auth_guard"),
        ("sql_sink", r"\b(?:db|tx)\.(Raw|Exec|Query)\s*\(", "database_query"),
    ],
    "chi": [
        ("route", r"\b(?:r|router)\.(Get|Post|Put|Patch|Delete|Method)\s*\(", "http_route"),
        ("middleware", r"\b(?:r|router)\.Use\s*\(", "middleware"),
        ("untrusted_input", r"\bchi\.URLParam|r\.URL\.Query\s*\(", "request_input"),
        ("authorization_guard", r"\b(?:Auth|Authorize|RequireRole|JWT)\w*\s*\(", "auth_guard"),
        ("sql_sink", r"\b(?:db|tx)\.(Query|QueryRow|Exec)\s*\(", "database_query"),
    ],
}


def _analyze_tree_sitter_lines(
    file_path: str,
    content: str,
    suffix: str,
) -> tuple[List[FrameworkObservation], Optional[str]]:
    language = {
        ".js": "javascript", ".jsx": "tsx", ".ts": "typescript", ".tsx": "tsx",
        ".java": "java", ".go": "go",
    }[suffix]
    parser_name = f"tree_sitter_{language}"
    parser_failure: Optional[str] = None
    syntax_validated = False
    if get_parser is None:
        parser_failure = "tree_sitter_unavailable"
        parser_name = "local_line_fallback"
    elif not _NATIVE_TREE_SITTER_ENABLED:
        parser_name = "local_line_fallback"
    else:
        parser = parser_for(language)
        if parser is None:
            parser_failure = "tree_sitter_unavailable"
            parser_name = "local_line_fallback"
        else:
            try:
                tree = parser.parse(content.encode("utf-8", errors="replace"))
                if tree.root_node.has_error:
                    parser_failure = "tree_sitter_parse_error"
                    parser_name = "local_line_fallback"
                else:
                    syntax_validated = True
            except Exception as exc:  # Native grammar acquisition can fail at runtime.
                parser_failure = f"tree_sitter_runtime_unavailable:{type(exc).__name__}"
                parser_name = "local_line_fallback"
    lowered = content.lower()
    frameworks = [
        framework for framework, markers in _FRAMEWORK_MARKERS[suffix].items()
        if any(marker in lowered for marker in markers)
    ]
    observations: List[FrameworkObservation] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        for framework in frameworks:
            for semantic_type, pattern, operation in _LINE_RULES.get(framework, []):
                match = re.search(pattern, line, re.IGNORECASE)
                if not match:
                    continue
                observations.append(FrameworkObservation(
                    framework=framework,
                    semantic_type=semantic_type,
                    operation=operation,
                    file_path=file_path,
                    line_start=line_number,
                    line_end=line_number,
                    symbol=match.group(0)[:120],
                    details={
                        "syntax_validated": syntax_validated,
                        "binding": "line_provenance",
                        "route": _route_literal(line) if semantic_type == "route" else None,
                        "method": (
                            str(match.group(1)).upper()
                            if semantic_type == "route" and match.lastindex
                            else None
                        ),
                    },
                    confidence=0.82,
                    parser=parser_name,
                ))
    return observations, parser_failure


def _build_risk_paths(observations: Iterable[FrameworkObservation]) -> List[Dict[str, Any]]:
    by_file: Dict[str, List[FrameworkObservation]] = {}
    for item in observations:
        by_file.setdefault(item.file_path, []).append(item)
    paths = []
    for file_path, items in by_file.items():
        entries = [item for item in items if item.semantic_type == "route"]
        sources = [item for item in items if item.semantic_type == "untrusted_input"]
        sinks = [item for item in items if item.semantic_type in {"sql_sink", "code_execution_sink"}]
        guards = [item for item in items if item.semantic_type in {"authentication_guard", "authorization_guard", "validation"}]
        for entry in entries:
            nearby_sources = [item for item in sources if abs(item.line_start - entry.line_start) <= 120]
            nearby_sinks = [item for item in sinks if abs(item.line_start - entry.line_start) <= 120]
            if not nearby_sources or not nearby_sinks:
                continue
            nearby_guards = [item for item in guards if abs(item.line_start - entry.line_start) <= 120]
            paths.append({
                "path_id": f"framework-path-{len(paths) + 1}",
                "framework": entry.framework,
                "file_path": file_path,
                "entry": entry.to_dict(),
                "sources": [item.to_dict() for item in nearby_sources[:5]],
                "sinks": [item.to_dict() for item in nearby_sinks[:5]],
                "guards": [item.to_dict() for item in nearby_guards[:5]],
                "guard_status": "observed" if nearby_guards else "not_observed",
                "binding": "same Python function" if entry.parser == "python_ast" else "bounded line proximity",
                "requires_follow_up": True,
            })
    return paths[:500]


def _observation(
    framework: str,
    semantic_type: str,
    operation: str,
    file_path: str,
    node: ast.AST,
    *,
    symbol: str = "",
    details: Optional[Dict[str, Any]] = None,
    parser: str,
) -> FrameworkObservation:
    return FrameworkObservation(
        framework=framework,
        semantic_type=semantic_type,
        operation=operation,
        file_path=file_path,
        line_start=int(getattr(node, "lineno", 1)),
        line_end=int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
        symbol=symbol,
        details=dict(details or {}),
        confidence=0.95,
        parser=parser,
    )


def _python_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal(node: ast.AST) -> str:
    return str(node.value) if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)) else ""


def _has_dynamic_call_argument(function: ast.AST, target_name: str) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or _python_name(node.func) != target_name:
            continue
        return any(isinstance(item, (ast.JoinedStr, ast.BinOp, ast.Call, ast.Name)) for item in node.args)
    return False


def _route_literal(line: str) -> str:
    match = re.search(r"[('\"](/[^'\"]*)['\"]", line)
    return match.group(1) if match else "<dynamic-route>"
