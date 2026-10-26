"""Bounded Tree-sitter semantic flow analysis for TypeScript and TSX."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

try:
    from tree_sitter_language_pack import get_parser
except ImportError:  # pragma: no cover - dependency failures remain explicit in coverage.
    get_parser = None

from ..languages.tree_sitter_gateway import parser_for

from .semantic_javascript import JS_SINKS
from .semantic_source import FunctionRecord, GUARD_MARKERS, SOURCE_NAME_MARKERS


TYPESCRIPT_EXTENSIONS = {".ts", ".tsx", ".mts", ".cts"}


@dataclass
class TypeScriptSemanticIndex:
    records: List[FunctionRecord]
    files_indexed: int
    parse_errors: List[Dict[str, str]] = field(default_factory=list)
    truncated: bool = False

    def __post_init__(self) -> None:
        self.by_id = {record.record_id: record for record in self.records}
        self.by_simple_name: Dict[str, List[FunctionRecord]] = {}
        for record in self.records:
            self.by_simple_name.setdefault(record.name, []).append(record)

    def resolve_call(self, call_name: str) -> List[FunctionRecord]:
        return self.by_simple_name.get(call_name.rsplit(".", 1)[-1], [])[:8]


def build_typescript_semantic_index(
    project_root: Path,
    source_files: Iterable[Path],
    *,
    max_files: int = 2_000,
    max_file_bytes: int = 512_000,
) -> TypeScriptSemanticIndex:
    if get_parser is None:
        return TypeScriptSemanticIndex([], 0, [{
            "file_path": "", "error": "tree-sitter-language-pack is unavailable",
        }])
    parsers = {
        "typescript": parser_for("typescript"),
        "tsx": parser_for("tsx"),
    }
    if not any(parsers.values()):
        return TypeScriptSemanticIndex([], 0, [{
            "file_path": "",
            "error": "tree-sitter parsers unavailable (not cached and download blocked)",
        }])
    records: List[FunctionRecord] = []
    parse_errors: List[Dict[str, str]] = []
    files_indexed = 0
    truncated = False
    for target in source_files:
        if target.suffix.lower() not in TYPESCRIPT_EXTENSIONS or target.stat().st_size > max_file_bytes:
            continue
        if files_indexed >= max_files:
            truncated = True
            break
        files_indexed += 1
        relative = target.resolve().relative_to(project_root).as_posix()
        content = target.read_bytes()
        parser_name = "tsx" if target.suffix.lower() == ".tsx" else "typescript"
        parser = parsers[parser_name]
        if parser is None:
            # 单一语法缺失（如 tsx 下载失败）时跳过该文件，不影响其余索引。
            parse_errors.append({
                "file_path": relative,
                "error": f"tree-sitter parser unavailable for {parser_name}",
            })
            continue
        tree = parser.parse(content)
        if tree.root_node.has_error:
            parse_errors.append({"file_path": relative, "error": "Tree-sitter parse contains ERROR nodes"})
        records.extend(_records_for_tree(relative, content, tree.root_node))
    return TypeScriptSemanticIndex(records, files_indexed, parse_errors[:100], truncated)


def trace_typescript_flow(
    index: TypeScriptSemanticIndex,
    *,
    file_path: str,
    symbol: str = "",
    line: int = 0,
    max_depth: int = 4,
    max_paths: int = 40,
) -> Dict[str, Any]:
    normalized = file_path.replace("\\", "/")
    seeds = [record for record in index.records if record.file_path == normalized]
    if symbol:
        seeds = [record for record in seeds if record.name == symbol or record.qualified_name.endswith(f".{symbol}")]
    if line > 0:
        containing = [record for record in seeds if record.line_start <= line <= record.line_end]
        seeds = containing or seeds
    seeds = seeds[:20]
    seed_ids = {item.record_id for item in seeds}
    seed_names = {item.name for item in seeds}
    callers = [
        record for record in index.records
        if record.record_id not in seed_ids
        and any(call["name"].rsplit(".", 1)[-1] in seed_names for call in record.calls)
    ][:100]
    callees = _unique_records(
        target for seed in seeds for call in seed.calls for target in index.resolve_call(call["name"])
    )[:100]

    paths: List[Dict[str, Any]] = []
    unresolved = set()
    for seed in seeds:
        queue: List[tuple[FunctionRecord, List[FunctionRecord], List[Dict[str, Any]], int]] = [
            (seed, [seed], [], 0)
        ]
        while queue and len(paths) < max_paths:
            current, nodes, edges, depth = queue.pop(0)
            if current.sinks:
                paths.append({
                    "node_ids": [node.record_id for node in nodes],
                    "nodes": [node.summary() for node in nodes],
                    "edges": edges,
                    "source_observations": [item for node in nodes for item in node.sources],
                    "sink_observations": current.sinks,
                    "guard_observations": [item for node in nodes for item in node.guards],
                    "cross_file": len({node.file_path for node in nodes}) > 1,
                })
            if depth >= max_depth:
                continue
            for call in current.calls:
                targets = index.resolve_call(call["name"])
                if not targets and _sink_kind(call["name"]) is None:
                    unresolved.add(call["name"])
                for target in targets:
                    if any(node.record_id == target.record_id for node in nodes):
                        continue
                    queue.append((
                        target,
                        [*nodes, target],
                        [*edges, {
                            "caller_id": current.record_id,
                            "callee_id": target.record_id,
                            "call_name": call["name"],
                            "file_path": current.file_path,
                            "line": call["line"],
                        }],
                        depth + 1,
                    ))
    return {
        "language": "typescript",
        "parser": "tree-sitter-typescript",
        "file_path": normalized,
        "symbol": symbol or None,
        "line": line or None,
        "seed_functions": [record.summary() for record in seeds],
        "callers": [record.summary() for record in callers],
        "callees": [record.summary() for record in callees],
        "paths": paths,
        "unresolved_calls": sorted(unresolved)[:200],
        "coverage": {
            "files_indexed": index.files_indexed,
            "functions_indexed": len(index.records),
            "parse_errors": index.parse_errors,
            "index_truncated": index.truncated,
            "max_depth": max_depth,
            "path_count": len(paths),
            "cross_file_path_count": sum(1 for path in paths if path["cross_file"]),
        },
    }


def _records_for_tree(file_path: str, content: bytes, root: Any) -> List[FunctionRecord]:
    records = []
    module = ".".join(Path(file_path).with_suffix("").parts)
    for node in _walk(root):
        name = ""
        function = None
        if node.type == "function_declaration":
            name = _text(content, node.child_by_field_name("name"))
            function = node
        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            if value is not None and value.type in {"arrow_function", "function_expression"}:
                name = _text(content, node.child_by_field_name("name"))
                function = value
        elif node.type in {"method_definition", "method_signature"}:
            name = _text(content, node.child_by_field_name("name"))
            function = node
        if name and function is not None:
            records.append(_function_record(file_path, f"{module}.{name}", name, content, function))
    return _unique_records(records)


def _function_record(
    file_path: str,
    qualified_name: str,
    name: str,
    content: bytes,
    node: Any,
) -> FunctionRecord:
    parameters = []
    parameter_node = node.child_by_field_name("parameters")
    if parameter_node is not None:
        for child in _walk(parameter_node):
            if child.type in {"required_parameter", "optional_parameter"}:
                pattern = child.child_by_field_name("pattern")
                parameter = _text(content, pattern).strip()
                if parameter and parameter not in parameters:
                    parameters.append(parameter)
    calls = []
    sources = []
    sinks = []
    guards = []
    line_start = int(node.start_point.row) + 1
    line_end = int(node.end_point.row) + 1
    for parameter in parameters:
        if parameter.lower() in SOURCE_NAME_MARKERS:
            sources.append({"kind": "parameter", "name": parameter, "line": line_start})
    body = node.child_by_field_name("body") or node
    for child in _walk(body):
        if child.type in {"call_expression", "new_expression"}:
            call_name = _expression_name(content, child.child_by_field_name("function"))
            if not call_name:
                call_name = _expression_name(content, child.child_by_field_name("constructor"))
            if not call_name:
                continue
            observation = {"name": call_name, "line": int(child.start_point.row) + 1}
            calls.append(observation)
            sink_kind = _sink_kind(call_name)
            if sink_kind:
                sinks.append({**observation, "kind": sink_kind})
            if any(marker in call_name.lower() for marker in GUARD_MARKERS):
                guards.append({**observation, "kind": "guard_call"})
        elif child.type in {"member_expression", "subscript_expression"}:
            member = _expression_name(content, child)
            if member.lower().startswith((
                "req.", "request.", "event.", "message.", "location.", "document.", "process.argv",
            )):
                sources.append({
                    "kind": "external_access", "name": member,
                    "line": int(child.start_point.row) + 1,
                })
        elif child.type == "assignment_expression":
            target = _expression_name(content, child.child_by_field_name("left"))
            if target.rsplit(".", 1)[-1] in {"innerHTML", "outerHTML"}:
                sinks.append({
                    "name": target, "line": int(child.start_point.row) + 1,
                    "kind": "html_injection",
                })
    return FunctionRecord(
        record_id=f"{file_path}:{line_start}:{qualified_name}",
        name=name,
        qualified_name=qualified_name,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        parameters=parameters,
        calls=_dedupe(calls),
        sources=_dedupe(sources),
        sinks=_dedupe(sinks),
        guards=_dedupe(guards),
    )


def _walk(node: Any) -> Iterable[Any]:
    if node is None:
        return
    yield node
    for child in node.children:
        yield from _walk(child)


def _expression_name(content: bytes, node: Any) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "property_identifier", "this", "super"}:
        return _text(content, node)
    if node.type == "member_expression":
        prefix = _expression_name(content, node.child_by_field_name("object"))
        suffix = _expression_name(content, node.child_by_field_name("property"))
        return f"{prefix}.{suffix}".strip(".")
    if node.type == "subscript_expression":
        prefix = _expression_name(content, node.child_by_field_name("object"))
        index = _text(content, node.child_by_field_name("index")).strip("'\"")
        return f"{prefix}.{index}".strip(".")
    return _text(content, node)


def _text(content: bytes, node: Any) -> str:
    if node is None:
        return ""
    return content[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _sink_kind(call_name: str) -> Optional[str]:
    if call_name in JS_SINKS:
        return JS_SINKS[call_name]
    simple = call_name.rsplit(".", 1)[-1]
    if simple in {"query", "execute"}:
        return "sql_execution"
    return None


def _unique_records(records: Iterable[FunctionRecord]) -> List[FunctionRecord]:
    output = []
    seen = set()
    for record in records:
        if record.record_id not in seen:
            seen.add(record.record_id)
            output.append(record)
    return output


def _dedupe(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    output = []
    seen = set()
    for value in values:
        marker = tuple(sorted(value.items()))
        if marker not in seen:
            seen.add(marker)
            output.append(value)
    return output
