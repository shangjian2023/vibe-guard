"""Behavior tests for bounded source exploration tools."""

import asyncio
from pathlib import Path

import pytest

from conftest import tree_sitter_ready

from core.tool_fabric import ArtifactStore, ToolGateway, ToolRequest, build_source_registry


def build_gateway(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    gateway = ToolGateway(
        build_source_registry(),
        project_root=str(project),
        artifact_store=ArtifactStore(str(tmp_path / "artifacts"), session_id="source-test"),
    )
    return project, gateway


def run_tool(gateway, name, arguments):
    return asyncio.run(gateway.execute(ToolRequest(tool_name=name, arguments=arguments)))


def test_source_tools_support_cross_file_search_and_bounded_read(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "service.py").write_text(
        "from db import run\n\n"
        "def load_user(user_id):\n"
        "    return run(f'SELECT * FROM users WHERE id={user_id}')\n",
        encoding="utf-8",
    )
    (project / "route.py").write_text(
        "from service import load_user\n"
        "def handler(request):\n"
        "    return load_user(request.args['id'])\n",
        encoding="utf-8",
    )

    search = run_tool(gateway, "search_code", {"pattern": "load_user", "max_results": 10})
    read = run_tool(gateway, "read_source", {
        "file_path": "service.py",
        "line_start": 1,
        "line_end": 500,
    })
    outline = run_tool(gateway, "inspect_file_outline", {"file_path": "service.py"})

    assert search.output["match_count"] == 3
    assert {item["file_path"] for item in search.output["matches"]} == {"route.py", "service.py"}
    assert search.artifacts[0].sha256
    assert read.output["line_end"] == 4
    assert read.signals[0].kind == "source_evidence"
    assert outline.output["symbols"][0]["name"] == "load_user"


def test_source_tools_ignore_dependency_directories_and_enforce_scope(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "app.py").write_text("safe = True\n", encoding="utf-8")
    dependency = project / "node_modules" / "package"
    dependency.mkdir(parents=True)
    (dependency / "index.js").write_text("dangerous()\n", encoding="utf-8")

    listed = run_tool(gateway, "list_source_files", {"glob": "*"})
    escaped = run_tool(gateway, "read_source", {"file_path": "../outside.py"})

    assert listed.output["files"] == ["app.py"]
    assert escaped.status.value == "blocked"


def test_source_reads_and_artifacts_redact_credential_literals(tmp_path):
    project, gateway = build_gateway(tmp_path)
    secret = "sk-live-looking-secret-123456789"
    (project / "config.py").write_text(
        f"api_key: str = {secret!r}\npassword = 'database-password'\n",
        encoding="utf-8",
    )

    read = run_tool(gateway, "read_source", {"file_path": "config.py"})
    search = run_tool(gateway, "search_code", {"pattern": "api_key"})
    serialized = str(read.to_dict()) + str(search.to_dict())
    artifact_text = "\n".join(
        Path(item.path).read_text(encoding="utf-8")
        for item in [*read.artifacts, *search.artifacts]
    )

    assert secret not in serialized
    assert "database-password" not in serialized
    assert secret not in artifact_text
    assert "database-password" not in artifact_text
    assert "[REDACTED sha256:" in read.output["content"]


def test_python_semantic_flow_traces_cross_file_source_to_sink(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "service.py").write_text(
        "def load_user(cursor, user_id):\n"
        "    query = f'SELECT * FROM users WHERE id={user_id}'\n"
        "    return cursor.execute(query)\n",
        encoding="utf-8",
    )
    (project / "route.py").write_text(
        "from service import load_user\n"
        "def handler(request, cursor):\n"
        "    return load_user(cursor, request.args['id'])\n",
        encoding="utf-8",
    )

    execution = run_tool(gateway, "trace_python_flow", {
        "file_path": "route.py",
        "symbol": "handler",
        "max_depth": 3,
    })

    assert execution.status.value == "completed"
    assert execution.output["seed_functions"][0]["qualified_name"] == "route.handler"
    assert execution.output["callees"][0]["qualified_name"] == "service.load_user"
    path = execution.output["paths"][0]
    assert path["cross_file"] is True
    assert path["source_observations"]
    assert path["sink_observations"][0]["kind"] == "sql_execution"
    assert path["guard_observations"] == []
    assert execution.output["coverage"]["cross_file_path_count"] == 1
    assert execution.artifacts[0].sha256


def test_javascript_semantic_flow_traces_cross_file_source_to_sink(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "service.js").write_text(
        "export function loadUser(db, userId) {\n"
        "  const query = `SELECT * FROM users WHERE id=${userId}`;\n"
        "  return db.query(query);\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "route.js").write_text(
        "import { loadUser } from './service.js';\n"
        "export function handler(req, db) {\n"
        "  return loadUser(db, req.query.id);\n"
        "}\n",
        encoding="utf-8",
    )

    execution = run_tool(gateway, "trace_javascript_flow", {
        "file_path": "route.js",
        "symbol": "handler",
        "max_depth": 3,
    })

    assert execution.status.value == "completed"
    assert execution.output["parser"] == "esprima"
    assert execution.output["seed_functions"][0]["qualified_name"] == "route.handler"
    assert execution.output["callees"][0]["qualified_name"] == "service.loadUser"
    path = execution.output["paths"][0]
    assert path["cross_file"] is True
    assert path["source_observations"]
    assert path["sink_observations"][0]["kind"] == "sql_execution"
    assert execution.output["coverage"]["cross_file_path_count"] == 1
    assert execution.artifacts[0].sha256


def test_javascript_semantic_flow_rejects_typescript_without_claiming_parser_support(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "route.ts").write_text("export function handler(req: Request) {}\n", encoding="utf-8")

    execution = run_tool(gateway, "trace_javascript_flow", {"file_path": "route.ts"})

    assert execution.status.value == "failed"
    assert "requires a JavaScript or JSX source file" in execution.error


@pytest.mark.skipif(
    not tree_sitter_ready("typescript"),
    reason="tree-sitter typescript 解析器未缓存且下载不可达",
)
def test_typescript_semantic_flow_traces_typed_cross_file_source_to_sink(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "service.ts").write_text(
        "export interface DB { query(value: string): unknown; }\n"
        "export function loadUser(db: DB, userId: string): unknown {\n"
        "  const query: string = `SELECT * FROM users WHERE id=${userId}`;\n"
        "  return db.query(query);\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "route.ts").write_text(
        "import { DB, loadUser } from './service';\n"
        "interface Request { query: { id: string } }\n"
        "export async function handler(req: Request, db: DB): Promise<unknown> {\n"
        "  return loadUser(db, req.query.id);\n"
        "}\n",
        encoding="utf-8",
    )

    execution = run_tool(gateway, "trace_typescript_flow", {
        "file_path": "route.ts",
        "symbol": "handler",
        "max_depth": 3,
    })

    assert execution.status.value == "completed"
    assert execution.output["parser"] == "tree-sitter-typescript"
    assert execution.output["seed_functions"][0]["qualified_name"] == "route.handler"
    assert execution.output["callees"][0]["qualified_name"] == "service.loadUser"
    path = execution.output["paths"][0]
    assert path["cross_file"] is True
    assert path["source_observations"]
    assert path["sink_observations"][0]["kind"] == "sql_execution"
    assert execution.output["coverage"]["parse_errors"] == []
    assert execution.output["coverage"]["cross_file_path_count"] == 1
    assert execution.artifacts[0].sha256


def test_audit_guidance_loads_bounded_hashed_methodology_and_existing_checklist(tmp_path):
    _, gateway = build_gateway(tmp_path)

    execution = run_tool(gateway, "load_audit_guidance", {
        "lane": "web_audit",
        "vulnerability_type": "sql_injection",
        "language": "python",
        "max_chars": 2_000,
    })

    assert execution.status.value == "completed"
    documents = {item["path"]: item for item in execution.output["documents"]}
    assert "knowledge_base/source_audit_methodology.md" in documents
    assert "knowledge_base/false_positive_and_verification.md" in documents
    assert "skill/references/checklists/web/sql_injection.md" in documents
    assert all(len(item["sha256"]) == 64 for item in documents.values())
    assert all(len(item["excerpt"]) <= 2_000 for item in documents.values())
    assert "skill/references/adapters/python.yaml" in execution.output["missing_documents"]
    assert execution.output["evidence_policy"].startswith("Guidance may direct tool use")
    assert execution.artifacts[0].artifact_type == "audit_guidance"
    assert execution.artifacts[0].sha256
    assert execution.signals[0].metadata["not_project_evidence"] is True


def test_audit_guidance_reports_missing_catalog_checklist_without_accepting_paths(tmp_path):
    _, gateway = build_gateway(tmp_path)
    spec = gateway.registry.get("load_audit_guidance").spec

    execution = run_tool(gateway, "load_audit_guidance", {
        "lane": "web_audit",
        "vulnerability_type": "ssrf",
    })

    assert "path" not in spec.input_schema["properties"]
    assert execution.status.value == "completed"
    assert execution.output["coverage_gap"] is True
    assert "skill/references/checklists/web/ssrf.md" in execution.output["missing_documents"]
    assert all(item["path"] != "skill/references/checklists/web/ssrf.md" for item in execution.output["documents"])


def test_dependency_inspection_parses_versions_locks_and_provenance_across_ecosystems(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["flask==3.0.0", "httpx>=0.25"]\n',
        encoding="utf-8",
    )
    (project / "poetry.lock").write_text(
        '[[package]]\nname = "flask"\nversion = "3.0.0"\n', encoding="utf-8",
    )
    (project / "package.json").write_text(
        '{"dependencies":{"express":"^4.18.0"},"devDependencies":{"vitest":"1.6.0"}}',
        encoding="utf-8",
    )
    (project / "package-lock.json").write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.3"}}}',
        encoding="utf-8",
    )
    (project / "go.mod").write_text(
        "module example.test/demo\nrequire example.test/lib v1.2.3\n", encoding="utf-8",
    )
    (project / "go.sum").write_text(
        "example.test/lib v1.2.3 h1:abc\n", encoding="utf-8",
    )
    (project / "pom.xml").write_text(
        '<project><properties><spring.version>6.1.2</spring.version></properties>'
        '<dependencies><dependency><groupId>org.springframework</groupId>'
        '<artifactId>spring-core</artifactId><version>${spring.version}</version>'
        '</dependency></dependencies></project>',
        encoding="utf-8",
    )
    (project / "build.gradle").write_text(
        'dependencies {\n implementation "com.google.guava:guava:33.0.0-jre"\n}\n',
        encoding="utf-8",
    )
    (project / "gradle.lockfile").write_text(
        "com.google.guava:guava:33.0.0-jre=runtimeClasspath\n", encoding="utf-8",
    )
    (project / "Cargo.toml").write_text(
        '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nserde="1.0.197"\n',
        encoding="utf-8",
    )
    (project / "Cargo.lock").write_text(
        '[[package]]\nname="serde"\nversion="1.0.197"\n', encoding="utf-8",
    )

    execution = run_tool(gateway, "inspect_dependencies", {})

    assert execution.status.value == "completed"
    output = execution.output
    assert output["ecosystems"] == ["cargo", "go", "gradle", "maven", "node", "python"]
    direct = {(item["ecosystem"], item["name"]): item for item in output["dependencies"]}
    assert direct[("python", "flask")]["resolved_version"] == "3.0.0"
    assert direct[("python", "flask")]["pinned"] is True
    assert direct[("python", "httpx")]["pinned"] is False
    assert direct[("node", "express")]["resolved_version"] == "4.18.3"
    assert direct[("node", "vitest")]["scope"] == "dev"
    assert direct[("go", "example.test/lib")]["provenance"] == {"file_path": "go.mod", "line": 2}
    assert direct[("maven", "org.springframework:spring-core")]["version_spec"] == "6.1.2"
    assert direct[("gradle", "com.google.guava:guava")]["resolved_version"] == "33.0.0-jre"
    assert direct[("cargo", "serde")]["resolved_version"] == "1.0.197"
    assert all(len(item["sha256"]) == 64 for item in output["manifests"])
    assert all(item["status"] == "parsed" for item in output["manifests"])
    assert output["coverage"]["parse_errors"] == 0
    assert execution.artifacts[0].artifact_type == "dependency_inventory"


def test_dependency_inspection_reports_missing_and_unparsed_locks_honestly(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "package.json").write_text(
        '{"dependencies":{"express":"^4.18.0"}}', encoding="utf-8",
    )
    (project / "pnpm-lock.yaml").write_text(
        "lockfileVersion: '9.0'\npackages: {}\n", encoding="utf-8",
    )
    (project / "requirements.txt").write_text("django>=5\n", encoding="utf-8")

    execution = run_tool(gateway, "inspect_dependencies", {})

    coverage = {item["ecosystem"]: item["status"] for item in execution.output["lock_coverage"]}
    assert coverage["node"] == "unverifiable"
    assert coverage["python"] == "missing"
    assert execution.output["coverage"]["recognized_unparsed"] == 1
    assert any("exact-version parser is not implemented" in gap for gap in execution.output["coverage"]["gaps"])
    assert any("No lockfile found for python" in gap for gap in execution.output["coverage"]["gaps"])


def test_dependency_inspection_can_filter_ecosystem_and_lists_requirements_files(tmp_path):
    project, gateway = build_gateway(tmp_path)
    (project / "requirements-dev.txt").write_text("pytest==9.0.2\n", encoding="utf-8")
    (project / "package.json").write_text('{"dependencies":{"react":"19.0.0"}}', encoding="utf-8")

    listed = run_tool(gateway, "list_source_files", {"glob": "requirements*"})
    execution = run_tool(gateway, "inspect_dependencies", {"ecosystem": "python"})

    assert listed.output["files"] == ["requirements-dev.txt"]
    assert execution.output["ecosystems"] == ["python"]
    assert execution.output["dependencies"][0]["name"] == "pytest"
    assert all(item["ecosystem"] == "python" for item in execution.output["manifests"])


def test_dependency_filter_is_applied_before_manifest_limit(tmp_path):
    project, gateway = build_gateway(tmp_path)
    for index in range(4):
        nested = project / f"node-{index}"
        nested.mkdir()
        (nested / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    (project / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    execution = run_tool(gateway, "inspect_dependencies", {
        "ecosystem": "python", "max_manifests": 1,
    })

    assert [item["file_path"] for item in execution.output["manifests"]] == ["requirements.txt"]
    assert execution.output["coverage"]["truncated"] is False
