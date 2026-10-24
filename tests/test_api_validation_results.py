import asyncio
from datetime import datetime, timedelta

import httpx
import pytest
from fastapi import HTTPException

from api import server


@pytest.fixture(autouse=True)
def isolated_api_state(tmp_path):
    original_store_path = server.api_state_store.path
    server.configure_state_store(tmp_path / "api-state.sqlite3")
    server.clear_api_state()
    yield
    server.configure_state_store(original_store_path)


def _seed_finding(project_id: str = "project-validation") -> tuple[str, server.Finding]:
    task_id = "task-validation"
    server.audit_tasks_db[task_id] = server.AuditTask(
        id=task_id,
        project_id=project_id,
        status=server.AuditTaskStatus.COMPLETED,
        created_at=datetime.now(),
    )
    finding = server.Finding(
        id="finding-sqli",
        task_id=task_id,
        vulnerability_type="sql_injection",
        severity="high",
        confidence=0.6,
        title="Possible SQL injection",
        file_path="models/user_model.py",
        line_start=72,
        line_end=72,
        description="User input is concatenated into a query.",
        evidence=[{"type": "code_snippet", "content": "SELECT ...", "line": 72}],
        evidence_bundle={"items": [], "gaps": ["dynamic validation unavailable"], "level": 1},
    )
    server.findings_db[task_id] = [finding]
    return task_id, finding


def _verified_update(candidate_passed: bool = True) -> server.FindingValidationUpdate:
    return server.FindingValidationUpdate(
        verification_status=server.FindingVerificationStatus.VERIFIED,
        verification_level=4,
        verification_predicate=(
            "The injected lookup returns a user while an unknown username returns 404."
        ),
        evidence=server.DynamicValidationEvidence(
            method="service",
            source="authorized-vampi-lab",
            outcome="supported",
            summary="A boolean predicate changed the lookup result without authentication.",
            candidate_case=server.ValidationCase(
                label="boolean predicate",
                expected_status=200,
                observed_status=200,
                passed=candidate_passed,
                summary="The predicate returned a user record.",
            ),
            positive_control=server.ValidationCase(
                label="known user",
                expected_status=200,
                observed_status=200,
                passed=True,
                summary="The endpoint returns the known fixture user.",
            ),
            negative_control=server.ValidationCase(
                label="unknown user",
                expected_status=404,
                observed_status=404,
                passed=True,
                summary="An unrelated username remains absent.",
            ),
        ),
    )


def test_validation_result_preserves_dynamic_evidence_and_confirms_finding(monkeypatch):
    task_id, finding = _seed_finding()
    monkeypatch.setenv("VIBE_SEC_VALIDATION_TOKEN", "test-validation-token")

    async def submit_and_read():
        transport = httpx.ASGITransport(app=server.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            updated = await client.post(
                f"/api/audit-tasks/{task_id}/findings/{finding.id}/validation",
                headers={"X-Vibe-Sec-Validation-Token": "test-validation-token"},
                json=_verified_update().model_dump(mode="json"),
            )
            stored = await client.get(f"/api/audit-tasks/{task_id}/findings")
            return updated, stored

    updated, stored = asyncio.run(submit_and_read())
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["verification_status"] == "verified"
    assert updated_body["verification_level"] == 4
    assert updated_body["verification_predicate"]
    assert updated_body["evidence_bundle"]["gaps"] == []
    assert len(updated_body["validation_sessions"]) == 1
    assert updated_body["validation_sessions"][0]["candidate_case"]["passed"] is True
    assert updated_body["evidence_bundle"]["items"][-1]["outcome"] == "supported"
    assert stored.status_code == 200
    assert stored.json()[0]["verification_status"] == "verified"
    assert stored.json()[0]["validation_sessions"][0]["verification_level"] == 4


def test_validation_result_fails_closed_without_a_configured_token():
    task_id, finding = _seed_finding()

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(server.record_finding_validation(task_id, finding.id, _verified_update()))

    assert exc_info.value.status_code == 503


def test_validation_result_rejects_incomplete_controls(monkeypatch):
    task_id, finding = _seed_finding()
    monkeypatch.setenv("VIBE_SEC_VALIDATION_TOKEN", "test-validation-token")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(server.record_finding_validation(
            task_id,
            finding.id,
            _verified_update(candidate_passed=False),
            x_vibe_sec_validation_token="test-validation-token",
        ))

    assert exc_info.value.status_code == 422
    assert finding.verification_status == "needs_evidence"
    assert not finding.validation_sessions


def test_validation_result_requires_a_completed_audit_task(monkeypatch):
    task_id, finding = _seed_finding()
    server.audit_tasks_db[task_id].status = server.AuditTaskStatus.RUNNING
    monkeypatch.setenv("VIBE_SEC_VALIDATION_TOKEN", "test-validation-token")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(server.record_finding_validation(
            task_id,
            finding.id,
            _verified_update(),
            x_vibe_sec_validation_token="test-validation-token",
        ))

    assert exc_info.value.status_code == 409


def test_project_finding_queue_clusters_completed_task_results():
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="Queue fixture",
        path="/tmp/queue-fixture",
    )))
    # Windows 时钟分辨率约 15ms，连续 datetime.now() 可能取到相同时间戳，
    # 导致"最新任务"排序不稳定，这里用显式时间戳保证跨平台确定性
    first_task = server.AuditTask(
        id="task-one", project_id=project.id, status=server.AuditTaskStatus.COMPLETED,
        created_at=datetime.now() - timedelta(seconds=10),
    )
    second_task = server.AuditTask(
        id="task-two", project_id=project.id, status=server.AuditTaskStatus.COMPLETED,
        created_at=datetime.now(),
    )
    server.audit_tasks_db[first_task.id] = first_task
    server.audit_tasks_db[second_task.id] = second_task
    first = server.Finding(
        id="sqli-one", task_id=first_task.id, vulnerability_type="sql_injection",
        severity="high", confidence=0.8, title="Unsafe query", file_path="service.py",
        line_start=20, line_end=20, description="Input reaches a query.",
        evidence=[{"type": "code_snippet", "content": "db.execute(query)"}],
    )
    duplicate = first.model_copy(update={"id": "sqli-two", "task_id": second_task.id, "line_start": 21, "line_end": 21})
    server.findings_db[first_task.id] = [first]
    server.findings_db[second_task.id] = [duplicate]

    latest_queue = asyncio.run(server.get_project_finding_queue(project.id))
    queue = asyncio.run(server.get_project_finding_queue(project.id, include_history=True))

    assert latest_queue.task_id == second_task.id
    assert latest_queue.includes_history is False
    assert latest_queue.raw_findings_count == 1
    assert latest_queue.review_findings_count == 1
    assert queue.raw_findings_count == 2
    assert queue.review_findings_count == 1
    assert queue.duplicate_findings_count == 1
    assert queue.includes_history is True
    assert queue.findings[0].duplicate_count == 2
    assert set(queue.findings[0].source_task_ids) == {first_task.id, second_task.id}


def test_api_state_survives_store_reinitialization(monkeypatch):
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="Validation fixture",
        path="/tmp/validation-fixture",
    )))
    task_id = "task-persistence"
    server.audit_tasks_db[task_id] = server.AuditTask(
        id=task_id,
        project_id=project.id,
        status=server.AuditTaskStatus.PENDING,
        created_at=datetime.now(),
    )
    server.api_state_store.save_audit_task(server.audit_tasks_db[task_id])

    async def fake_run_audit(**_kwargs):
        return {
            "findings": [{
                "id": "finding-sqli",
                "vulnerability_type": "sql_injection",
                "severity": "high",
                "confidence": 0.6,
                "title": "Possible SQL injection",
                "file_path": "models/user_model.py",
                "line_start": 72,
                "line_end": 72,
                "description": "User input is concatenated into a query.",
            }],
            "remediation_bundles": [{
                "finding_id": "finding-sqli",
                "vulnerability_type": "sql_injection",
                "title": "Use parameterized queries",
                "severity": "high",
                "file_path": "models/user_model.py",
                "line_start": 72,
                "line_end": 72,
                "ai_patch_prompt": "Replace string interpolation with parameter binding.",
                "patch_strategy": "parameterization",
                "patch_constraints": [],
                "retest_plan": [],
                "acceptance_criteria": ["Unknown usernames still return 404."],
            }],
        }

    monkeypatch.setattr("main.run_audit", fake_run_audit)
    asyncio.run(server.run_audit_task(task_id, project, use_llm=False, output_format="json"))
    finding = server.findings_db[task_id][0]
    monkeypatch.setenv("VIBE_SEC_VALIDATION_TOKEN", "test-validation-token")

    updated = asyncio.run(server.record_finding_validation(
        task_id,
        finding.id,
        _verified_update(),
        x_vibe_sec_validation_token="test-validation-token",
    ))
    database_path = server.api_state_store.path
    server.configure_state_store(database_path)

    assert server.projects_db[project.id].name == "Validation fixture"
    assert server.audit_tasks_db[task_id].status == server.AuditTaskStatus.COMPLETED
    restored_finding = server.findings_db[task_id][0]
    assert restored_finding.verification_status == "verified"
    assert restored_finding.validation_sessions[0]["id"] == updated.validation_sessions[0]["id"]
    assert restored_finding.evidence_bundle["items"][-1]["outcome"] == "supported"
    assert server.remediation_db[task_id][0].patch_strategy == "parameterization"


def test_remediation_endpoint_keeps_finding_verification_and_proposal_state():
    task_id, finding = _seed_finding()
    finding.verification_status = "static_only"
    server.remediation_db[task_id] = [server.RemediationBundle(
        finding_id=finding.id,
        vulnerability_type=finding.vulnerability_type,
        title="Use parameterized queries",
        severity=finding.severity,
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        ai_patch_prompt="Replace string interpolation with parameter binding.",
        patch_strategy="parameterization",
        patch_constraints=[],
        retest_plan=[],
        acceptance_criteria=["Unknown usernames still return 404."],
    )]

    bundles = asyncio.run(server.get_remediations(task_id))

    assert bundles[0].verification_status == "static_only"
    assert bundles[0].proposal_only is True


def test_store_reinitialization_marks_interrupted_task_failed():
    project = asyncio.run(server.create_project(server.ProjectCreate(
        name="Interrupted audit fixture",
        path="/tmp/interrupted-audit-fixture",
    )))
    task_id = "task-interrupted"
    server.audit_tasks_db[task_id] = server.AuditTask(
        id=task_id,
        project_id=project.id,
        status=server.AuditTaskStatus.RUNNING,
        created_at=datetime.now(),
        started_at=datetime.now(),
    )
    server.api_state_store.save_audit_task(server.audit_tasks_db[task_id])

    server.configure_state_store(server.api_state_store.path)

    restored = server.audit_tasks_db[task_id]
    assert restored.status == server.AuditTaskStatus.FAILED
    assert restored.completed_at is not None
    assert "process restart" in restored.error
