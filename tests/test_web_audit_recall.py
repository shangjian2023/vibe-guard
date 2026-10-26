"""VAmPI 靶场短板类型的静态召回回归（弱密钥之外的业务语义类漏洞）。

背景：docs/VAMPI_TEST_REPORT.md 记录 VAmPI 6 个已知漏洞仅命中 SQL 注入
（f-string 形态）。本文件锁定三类改进的召回与误报控制：

1. SQL 注入的非 f-string 形态：调用外字符串拼接、% 中置格式化；
2. 特权字段自赋值（mass_assignment）：admin/role 等字段直接取自请求数据；
3. 明文密码比较（plaintext_password_comparison）：与存储凭据对象的 == 比对。
"""

from __future__ import annotations

import asyncio

from main import run_audit

from agents.audit_agent import AuditAgent
from agents.remediation_agent import PROFILES as REMEDIATION_PROFILES
from agents.verification_agent import VerificationAgent


def _scan_patterns(content: str) -> set:
    import re

    agent = AuditAgent()
    found = set()
    for vuln, info in agent.web_vulnerability_patterns.items():
        for pattern in info["patterns"]:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                found.add(vuln)
    return found


VAMPI_BOOKS = (
    'from flask import request\n'
    'from app import db\n'
    '\n'
    '\n'
    'def get_all_books():\n'
    '    query = "SELECT * FROM books WHERE title = \'" + request.args.get("title") + "\'"\n'
    '    return db.execute(query)\n'
    '\n'
    '\n'
    'def get_book_by_id(book_id):\n'
    '    return db.execute("SELECT * FROM books WHERE id = %s" % book_id)\n'
)

VAMPI_USERS = (
    'from flask import request\n'
    'from app import db\n'
    '\n'
    '\n'
    'def register():\n'
    '    data = request.get_json()\n'
    '    user = User(username=data["username"], password=data["password"],\n'
    '                admin=data.get("admin", False))\n'
    '    db.add(user)\n'
    '\n'
    '\n'
    'def login():\n'
    '    data = request.get_json()\n'
    '    user = User.query.filter_by(username=data["username"]).first()\n'
    '    if data["password"] == user.password:\n'
    '        return "ok"\n'
    '    return "fail"\n'
)

VAMPI_CONFIG = "SECRET_KEY = 'random'\n"

SAFE_APP = (
    'from flask import request\n'
    'from app import db\n'
    '\n'
    '\n'
    'def get_book(book_id):\n'
    '    row = db.execute("SELECT * FROM books WHERE id = ?", (book_id,))\n'
    '    if row.owner_id != current_user.id:\n'
    '        abort(403)\n'
    '    return row\n'
    '\n'
    '\n'
    'def register():\n'
    '    data = request.get_json()\n'
    '    if data["password"] == data["confirm"]:\n'
    '        user = User(username=data["username"], admin=False)\n'
    '        db.add(user)\n'
)


class TestPatternRecall:
    def test_sql_concat_outside_call_detected(self):
        assert "sql_injection" in _scan_patterns(VAMPI_BOOKS)

    def test_mass_assignment_detected(self):
        assert "mass_assignment" in _scan_patterns(VAMPI_USERS)

    def test_plaintext_password_comparison_detected(self):
        assert "plaintext_password_comparison" in _scan_patterns(VAMPI_USERS)

    def test_safe_parameterized_and_allowlisted_code_not_flagged(self):
        found = _scan_patterns(SAFE_APP)
        assert "sql_injection" not in found
        assert "mass_assignment" not in found
        assert "plaintext_password_comparison" not in found

    def test_new_types_have_remediation_and_verification_support(self):
        for vuln_type in ("mass_assignment", "plaintext_password_comparison"):
            assert vuln_type in REMEDIATION_PROFILES
            assert vuln_type in VerificationAgent.SUPPORTED_TYPES
            assert vuln_type in VerificationAgent.STATIC_CONFIRMABLE


def _write_fixture(tmp_path):
    (tmp_path / "api_views").mkdir()
    (tmp_path / "config.py").write_text(VAMPI_CONFIG, encoding="utf-8")
    (tmp_path / "api_views" / "books.py").write_text(VAMPI_BOOKS, encoding="utf-8")
    (tmp_path / "api_views" / "users.py").write_text(VAMPI_USERS, encoding="utf-8")


def _vulnerability_types(result) -> set:
    data = result
    for key in ("findings", "verified_findings"):
        if isinstance(data, dict) and isinstance(data.get(key), list):
            return {str(item.get("vulnerability_type")) for item in data[key]}
    return set()


def test_vampi_style_end_to_end_recall(tmp_path):
    _write_fixture(tmp_path)
    result = asyncio.run(run_audit(project_path=str(tmp_path), use_llm=False))
    types = _vulnerability_types(result)
    assert {"sql_injection", "mass_assignment", "plaintext_password_comparison"} <= types
    # 弱密钥检测早已覆盖 SECRET_KEY（大小写不敏感），一并锁定回归。
    assert "api_key" in types


def test_safe_end_to_end_no_new_false_positives(tmp_path):
    (tmp_path / "app.py").write_text(SAFE_APP, encoding="utf-8")
    result = asyncio.run(run_audit(project_path=str(tmp_path), use_llm=False))
    types = _vulnerability_types(result)
    assert "sql_injection" not in types
    assert "mass_assignment" not in types
    assert "plaintext_password_comparison" not in types
