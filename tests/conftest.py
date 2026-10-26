"""Shared pytest fixtures and probes for the test suite."""

from __future__ import annotations

import threading

import pytest


def _probe_parser(language: str, timeout_seconds: float = 90.0) -> bool:
    """探测解析器是否可获得：缓存命中免网络，否则后台线程限时尝试下载。

    供 skipif 使用——离线环境探测失败后由网关负缓存，后续模块的探测
    即时返回，不会反复退避。
    """
    from core.languages import tree_sitter_gateway as gateway

    if gateway.language_ready(language):
        return True
    if gateway.get_parser is None:
        return False

    outcome: dict = {}

    def _attempt():
        try:
            outcome["parser"] = gateway.parser_for(language)
        except Exception:  # pragma: no cover - parser_for 自身不抛出，防御性兜底
            outcome["parser"] = None

    thread = threading.Thread(target=_attempt, daemon=True)
    thread.start()
    thread.join(timeout_seconds)
    return bool(outcome.get("parser"))


def tree_sitter_ready(language: str) -> bool:
    return _probe_parser(language)


@pytest.fixture
def gateway_clean_state(monkeypatch):
    """每个用例重置网关进程内状态（负缓存与一次性配置）。"""
    from core.languages import tree_sitter_gateway as gateway

    gateway._reset_state()
    monkeypatch.delenv("VIBE_SEC_TREE_SITTER_CACHE", raising=False)
    monkeypatch.delenv("VIBE_SEC_DISABLE_TREE_SITTER", raising=False)
    yield gateway
    gateway._reset_state()
