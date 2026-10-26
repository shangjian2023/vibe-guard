"""tree-sitter 网关的离线韧性与配置行为。"""

from __future__ import annotations

import pytest

from core.languages import tree_sitter_gateway as gateway


class _SentinelParser:
    pass


def _raise_download_error(language):
    from tree_sitter_language_pack.exceptions import DownloadError

    raise DownloadError("network blocked")


@pytest.mark.usefixtures("gateway_clean_state")
class TestParserForDegradation:
    def test_download_blocked_returns_none_and_caches(self, gateway_clean_state, monkeypatch):
        calls = []

        def fake_get_parser(name):
            calls.append(name)
            return _raise_download_error(name)

        monkeypatch.setattr(gateway_clean_state, "get_parser", fake_get_parser)
        assert gateway_clean_state.parser_for("typescript") is None
        assert gateway_clean_state.parser_for("typescript") is None
        assert calls == ["typescript"], "失败必须按语言负缓存，避免逐文件重复退避"

    def test_disable_env_short_circuits(self, gateway_clean_state, monkeypatch):
        def unexpected(name):  # pragma: no cover - 不应被调用
            raise AssertionError("disabled 时不得尝试获取解析器")

        monkeypatch.setattr(gateway_clean_state, "get_parser", unexpected)
        monkeypatch.setenv("VIBE_SEC_DISABLE_TREE_SITTER", "1")
        assert gateway_clean_state.parser_for("python") is None

    def test_success_returns_parser(self, gateway_clean_state, monkeypatch):
        sentinel = _SentinelParser()
        monkeypatch.setattr(gateway_clean_state, "get_parser", lambda name: sentinel)
        assert gateway_clean_state.parser_for("tsx") is sentinel


@pytest.mark.usefixtures("gateway_clean_state")
class TestCacheDirConfiguration:
    def test_env_cache_dir_applied_once_via_configure(self, gateway_clean_state, monkeypatch, tmp_path):
        captured = []

        def fake_configure(config):
            captured.append(config)

        monkeypatch.setattr(gateway_clean_state, "configure", fake_configure)
        monkeypatch.setenv("VIBE_SEC_TREE_SITTER_CACHE", str(tmp_path))
        monkeypatch.setattr(gateway_clean_state, "get_parser", lambda name: _SentinelParser())

        gateway_clean_state.parser_for("python")
        gateway_clean_state.parser_for("python")

        assert len(captured) == 1, "configure 只应执行一次"
        assert captured[0].cache_dir == str(tmp_path)

    def test_no_env_means_no_configure(self, gateway_clean_state, monkeypatch):
        def unexpected(config):  # pragma: no cover - 不应被调用
            raise AssertionError("未设置缓存目录时不应调用 configure")

        monkeypatch.setattr(gateway_clean_state, "configure", unexpected)
        monkeypatch.setattr(gateway_clean_state, "get_parser", lambda name: _SentinelParser())
        assert gateway_clean_state.parser_for("python") is not None


@pytest.mark.usefixtures("gateway_clean_state")
class TestWarmupAndStatus:
    def test_warmup_reports_cached_and_downloaded(self, gateway_clean_state, monkeypatch):
        monkeypatch.setattr(
            gateway_clean_state, "downloaded_languages", lambda: ["python"]
        )
        downloaded = []

        def fake_download(names):
            downloaded.extend(names)
            return len(names)

        monkeypatch.setattr(gateway_clean_state, "download", fake_download)
        result = gateway_clean_state.warmup(["python", "typescript"])
        assert result["status"] == "ready"
        assert result["languages"]["python"] == "cached"
        assert result["languages"]["typescript"] in {"downloaded", "download_claimed"}
        assert downloaded == ["typescript"], "已缓存语言不应重复下载"

    def test_warmup_download_failure_is_structured_not_raised(self, gateway_clean_state, monkeypatch):
        monkeypatch.setattr(gateway_clean_state, "downloaded_languages", lambda: [])

        def failing_download(names):
            from tree_sitter_language_pack.exceptions import DownloadError

            raise DownloadError("blocked")

        monkeypatch.setattr(gateway_clean_state, "download", failing_download)
        result = gateway_clean_state.warmup(["typescript"])
        assert result["status"] == "partial"
        assert result["languages"]["typescript"].startswith("failed:")

    def test_status_shape_and_hint(self, gateway_clean_state, monkeypatch):
        monkeypatch.setattr(gateway_clean_state, "downloaded_languages", lambda: list(gateway.DEFAULT_LANGUAGES))
        monkeypatch.setattr(
            gateway_clean_state, "_effective_cache_dir", lambda: "/cache"
        )
        snapshot = gateway_clean_state.status()
        assert snapshot["all_ready"] is True
        assert snapshot["cache_dir"] == "/cache"
        assert all(snapshot["languages"].values())

        monkeypatch.setattr(gateway_clean_state, "downloaded_languages", lambda: [])
        degraded = gateway_clean_state.status()
        assert degraded["all_ready"] is False
        assert "VIBE_SEC_TREE_SITTER_CACHE" in degraded["hint"]

    def test_disable_env_reported_in_status(self, gateway_clean_state, monkeypatch):
        monkeypatch.setenv("VIBE_SEC_DISABLE_TREE_SITTER", "1")
        snapshot = gateway_clean_state.status()
        assert snapshot["enabled"] is False
        assert snapshot["all_ready"] is False
