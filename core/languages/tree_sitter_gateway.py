"""tree-sitter 解析器统一网关：离线韧性、共享缓存与预热。

tree_sitter_language_pack 在解析器未缓存时会从 GitHub 下载平台解析器包，
受限网络下抛出 DownloadError 且自带重试退避（单次可阻塞数十秒）。此前
各调用点只处理了 ImportError，运行期下载失败会击穿整个审计通道。

本网关集中提供：

- ``parser_for(language)``：安全获取解析器，不可用时返回 ``None``，
  失败按语言进程内负缓存，避免逐文件重复退避；
- ``VIBE_SEC_TREE_SITTER_CACHE``：指定共享缓存目录，支持离线分发与
  多项目复用；
- ``VIBE_SEC_DISABLE_TREE_SITTER``：置 ``1`` 时跳过一切下载尝试，
  全部通道立即走降级路径；
- ``warmup()`` / ``status()``：供 setup 预热与 doctor 报告。

注意：``has_language()`` 是静态注册表检查（离线也返回 True），缓存探测
必须使用 ``downloaded_languages()``。
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, Optional

try:
    from tree_sitter_language_pack import (
        PackConfig,
        configure,
        downloaded_languages,
        download,
        get_parser,
    )
except ImportError:  # pragma: no cover - 依赖声明存在但运行环境可能缺包
    PackConfig = None  # type: ignore[assignment]
    configure = None  # type: ignore[assignment]
    downloaded_languages = None  # type: ignore[assignment]
    download = None  # type: ignore[assignment]
    get_parser = None  # type: ignore[assignment]

#: 审计通道默认依赖的解析器语言。
DEFAULT_LANGUAGES: tuple = ("python", "typescript", "tsx", "javascript")

ENV_CACHE_DIR = "VIBE_SEC_TREE_SITTER_CACHE"
ENV_DISABLE = "VIBE_SEC_DISABLE_TREE_SITTER"

_failed_languages: set = set()
_configured = False


def _reset_state() -> None:
    """重置进程内状态（测试与 doctor 探测复用）。"""
    global _configured
    _failed_languages.clear()
    _configured = False


def _ensure_configured() -> None:
    global _configured
    if _configured:
        return
    _configured = True
    cache_override = os.getenv(ENV_CACHE_DIR)
    if configure is not None and cache_override:
        configure(PackConfig(cache_dir=cache_override))


def parser_for(language: str):
    """返回指定语言的解析器；不可用（离线、禁用、加载失败）时返回 ``None``。"""
    if get_parser is None or os.getenv(ENV_DISABLE) == "1":
        return None
    _ensure_configured()
    if language in _failed_languages:
        return None
    try:
        return get_parser(language)
    except Exception:
        # DownloadError / DynamicLoadError 等：统一按语言负缓存并降级。
        _failed_languages.add(language)
        return None


def language_ready(language: str) -> bool:
    """快速缓存探测，不触发网络（供测试跳过逻辑与状态报告使用）。"""
    if get_parser is None:
        return False
    _ensure_configured()
    try:
        return language in set(downloaded_languages())
    except Exception:
        return False


def warmup(languages: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """预下载解析器到本地缓存。失败不抛出，逐语言返回结构化状态。"""
    names = [str(name) for name in (languages or DEFAULT_LANGUAGES)]
    result: Dict[str, Any] = {
        "contract_version": "vibe-sec.tree-sitter-warmup.v1",
        "cache_dir": _effective_cache_dir(),
        "languages": {},
    }
    if download is None:
        result["status"] = "unavailable"
        result["reason"] = "tree-sitter-language-pack is not installed"
        return result
    if os.getenv(ENV_DISABLE) == "1":
        result["status"] = "disabled"
        result["reason"] = f"{ENV_DISABLE}=1"
        return result
    _ensure_configured()
    overall = "ready"
    for name in names:
        try:
            if language_ready(name):
                result["languages"][name] = "cached"
                continue
            download([name])
            result["languages"][name] = "downloaded" if language_ready(name) else "download_claimed"
        except Exception as exc:
            overall = "partial"
            result["languages"][name] = f"failed:{type(exc).__name__}"
    result["status"] = overall
    return result


def status() -> Dict[str, Any]:
    """doctor 报告用的解析器就绪状态（不触发网络）。"""
    ready = {name: language_ready(name) for name in DEFAULT_LANGUAGES}
    pack_installed = get_parser is not None
    enabled = pack_installed and os.getenv(ENV_DISABLE) != "1"
    if not pack_installed:
        hint = "tree-sitter-language-pack 未安装，AST 通道全部降级"
    elif not enabled:
        hint = f"{ENV_DISABLE}=1，AST 通道全部降级"
    elif not all(ready.values()):
        missing = [name for name, ok in ready.items() if not ok]
        hint = (
            f"解析器未缓存: {', '.join(missing)}。"
            "在线环境执行 vibe-sec setup 会自动预热；离线环境可设置 "
            f"{ENV_CACHE_DIR} 指向预置缓存目录，或设置 {ENV_DISABLE}=1 跳过下载。"
        )
    else:
        hint = "默认语言解析器已就绪"
    return {
        "contract_version": "vibe-sec.tree-sitter-status.v1",
        "pack_installed": pack_installed,
        "enabled": enabled,
        "cache_dir": _effective_cache_dir(),
        "languages": ready,
        "all_ready": pack_installed and enabled and all(ready.values()),
        "hint": hint,
    }


def _effective_cache_dir() -> Optional[str]:
    if downloaded_languages is None:
        return None
    _ensure_configured()
    try:
        from tree_sitter_language_pack import cache_dir

        return cache_dir()
    except Exception:
        return os.getenv(ENV_CACHE_DIR)
