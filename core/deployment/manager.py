"""Deterministic local setup, update, and diagnostics for the Skill runtime."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ..languages.tree_sitter_gateway import status as tree_sitter_status
from ..languages.tree_sitter_gateway import warmup as tree_sitter_warmup
from ..tool_fabric.image_preflight import (
    ContainerImagePreflight,
    ImageRequirement,
)


class DeploymentManager:
    def __init__(
        self,
        *,
        root: Optional[str] = None,
        manifest_path: Optional[str] = None,
        docker_binary: str = "docker",
    ):
        self.root = Path(root).resolve() if root else Path(__file__).resolve().parents[2]
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else (
            self.root / "manifests" / "tool-images.lock.json"
        )
        self.docker_binary = docker_binary
        self.manifest = self._load_manifest()
        self.images = {str(item["id"]): dict(item) for item in self.manifest["images"]}

    def doctor(self) -> Dict[str, Any]:
        docker = self._docker_status()
        image_results = [self._inspect_image(item) for item in self.manifest["images"]]
        required = [item for item in image_results if item["default_install"]]
        required_ready = bool(docker["daemon_available"]) and all(
            bool(item["available"]) for item in required
        )
        required_gaps = [
            item["id"] for item in image_results
            if item["default_install"] and not item["available"]
        ]
        optional_gaps = [
            item["id"] for item in image_results
            if not item["default_install"] and not item["available"]
        ]
        llm_variables = ["VIBE_SEC_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"]
        return {
            "contract_version": "vibe-sec.doctor.v1",
            "status": "ready" if required_ready else "not_ready",
            "release": self.manifest.get("release"),
            "platform": {
                "system": platform.system(),
                "machine": platform.machine(),
                "python": platform.python_version(),
                "python_supported": sys.version_info >= (3, 11),
            },
            "docker": docker,
            "images": image_results,
            "llm": {
                "configured": any(os.getenv(name) for name in llm_variables),
                "accepted_environment_variables": llm_variables,
                "credential_values_exposed": False,
            },
            "tree_sitter": tree_sitter_status(),
            "required_gaps": required_gaps,
            "optional_gaps": optional_gaps,
            "workspace": {
                "root": str(self.root),
                "free_bytes": shutil.disk_usage(self.root).free,
            },
        }

    def setup(
        self,
        *,
        include: Optional[Iterable[str]] = None,
        include_codeql: bool = False,
        force: bool = False,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        selected = self._selected_images(include, include_codeql)
        before = self.doctor()
        actions: List[Dict[str, Any]] = []
        docker = before["docker"]
        if not docker["daemon_available"]:
            return {
                "contract_version": "vibe-sec.setup.v1",
                "status": "blocked",
                "reason": docker["error"] or "Docker daemon is unavailable",
                "selected": [item["id"] for item in selected],
                "actions": actions,
                "doctor": before,
            }
        for item in selected:
            current = self._inspect_image(item)
            if current["available"] and not force:
                actions.append({"id": item["id"], "status": "already_ready"})
                continue
            command = [
                self.docker_binary,
                "build",
                "--progress=plain",
                "-t",
                str(item["image"]),
                str((self.root / str(item["build_context"])).resolve()),
            ]
            if force:
                command.insert(2, "--pull")
            if dry_run:
                actions.append({
                    "id": item["id"], "status": "planned", "command": command,
                    "artifacts": [artifact["path"] for artifact in item.get("artifacts", [])],
                })
                continue
            dependency_failure = next((
                action for action in actions
                if action.get("id") in item.get("depends_on", [])
                and action.get("status") in {"failed", "blocked"}
            ), None)
            if dependency_failure:
                actions.append({
                    "id": item["id"], "status": "blocked",
                    "reason": f"Dependency failed: {dependency_failure['id']}",
                })
                continue
            try:
                artifacts = [self._prepare_artifact(value) for value in item.get("artifacts", [])]
            except (OSError, ValueError) as exc:
                actions.append({"id": item["id"], "status": "failed", "reason": str(exc)})
                continue
            completed = subprocess.run(
                command,
                cwd=str(self.root),
                capture_output=True,
                text=True,
                timeout=1_800,
                check=False,
            )
            accepted = self._inspect_image(item)
            status = "installed" if completed.returncode == 0 and accepted["available"] else "failed"
            failure_reason = (
                accepted["reason"]
                if completed.returncode == 0
                else (completed.stderr.strip() or f"Docker build exited with {completed.returncode}")[-2_000:]
            )
            actions.append({
                "id": item["id"],
                "status": status,
                "exit_code": completed.returncode,
                "reason": failure_reason if status == "failed" else "Image installed and accepted",
                "artifacts": artifacts,
                "log_tail": (completed.stdout + "\n" + completed.stderr)[-4_000:],
            })
        after = before if dry_run else self.doctor()
        failed = [item for item in actions if item["status"] in {"failed", "blocked"}]
        report = {
            "contract_version": "vibe-sec.setup.v1",
            "status": "planned" if dry_run else ("completed" if not failed else "partial"),
            "release": self.manifest.get("release"),
            "selected": [item["id"] for item in selected],
            "actions": actions,
            "doctor": after,
        }
        if not dry_run:
            # 解析器预热失败不阻塞镜像安装结果，仅作为附加状态报告。
            report["tree_sitter_warmup"] = tree_sitter_warmup()
            self._write_state(report)
        return report

    def _selected_images(
        self,
        include: Optional[Iterable[str]],
        include_codeql: bool,
    ) -> List[Dict[str, Any]]:
        requested = list(dict.fromkeys(str(item) for item in (include or []) if str(item)))
        if requested:
            unknown = sorted(set(requested) - set(self.images))
            if unknown:
                raise ValueError("Unknown tool image ids: " + ", ".join(unknown))
            selected_ids = set(requested)
        else:
            selected_ids = {
                str(item["id"]) for item in self.manifest["images"] if item.get("default_install")
            }
        if include_codeql:
            selected_ids.add("codeql")
        changed = True
        while changed:
            changed = False
            for image_id in list(selected_ids):
                for dependency in self.images[image_id].get("depends_on", []):
                    if dependency not in selected_ids:
                        selected_ids.add(dependency)
                        changed = True
        return [item for item in self.manifest["images"] if item["id"] in selected_ids]

    def _inspect_image(self, item: Dict[str, Any]) -> Dict[str, Any]:
        requirement = ImageRequirement(
            str(item["image"]),
            set(item.get("capabilities", [])),
            str(item.get("image_version", "")),
            dict(item.get("tool_versions", {})),
        )
        result = ContainerImagePreflight(docker_binary=self.docker_binary).inspect(requirement)
        return {
            "id": item["id"],
            "default_install": bool(item.get("default_install")),
            **result.to_dict(),
        }

    def _docker_status(self) -> Dict[str, Any]:
        binary = shutil.which(self.docker_binary)
        if not binary:
            return {
                "binary": None, "client_available": False, "daemon_available": False,
                "server_version": "", "error": f"Container runtime not found: {self.docker_binary}",
            }
        try:
            completed = subprocess.run(
                [self.docker_binary, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {
                "binary": binary, "client_available": True, "daemon_available": False,
                "server_version": "", "error": str(exc),
            }
        return {
            "binary": binary,
            "client_available": True,
            "daemon_available": completed.returncode == 0,
            "server_version": completed.stdout.strip() if completed.returncode == 0 else "",
            "error": "" if completed.returncode == 0 else completed.stderr.strip(),
        }

    def _prepare_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        target = (self.root / str(artifact["path"])).resolve()
        target.relative_to(self.root)
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = str(artifact["sha256"]).lower()
        if target.is_file() and _sha256(target) == expected:
            return {"path": str(target), "status": "cached", "sha256": expected}
        offset = target.stat().st_size if target.is_file() else 0
        request = urllib.request.Request(
            str(artifact["url"]),
            headers={
                "User-Agent": "vibe-sec-installer/0.5.0",
                **({"Range": f"bytes={offset}-"} if offset else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                append = offset > 0 and getattr(response, "status", 200) == 206
                with target.open("ab" if append else "wb") as handle:
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        handle.write(chunk)
        except Exception as exc:
            raise OSError(f"Artifact download failed; partial cache preserved at {target}: {exc}") from exc
        actual = _sha256(target)
        if actual != expected:
            target.unlink(missing_ok=True)
            raise ValueError(
                f"Artifact checksum mismatch for {artifact['url']}: expected {expected}, received {actual}"
            )
        return {"path": str(target), "status": "downloaded", "sha256": actual}

    def _write_state(self, report: Dict[str, Any]) -> None:
        state_dir = self.root / ".vibe-sec"
        state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "vibe-sec.install-state.v1",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "release": self.manifest.get("release"),
            "status": report.get("status"),
            "selected": report.get("selected", []),
            "doctor": report.get("doctor", {}),
        }
        (state_dir / "install-state.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8",
        )

    def _load_manifest(self) -> Dict[str, Any]:
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid tool image manifest: {exc}") from exc
        if payload.get("schema_version") != "vibe-sec.tool-images.v1":
            raise ValueError("Unsupported tool image manifest schema")
        if not isinstance(payload.get("images"), list) or not payload["images"]:
            raise ValueError("Tool image manifest must contain images")
        return payload


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
