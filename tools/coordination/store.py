from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def utcnow() -> str:
    """Return an ISO8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_session_id(cwd: str | os.PathLike[str] | None) -> str:
    """Build a stable session id from cwd when a runtime id is unavailable."""
    path = Path(cwd or ".").resolve()
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", path.name).strip("-") or "session"
    digest = hashlib.sha1(str(path).encode("utf-8")).hexdigest()[:12]
    return f"{slug}-{digest}"


def _slugify(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-") or "item"


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _read_text(path: Path, max_chars: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


def _safe_stat_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _extract_skill_metadata(path: Path) -> dict[str, str]:
    text = _read_text(path, max_chars=2500)
    lines = [line.strip() for line in text.splitlines()]

    title = ""
    description = ""
    for line in lines:
        if not title and line.startswith("# "):
            title = line[2:].strip()
            continue
        if line.lower().startswith("description:"):
            description = line.split(":", 1)[1].strip()
            continue
        if title and not description and line and not line.startswith(("#", "-", "`", "|")):
            description = line
            break

    if not title:
        title = path.parent.name

    if not description:
        description = f"Skill from {path.parent}"

    return {"title": title[:120], "description": description[:240]}


def _extract_instruction_metadata(path: Path) -> dict[str, str]:
    text = _read_text(path, max_chars=2500)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    title = path.name
    summary = ""

    for line in lines:
        if line.startswith("# "):
            title = line[2:].strip()[:120]
            continue
        if line.startswith(("##", "###", "-", "*", "`")):
            continue
        summary = line[:240]
        break

    if not summary:
        summary = f"Instruction document from {path.parent}"
    return {"title": title, "summary": summary}


def build_digest_payload(
    *,
    title: str,
    text: str,
    kind: str,
    source_refs: Iterable[str] | None = None,
    generated_by: str = "unknown",
    model: str = "heuristic",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a structured digest payload from free-form text."""
    normalized = text.replace("\r\n", "\n").strip()
    lines = [line.strip() for line in normalized.splitlines() if line.strip()]

    signal_lines: list[str] = []
    open_questions: list[str] = []
    known_constraints: list[str] = []
    next_best_actions: list[str] = []
    do_not_repeat: list[str] = []

    for line in lines:
        lowered = line.lower()
        if len(signal_lines) < 8 and (
            line.startswith(("-", "*", "•"))
            or any(
                token in lowered
                for token in (
                    "critical",
                    "high",
                    "warning",
                    "error",
                    "risk",
                    "finding",
                    "flag",
                    "cve",
                    "todo",
                    "next",
                    "must",
                    "required",
                    "blocked",
                )
            )
        ):
            signal_lines.append(line)
        if len(open_questions) < 5 and ("?" in line or lowered.startswith("open question")):
            open_questions.append(line)
        if len(known_constraints) < 5 and any(
            token in lowered
            for token in ("must", "required", "forbidden", "do not", "limit", "ttl", "scope")
        ):
            known_constraints.append(line)
        if len(next_best_actions) < 5 and any(
            token in lowered for token in ("next", "action", "recommend", "resume", "retry")
        ):
            next_best_actions.append(line)
        if len(do_not_repeat) < 5 and any(
            token in lowered for token in ("duplicate", "already", "cached", "skip", "re-run")
        ):
            do_not_repeat.append(line)

    if not signal_lines:
        signal_lines = lines[: min(8, len(lines))]

    summary_1liner = lines[0][:240] if lines else title[:240]

    return {
        "title": title,
        "kind": kind,
        "summary_1liner": summary_1liner,
        "high_signal_facts": signal_lines,
        "open_questions": open_questions,
        "known_constraints": known_constraints,
        "do_not_repeat": do_not_repeat,
        "next_best_actions": next_best_actions,
        "source_refs": list(source_refs or []),
        "generated_by": generated_by,
        "model": model,
        "confidence": "medium" if signal_lines else "low",
        "metadata": metadata or {},
        "content_sha256": _sha256_text(normalized or title),
        "generated_at": utcnow(),
    }


@dataclass
class CoordinationStore:
    """Filesystem-backed coordination state for multi-tool workflows."""

    project_root: Path
    coordination_root: Path = field(init=False)

    def __post_init__(self) -> None:
        self.project_root = self.project_root.resolve()
        self.coordination_root = self.project_root / "coordination"
        self.coordination_root.mkdir(parents=True, exist_ok=True)
        (self.coordination_root / "sessions").mkdir(exist_ok=True)
        (self.coordination_root / "cache" / "digests").mkdir(parents=True, exist_ok=True)
        (self.coordination_root / "cache" / "skills").mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, project_root: str | os.PathLike[str] | None = None) -> "CoordinationStore":
        root = Path(project_root or os.environ.get("COORD_PROJECT_ROOT") or Path(__file__).resolve().parents[2])
        return cls(root)

    def session_dir(self, session_id: str) -> Path:
        path = self.coordination_root / "sessions" / _slugify(session_id)
        path.mkdir(parents=True, exist_ok=True)
        for name in (
            "handoffs",
            "checkpoints",
            "summaries",
            "skills",
            "instructions",
            "events",
        ):
            (path / name).mkdir(exist_ok=True)
        return path

    def manifest_path(self, session_id: str) -> Path:
        return self.session_dir(session_id) / "session_manifest.json"

    def leader_state_path(self, session_id: str) -> Path:
        return self.session_dir(session_id) / "leader_state.json"

    def artifact_index_path(self, session_id: str) -> Path:
        return self.session_dir(session_id) / "artifact_index.json"

    def events_path(self, session_id: str) -> Path:
        return self.session_dir(session_id) / "events" / "events.jsonl"

    def _read_json(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _display_path(self, path: Path | str) -> str:
        candidate = Path(path).resolve()
        try:
            return str(candidate.relative_to(self.project_root))
        except ValueError:
            return str(candidate)

    def _session_cwd(self, session_id: str | None = None) -> Path:
        if not session_id:
            return self.project_root
        manifest = self.session_manifest(session_id)
        cwd = manifest.get("cwd")
        if cwd:
            return Path(cwd).resolve()
        return self.project_root

    def _ancestor_roots(self, start: Path) -> list[Path]:
        current = start.resolve()
        return [current, *list(current.parents)]

    def _find_existing_dir(self, cwd: Path, dirname: str) -> Path | None:
        for root in self._ancestor_roots(cwd):
            candidate = root / dirname
            if candidate.exists() and candidate.is_dir():
                return candidate
        return None

    def _read_omx_session(self, cwd: Path) -> tuple[Path | None, dict[str, Any]]:
        omx_root = self._find_existing_dir(cwd, ".omx")
        if omx_root is None:
            return None, {}
        session_path = omx_root / "state" / "session.json"
        return session_path, self._read_json(session_path, {})

    def session_manifest(self, session_id: str) -> dict[str, Any]:
        return self._read_json(self.manifest_path(session_id), {})

    def leader_state(self, session_id: str) -> dict[str, Any]:
        return self._read_json(self.leader_state_path(session_id), {})

    def artifact_index(self, session_id: str) -> dict[str, Any]:
        return self._read_json(self.artifact_index_path(session_id), {"artifacts": []})

    def ensure_session(
        self,
        *,
        session_id: str | None,
        cwd: str | os.PathLike[str] | None = None,
        leader: str = "unknown",
        tool: str = "unknown",
        lead_mode: str = "auto",
        status: str = "active",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        actual_id = session_id or stable_session_id(cwd)
        manifest_path = self.manifest_path(actual_id)
        manifest = self._read_json(manifest_path, {})
        now = utcnow()
        resolved_cwd = str(Path(cwd or ".").resolve())

        if not manifest:
            manifest = {
                "session_id": actual_id,
                "mission_id": actual_id,
                "target": Path(resolved_cwd).name,
                "mode": "interactive",
                "lead_mode": lead_mode,
                "current_leader": leader,
                "status": status,
                "cwd": resolved_cwd,
                "created_at": now,
                "updated_at": now,
                "active_tracks": [],
                "tool_roles": {tool: leader} if tool else {},
                "latest_context_digest_ref": None,
                "latest_artifact_index_ref": None,
                "latest_skill_index_ref": None,
                "latest_instruction_index_ref": None,
                "latest_handoff_ref": None,
                "metadata": metadata or {},
            }
        else:
            manifest["updated_at"] = now
            manifest["current_leader"] = leader or manifest.get("current_leader", "unknown")
            manifest["status"] = status or manifest.get("status", "active")
            manifest["lead_mode"] = lead_mode or manifest.get("lead_mode", "auto")
            manifest["cwd"] = resolved_cwd
            manifest.setdefault("tool_roles", {})
            if tool:
                manifest["tool_roles"][tool] = leader
            if metadata:
                manifest.setdefault("metadata", {}).update(metadata)

        self._write_json(manifest_path, manifest)
        return manifest

    def merge_manifest_metadata(self, session_id: str, metadata: dict[str, Any]) -> dict[str, Any]:
        manifest = self.session_manifest(session_id)
        manifest.setdefault("metadata", {}).update(metadata)
        manifest["updated_at"] = utcnow()
        self._write_json(self.manifest_path(session_id), manifest)
        return manifest

    def update_manifest_ref(self, session_id: str, key: str, value: str | None) -> dict[str, Any]:
        manifest = self.session_manifest(session_id)
        manifest[key] = value
        manifest["updated_at"] = utcnow()
        self._write_json(self.manifest_path(session_id), manifest)
        return manifest

    def append_event(self, session_id: str, event_type: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        event = {
            "event_type": event_type,
            "session_id": session_id,
            "timestamp": utcnow(),
            "payload": payload or {},
        }
        with self.events_path(session_id).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def write_digest(
        self,
        session_id: str,
        payload: dict[str, Any],
        *,
        cache_key: str | None = None,
        update_latest: bool = True,
    ) -> dict[str, Any]:
        session_dir = self.session_dir(session_id)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        digest_name = f"{timestamp}-{_slugify(payload.get('kind', 'digest'))}.json"
        payload = dict(payload)
        payload["session_id"] = session_id

        if cache_key:
            cache_path = self.coordination_root / "cache" / "digests" / f"{cache_key}.json"
            if cache_path.exists():
                cached = self._read_json(cache_path, {})
                if cached:
                    payload = {**cached, **payload, "cache_key": cache_key, "cache_hit": True}
            else:
                self._write_json(cache_path, payload)
                payload["cache_key"] = cache_key
                payload["cache_hit"] = False

        path = session_dir / "summaries" / digest_name
        self._write_json(path, payload)
        if update_latest:
            self.update_manifest_ref(session_id, "latest_context_digest_ref", self._display_path(path))
        self.append_event(
            session_id,
            "digest_created",
            {
                "kind": payload.get("kind"),
                "title": payload.get("title"),
                "path": self._display_path(path),
                "cache_hit": payload.get("cache_hit", False),
            },
        )
        return {"path": self._display_path(path), "payload": payload}

    def latest_digest(self, session_id: str, kind: str | None = None) -> dict[str, Any] | None:
        session_dir = self.session_dir(session_id)
        summaries = sorted((session_dir / "summaries").glob("*.json"), reverse=True)
        for path in summaries:
            payload = self._read_json(path, {})
            if not payload:
                continue
            if kind and payload.get("kind") != kind:
                continue
            return {"path": self._display_path(path), "payload": payload}
        return None

    def register_artifact(
        self,
        session_id: str,
        *,
        artifact_path: str,
        artifact_type: str,
        producer: str,
        status: str = "valid",
        replaces: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        index_path = self.artifact_index_path(session_id)
        index = self._read_json(index_path, {"artifacts": []})
        abs_path = Path(artifact_path).resolve()
        entry = {
            "path": self._display_path(abs_path),
            "type": artifact_type,
            "producer": producer,
            "status": status,
            "created_at": utcnow(),
            "sha256": _sha256_file(abs_path) if abs_path.exists() and abs_path.is_file() else "",
            "replaces": replaces,
            "metadata": metadata or {},
        }
        index["artifacts"] = [
            existing for existing in index["artifacts"] if existing.get("path") != entry["path"]
        ]
        index["artifacts"].append(entry)
        self._write_json(index_path, index)
        self.update_manifest_ref(session_id, "latest_artifact_index_ref", self._display_path(index_path))
        self.append_event(
            session_id,
            "artifact_registered",
            {
                "path": entry["path"],
                "type": artifact_type,
                "producer": producer,
                "status": status,
            },
        )
        return entry

    def update_checkpoint(
        self,
        session_id: str,
        *,
        actor: str,
        stage: str,
        status: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        checkpoint_path = self.session_dir(session_id) / "checkpoints" / f"{_slugify(actor)}.json"
        checkpoint = self._read_json(checkpoint_path, {})
        checkpoint.update(
            {
                "actor": actor,
                "stage": stage,
                "status": status,
                "updated_at": utcnow(),
            }
        )
        if not checkpoint.get("created_at"):
            checkpoint["created_at"] = utcnow()
        if payload:
            checkpoint.update(payload)
        self._write_json(checkpoint_path, checkpoint)
        self.append_event(
            session_id,
            "checkpoint_updated",
            {
                "actor": actor,
                "stage": stage,
                "status": status,
                "path": self._display_path(checkpoint_path),
            },
        )
        return checkpoint

    def set_leader(
        self,
        session_id: str,
        *,
        leader: str,
        tool: str,
        reason: str,
        responsibilities: Iterable[str] | None = None,
        handoff_ref: str | None = None,
        latest_digest_ref: str | None = None,
    ) -> dict[str, Any]:
        current_manifest = self.session_manifest(session_id)
        manifest = self.ensure_session(
            session_id=session_id,
            cwd=self._session_cwd(session_id),
            leader=leader,
            tool=tool,
            lead_mode="auto",
            status=current_manifest.get("status", "active") or "active",
        )
        current_state = self.leader_state(session_id)
        previous_leader = current_state.get("leader") or current_manifest.get("current_leader")
        state = {
            "leader": leader,
            "tool": tool,
            "responsibilities": list(responsibilities or current_state.get("responsibilities", [])),
            "reason": reason,
            "previous_leader": previous_leader,
            "activated_at": utcnow(),
            "handoff_ref": handoff_ref,
            "latest_digest_ref": latest_digest_ref or manifest.get("latest_context_digest_ref"),
        }
        self._write_json(self.leader_state_path(session_id), state)
        manifest["current_leader"] = leader
        manifest.setdefault("tool_roles", {})[tool] = leader
        manifest["updated_at"] = utcnow()
        self._write_json(self.manifest_path(session_id), manifest)
        self.append_event(
            session_id,
            "leader_changed",
            {
                "leader": leader,
                "tool": tool,
                "reason": reason,
                "previous_leader": previous_leader,
                "handoff_ref": handoff_ref,
            },
        )
        return state

    def write_handoff(
        self,
        session_id: str,
        *,
        from_actor: str,
        to_actor: str,
        reason: str,
        expected_decision_scope: str,
        input_digest_refs: Iterable[str] | None = None,
        artifact_refs: Iterable[str] | None = None,
        required_outputs: Iterable[str] | None = None,
        open_risks: Iterable[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        handoff = {
            "session_id": session_id,
            "from": from_actor,
            "to": to_actor,
            "reason": reason,
            "expected_decision_scope": expected_decision_scope,
            "input_digest_refs": list(input_digest_refs or []),
            "artifact_refs": list(artifact_refs or []),
            "required_outputs": list(required_outputs or []),
            "open_risks": list(open_risks or []),
            "metadata": metadata or {},
            "created_at": utcnow(),
        }
        filename = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}-{_slugify(from_actor)}-to-{_slugify(to_actor)}.json"
        path = self.session_dir(session_id) / "handoffs" / filename
        self._write_json(path, handoff)
        self.update_manifest_ref(session_id, "latest_handoff_ref", self._display_path(path))
        self.append_event(
            session_id,
            "handoff_created",
            {
                "from": from_actor,
                "to": to_actor,
                "reason": reason,
                "path": self._display_path(path),
            },
        )
        return {"path": self._display_path(path), "payload": handoff}

    def latest_handoff(self, session_id: str, *, to_actor: str | None = None) -> dict[str, Any] | None:
        handoff_dir = self.session_dir(session_id) / "handoffs"
        for path in sorted(handoff_dir.glob("*.json"), reverse=True):
            payload = self._read_json(path, {})
            if not payload:
                continue
            if to_actor and payload.get("to") != to_actor:
                continue
            return {"path": self._display_path(path), "payload": payload}
        return None

    def consume_handoff(self, session_id: str, *, to_actor: str | None = None) -> dict[str, Any]:
        handoff = self.latest_handoff(session_id, to_actor=to_actor)
        payload = {
            "session_id": session_id,
            "manifest": self.session_manifest(session_id),
            "leader_state": self.leader_state(session_id),
            "handoff": handoff,
            "latest_digest": self.latest_digest(session_id),
            "artifact_index": self.artifact_index(session_id),
        }
        self.append_event(
            session_id,
            "handoff_consumed",
            {
                "to": to_actor,
                "handoff_ref": handoff["path"] if handoff else None,
            },
        )
        return payload

    def session_status(self, session_id: str) -> dict[str, Any]:
        manifest = self.session_manifest(session_id)
        leader_state = self.leader_state(session_id)
        latest_handoff = self.latest_handoff(session_id)
        artifact_index = self.artifact_index(session_id)
        checkpoint_count = len(list((self.session_dir(session_id) / "checkpoints").glob("*.json")))
        pending_handoff = bool(latest_handoff and latest_handoff["payload"].get("to") != manifest.get("current_leader"))
        return {
            "session_id": session_id,
            "current_leader": manifest.get("current_leader"),
            "leader_state": leader_state,
            "latest_digest": self.latest_digest(session_id),
            "latest_handoff": latest_handoff,
            "artifact_count": len(artifact_index.get("artifacts", [])),
            "checkpoint_count": checkpoint_count,
            "pending_handoff": pending_handoff,
            "manifest": manifest,
        }

    def _skill_search_roots(self, session_id: str | None = None) -> list[Path]:
        home = Path.home()
        session_cwd = self._session_cwd(session_id)
        roots = [
            self.project_root / ".claude" / "skills",
            self.project_root / ".claude_auth" / "plugins",
            home / ".claude" / "skills",
            home / ".agents" / "skills",
            home / ".codex" / "skills",
        ]

        for parent in self._ancestor_roots(self.project_root):
            roots.append(parent / ".claude" / "skills")
            roots.append(parent / "skills")
        for parent in self._ancestor_roots(session_cwd):
            roots.append(parent / ".claude" / "skills")
            roots.append(parent / "skills")

        seen: set[Path] = set()
        deduped: list[Path] = []
        for root in roots:
            try:
                resolved = root.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            deduped.append(resolved)
        return deduped

    def discover_skills(self, session_id: str, *, include_plugin_cache: bool = True) -> dict[str, Any]:
        session_dir = self.session_dir(session_id)
        seen: set[str] = set()
        skills: list[dict[str, Any]] = []

        for root in self._skill_search_roots(session_id):
            if not root.exists():
                continue
            for skill_file in root.rglob("SKILL.md"):
                try:
                    resolved = str(skill_file.resolve())
                except OSError:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                if not include_plugin_cache and ".claude_auth" in resolved:
                    continue
                meta = _extract_skill_metadata(skill_file)
                skills.append(
                    {
                        "name": skill_file.parent.name,
                        "title": meta["title"],
                        "description": meta["description"],
                        "path": resolved,
                        "source_root": str(root),
                    }
                )

        skills.sort(key=lambda item: (item["name"], item["path"]))
        catalog = {
            "generated_at": utcnow(),
            "session_id": session_id,
            "roots": [str(root) for root in self._skill_search_roots(session_id) if root.exists()],
            "count": len(skills),
            "skills": skills,
        }

        catalog_path = session_dir / "skills" / "skill_index.json"
        self._write_json(catalog_path, catalog)
        cache_path = self.coordination_root / "cache" / "skills" / f"{_slugify(session_id)}-skill-index.json"
        self._write_json(cache_path, catalog)
        self.update_manifest_ref(session_id, "latest_skill_index_ref", self._display_path(catalog_path))
        self.append_event(
            session_id,
            "skills_indexed",
            {"count": len(skills), "path": self._display_path(catalog_path)},
        )
        return catalog

    def relevant_skills(self, session_id: str, query: str, *, limit: int = 5) -> list[dict[str, Any]]:
        session_dir = self.session_dir(session_id)
        catalog = self._read_json(session_dir / "skills" / "skill_index.json", {})
        if not catalog:
            catalog = self.discover_skills(session_id)
        tokens = {
            token
            for token in re.findall(r"[a-zA-Z0-9_.-]{3,}", query.lower())
            if token not in {"with", "that", "this", "from", "then", "mode", "task"}
        }
        if not tokens:
            return []

        scored: list[tuple[int, dict[str, Any]]] = []
        for skill in catalog.get("skills", []):
            haystack = " ".join(
                [skill.get("name", ""), skill.get("title", ""), skill.get("description", ""), skill.get("path", "")]
            ).lower()
            score = sum(3 for token in tokens if token in skill.get("name", "").lower())
            score += sum(2 for token in tokens if token in skill.get("title", "").lower())
            score += sum(1 for token in tokens if token in haystack)
            if score > 0:
                scored.append((score, skill))
        scored.sort(key=lambda item: (-item[0], item[1]["name"]))
        return [skill for _, skill in scored[:limit]]

    def discover_instruction_docs(self, session_id: str) -> dict[str, Any]:
        session_dir = self.session_dir(session_id)
        cwd = self._session_cwd(session_id)
        docs: list[dict[str, Any]] = []
        seen: set[str] = set()

        for root in self._ancestor_roots(cwd):
            for filename, doc_type in (("AGENTS.md", "agents"), ("CLAUDE.md", "claude")):
                candidate = root / filename
                if not candidate.exists():
                    continue
                try:
                    resolved = str(candidate.resolve())
                except OSError:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                meta = _extract_instruction_metadata(candidate)
                docs.append(
                    {
                        "type": doc_type,
                        "title": meta["title"],
                        "summary": meta["summary"],
                        "path": resolved,
                        "scope_root": str(root.resolve()),
                        "depth": len(candidate.resolve().relative_to(Path("/")).parts),
                    }
                )

        docs.sort(key=lambda item: (-item["depth"], item["type"], item["path"]))
        index = {
            "generated_at": utcnow(),
            "session_id": session_id,
            "cwd": str(cwd),
            "count": len(docs),
            "documents": docs,
        }
        index_path = session_dir / "instructions" / "instruction_index.json"
        self._write_json(index_path, index)
        self.update_manifest_ref(session_id, "latest_instruction_index_ref", self._display_path(index_path))
        self.append_event(
            session_id,
            "instructions_indexed",
            {"count": len(docs), "path": self._display_path(index_path)},
        )
        return index

    def relevant_instruction_docs(self, session_id: str, query: str, *, limit: int = 5) -> list[dict[str, Any]]:
        session_dir = self.session_dir(session_id)
        index = self._read_json(session_dir / "instructions" / "instruction_index.json", {})
        if not index:
            index = self.discover_instruction_docs(session_id)

        tokens = {
            token
            for token in re.findall(r"[a-zA-Z0-9_.-]{3,}", query.lower())
            if token not in {"with", "that", "this", "from", "then", "mode", "task", "agent"}
        }

        scored: list[tuple[int, dict[str, Any]]] = []
        for document in index.get("documents", []):
            haystack = " ".join(
                [
                    document.get("type", ""),
                    document.get("title", ""),
                    document.get("summary", ""),
                    document.get("path", ""),
                    document.get("scope_root", ""),
                ]
            ).lower()
            score = document.get("depth", 0)
            score += sum(2 for token in tokens if token in haystack)
            if document.get("type") == "claude":
                score += 1
            scored.append((score, document))

        scored.sort(key=lambda item: (-item[0], item[1]["path"]))
        return [document for _, document in scored[:limit]]

    def sync_omx_state(self, session_id: str, *, cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        resolved_cwd = Path(cwd or self._session_cwd(session_id)).resolve()
        omx_root = self._find_existing_dir(resolved_cwd, ".omx") or (resolved_cwd / ".omx")
        state_dir = omx_root / "state"
        plans_dir = omx_root / "plans"
        notepad_path = omx_root / "notepad.md"
        session_json_path = state_dir / "session.json"

        synced_artifacts: list[dict[str, Any]] = []
        source_refs: list[str] = []
        summary_lines: list[str] = [
            f"- OMX root: {self._display_path(omx_root)}",
            f"- Sync cwd: {self._display_path(resolved_cwd)}",
        ]

        omx_session = self._read_json(session_json_path, {})
        if omx_session:
            self.merge_manifest_metadata(
                session_id,
                {
                    "omx_session_id": omx_session.get("session_id"),
                    "omx_pid": omx_session.get("pid"),
                    "omx_started_at": omx_session.get("started_at"),
                },
            )
            source_refs.append(self._display_path(session_json_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(session_json_path),
                    artifact_type="omx_session",
                    producer="omx_sync",
                    metadata={"session_id": omx_session.get("session_id")},
                )
            )
            summary_lines.extend(
                [
                    f"- OMX session id: {omx_session.get('session_id', 'unknown')}",
                    f"- OMX session cwd: {omx_session.get('cwd', 'unknown')}",
                ]
            )

        if notepad_path.exists() and _read_text(notepad_path, max_chars=20000).strip():
            source_refs.append(self._display_path(notepad_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(notepad_path),
                    artifact_type="omx_notepad",
                    producer="omx_sync",
                )
            )
            self.write_digest(
                session_id,
                build_digest_payload(
                    title="OMX notepad snapshot",
                    text=_read_text(notepad_path, max_chars=6000),
                    kind="omx_notepad",
                    source_refs=[self._display_path(notepad_path)],
                    generated_by="sync_omx_state",
                    model="omx-runtime",
                ),
                update_latest=False,
            )
            summary_lines.append("- OMX notepad: present")
        else:
            summary_lines.append("- OMX notepad: absent")

        plan_files = sorted(
            plans_dir.glob("*.md") if plans_dir.exists() else [],
            key=lambda candidate: candidate.stat().st_mtime,
            reverse=True,
        )
        if plan_files:
            summary_lines.append(f"- OMX plans: {len(plan_files)} file(s)")
        else:
            summary_lines.append("- OMX plans: none")

        for plan_path in plan_files[:3]:
            source_refs.append(self._display_path(plan_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(plan_path),
                    artifact_type="omx_plan",
                    producer="omx_sync",
                )
            )
            self.write_digest(
                session_id,
                build_digest_payload(
                    title=f"OMX plan snapshot: {plan_path.name}",
                    text=_read_text(plan_path, max_chars=6000),
                    kind="omx_plan",
                    source_refs=[self._display_path(plan_path)],
                    generated_by="sync_omx_state",
                    model="omx-runtime",
                ),
                update_latest=False,
            )
            summary_lines.append(f"  - latest plan: {plan_path.name}")

        state_files = sorted(
            candidate
            for candidate in state_dir.glob("*.json")
            if candidate.is_file()
        ) if state_dir.exists() else []
        for state_file in state_files:
            if state_file == session_json_path:
                continue
            source_refs.append(self._display_path(state_file))
        if state_files:
            summary_lines.append(
                "- OMX state files: " + ", ".join(state_file.name for state_file in state_files[:6])
            )

        sync_digest = self.write_digest(
            session_id,
            build_digest_payload(
                title="OMX runtime synchronization",
                text="\n".join(summary_lines),
                kind="omx_state_sync",
                source_refs=source_refs,
                generated_by="sync_omx_state",
                model="omx-runtime",
                metadata={
                    "artifact_count": len(synced_artifacts),
                    "plan_count": len(plan_files),
                    "has_notepad": notepad_path.exists(),
                },
            ),
            update_latest=True,
        )
        checkpoint = self.update_checkpoint(
            session_id,
            actor="omx_sync",
            stage="runtime_sync",
            status="completed",
            payload={
                "cwd": str(resolved_cwd),
                "omx_root": self._display_path(omx_root),
                "artifact_count": len(synced_artifacts),
                "plan_count": len(plan_files),
                "latest_digest_ref": sync_digest["path"],
            },
        )
        result = {
            "session_id": session_id,
            "cwd": str(resolved_cwd),
            "omx_root": self._display_path(omx_root),
            "artifacts": synced_artifacts,
            "latest_digest": sync_digest,
            "checkpoint": checkpoint,
        }
        self.append_event(
            session_id,
            "omx_state_synced",
            {
                "omx_root": result["omx_root"],
                "artifact_count": len(synced_artifacts),
                "latest_digest_ref": sync_digest["path"],
            },
        )
        return result

    def sync_claude_state(self, session_id: str, *, cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        resolved_cwd = Path(cwd or self._session_cwd(session_id)).resolve()
        home = Path.home()
        claude_root = home / ".claude"
        tasks_dir = claude_root / "tasks"
        teams_dir = claude_root / "teams"
        compaction_state_path = self.project_root / ".omc" / "compaction_state.json"

        synced_artifacts: list[dict[str, Any]] = []
        source_refs: list[str] = []
        summary_lines: list[str] = [
            f"- Claude root: {self._display_path(claude_root) if claude_root.exists() else str(claude_root)}",
            f"- Sync cwd: {self._display_path(resolved_cwd)}",
        ]

        recent_tasks = sorted(
            (candidate for candidate in tasks_dir.glob("*.json") if candidate.is_file()),
            key=_safe_stat_mtime,
            reverse=True,
        ) if tasks_dir.exists() else []
        active_task_lines: list[str] = []
        for task_path in recent_tasks[:12]:
            task_payload = self._read_json(task_path, {})
            status = str(task_payload.get("status", "unknown"))
            subject = str(task_payload.get("subject") or task_payload.get("prompt") or task_path.stem)
            if status in {"in_progress", "pending", "running", "completed", "failed"}:
                active_task_lines.append(f"- {status}: {subject[:160]}")
            source_refs.append(self._display_path(task_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(task_path),
                    artifact_type="claude_task",
                    producer="claude_sync",
                    metadata={"status": status, "subject": subject[:160]},
                )
            )
        summary_lines.append(f"- Claude tasks discovered: {len(recent_tasks)}")
        if active_task_lines:
            summary_lines.append("- Recent Claude tasks:")
            summary_lines.extend(f"  {line}" for line in active_task_lines[:8])

        recent_teams = sorted(
            (candidate for candidate in teams_dir.glob("*/config.json") if candidate.is_file()),
            key=_safe_stat_mtime,
            reverse=True,
        ) if teams_dir.exists() else []
        team_lines: list[str] = []
        for team_path in recent_teams[:8]:
            team_payload = self._read_json(team_path, {})
            team_name = str(team_payload.get("team_name") or team_payload.get("name") or team_path.parent.name)
            member_count = len(team_payload.get("members") or [])
            team_lines.append(f"- {team_name} ({member_count} members)")
            source_refs.append(self._display_path(team_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(team_path),
                    artifact_type="claude_team",
                    producer="claude_sync",
                    metadata={"team_name": team_name, "member_count": member_count},
                )
            )
        summary_lines.append(f"- Claude team configs discovered: {len(recent_teams)}")
        if team_lines:
            summary_lines.append("- Recent Claude teams:")
            summary_lines.extend(f"  {line}" for line in team_lines[:6])

        if compaction_state_path.exists():
            source_refs.append(self._display_path(compaction_state_path))
            synced_artifacts.append(
                self.register_artifact(
                    session_id,
                    artifact_path=str(compaction_state_path),
                    artifact_type="claude_compaction_state",
                    producer="claude_sync",
                )
            )
            compaction_text = _read_text(compaction_state_path, max_chars=6000)
            self.write_digest(
                session_id,
                build_digest_payload(
                    title="Claude compaction state snapshot",
                    text=compaction_text,
                    kind="claude_compaction_state",
                    source_refs=[self._display_path(compaction_state_path)],
                    generated_by="sync_claude_state",
                    model="claude-runtime",
                ),
                update_latest=False,
            )
            summary_lines.append("- Claude compaction state: present")
        else:
            summary_lines.append("- Claude compaction state: absent")

        checkpoint_roots = [resolved_cwd, self.project_root / "targets", self.project_root / "tests"]
        checkpoint_candidates: list[Path] = []
        seen_paths: set[Path] = set()
        for root in checkpoint_roots:
            if not root.exists():
                continue
            for candidate in root.rglob("checkpoint*.json"):
                if candidate.is_file() and candidate not in seen_paths:
                    checkpoint_candidates.append(candidate)
                    seen_paths.add(candidate)
                if len(checkpoint_candidates) >= 24:
                    break
        checkpoint_files = sorted(checkpoint_candidates, key=_safe_stat_mtime, reverse=True)[:8]
        checkpoint_lines: list[str] = []
        for checkpoint_path in checkpoint_files:
            payload = self._read_json(checkpoint_path, {})
            status = str(payload.get("status", "unknown"))
            agent = str(payload.get("agent", "unknown"))
            phase = str(payload.get("phase_name") or payload.get("phase") or "?")
            checkpoint_lines.append(f"- {agent} status={status} phase={phase} path={self._display_path(checkpoint_path)}")
        if checkpoint_lines:
            summary_lines.append("- Recent checkpoint snapshots:")
            summary_lines.extend(f"  {line}" for line in checkpoint_lines[:6])

        self.merge_manifest_metadata(
            session_id,
            {
                "claude_task_count": len(recent_tasks),
                "claude_team_count": len(recent_teams),
                "claude_compaction_state_present": compaction_state_path.exists(),
            },
        )

        sync_digest = self.write_digest(
            session_id,
            build_digest_payload(
                title="Claude runtime synchronization",
                text="\n".join(summary_lines),
                kind="claude_state_sync",
                source_refs=source_refs,
                generated_by="sync_claude_state",
                model="claude-runtime",
                metadata={
                    "artifact_count": len(synced_artifacts),
                    "task_count": len(recent_tasks),
                    "team_count": len(recent_teams),
                    "has_compaction_state": compaction_state_path.exists(),
                },
            ),
            update_latest=True,
        )
        checkpoint = self.update_checkpoint(
            session_id,
            actor="claude_sync",
            stage="runtime_sync",
            status="completed",
            payload={
                "cwd": str(resolved_cwd),
                "artifact_count": len(synced_artifacts),
                "task_count": len(recent_tasks),
                "team_count": len(recent_teams),
                "latest_digest_ref": sync_digest["path"],
            },
        )
        result = {
            "session_id": session_id,
            "cwd": str(resolved_cwd),
            "artifacts": synced_artifacts,
            "latest_digest": sync_digest,
            "checkpoint": checkpoint,
        }
        self.append_event(
            session_id,
            "claude_state_synced",
            {
                "artifact_count": len(synced_artifacts),
                "task_count": len(recent_tasks),
                "team_count": len(recent_teams),
                "latest_digest_ref": sync_digest["path"],
            },
        )
        return result

    def bootstrap_codex(self, *, session_id: str | None = None, cwd: str | os.PathLike[str] | None = None) -> dict[str, Any]:
        resolved_cwd = Path(cwd or ".").resolve()
        omx_session_path, omx_session = self._read_omx_session(resolved_cwd)
        actual_session = session_id or omx_session.get("session_id") or stable_session_id(resolved_cwd)
        manifest = self.ensure_session(
            session_id=actual_session,
            cwd=resolved_cwd,
            leader="codex",
            tool="omx",
            lead_mode="auto",
            status="active",
            metadata={
                "bootstrap_source": "bootstrap-codex",
                "omx_session_path": self._display_path(omx_session_path) if omx_session_path else None,
            },
        )
        skills = self.discover_skills(actual_session)
        instructions = self.discover_instruction_docs(actual_session)
        claude_sync_result = self.sync_claude_state(actual_session, cwd=resolved_cwd)
        sync_result = self.sync_omx_state(actual_session, cwd=resolved_cwd)
        leader_state = self.set_leader(
            actual_session,
            leader="codex",
            tool="omx",
            reason="codex_bootstrap",
            responsibilities=["planning", "verification", "cross-tool coordination"],
            latest_digest_ref=sync_result["latest_digest"]["path"],
        )
        refreshed_manifest = self.session_manifest(actual_session)
        summary_text = "\n".join(
            [
                "- Codex/OMX bootstrap completed",
                f"- Session id: {actual_session}",
                f"- Skill count: {skills.get('count', 0)}",
                f"- Instruction doc count: {instructions.get('count', 0)}",
                f"- Latest Claude sync digest: {claude_sync_result['latest_digest']['path']}",
                f"- Latest digest: {sync_result['latest_digest']['path']}",
                "- Read latest digest and latest handoff before re-reading long docs.",
                "- Treat coordination Claude sync snapshots as shared memory from Claude.",
                "- Write structured handoffs before switching leader back to Claude.",
            ]
        )
        bootstrap_digest = self.write_digest(
            actual_session,
            build_digest_payload(
                title="Codex bootstrap summary",
                text=summary_text,
                kind="codex_bootstrap",
                source_refs=[
                    refreshed_manifest.get("latest_skill_index_ref", ""),
                    refreshed_manifest.get("latest_instruction_index_ref", ""),
                    claude_sync_result["latest_digest"]["path"],
                    sync_result["latest_digest"]["path"],
                ],
                generated_by="bootstrap_codex",
                model="omx-runtime",
                metadata={
                    "skill_count": skills.get("count", 0),
                    "instruction_count": instructions.get("count", 0),
                },
            ),
            update_latest=True,
        )
        leader_state["latest_digest_ref"] = bootstrap_digest["path"]
        self._write_json(self.leader_state_path(actual_session), leader_state)
        self.append_event(
            actual_session,
            "codex_bootstrapped",
            {
                "skill_count": skills.get("count", 0),
                "instruction_count": instructions.get("count", 0),
                "latest_digest_ref": bootstrap_digest["path"],
            },
        )
        return {
            "session_id": actual_session,
            "manifest": self.session_manifest(actual_session),
            "leader_state": leader_state,
            "skills": {"count": skills.get("count", 0), "path": self.session_manifest(actual_session).get("latest_skill_index_ref")},
            "instructions": {
                "count": instructions.get("count", 0),
                "path": self.session_manifest(actual_session).get("latest_instruction_index_ref"),
            },
            "latest_digest": bootstrap_digest,
            "latest_handoff": self.latest_handoff(actual_session, to_actor="codex"),
            "artifact_index": self.artifact_index(actual_session),
        }
