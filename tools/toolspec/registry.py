"""ToolSpec registry — typed tool metadata for Terminator pipeline."""
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
import json
import yaml


class ToolKind(Enum):
    QUERY = "query"
    ANALYSIS = "analysis"
    MUTATION = "mutation"
    EXECUTION = "execution"
    NETWORK = "network"


class ParallelClass(Enum):
    INDEPENDENT = "independent"
    EXCLUSIVE = "exclusive"
    GROUPED = "grouped"


@dataclass
class ToolSpec:
    tool_id: str
    name: str
    kind: ToolKind
    entrypoint: str
    description: str = ""
    read_only: bool = True
    side_effects: List[str] = field(default_factory=list)
    produces_artifacts: List[str] = field(default_factory=list)
    timeout: int = 300
    parallel_class: ParallelClass = ParallelClass.INDEPENDENT
    tags: List[str] = field(default_factory=list)
    agent_roles: List[str] = field(default_factory=list)
    install_method: str = ""
    install_cmd: str = ""
    binary_path: str = ""
    version_cmd: str = ""
    health_cmd: str = ""
    category: str = ""
    min_version: str = ""
    pipelines: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "tool_id": self.tool_id,
            "name": self.name,
            "kind": self.kind.value,
            "entrypoint": self.entrypoint,
            "description": self.description,
            "read_only": self.read_only,
            "side_effects": self.side_effects,
            "produces_artifacts": self.produces_artifacts,
            "timeout": self.timeout,
            "parallel_class": self.parallel_class.value,
            "tags": self.tags,
            "agent_roles": self.agent_roles,
        }
        for f in ("install_method", "install_cmd", "binary_path",
                   "version_cmd", "health_cmd", "category", "min_version"):
            v = getattr(self, f)
            if v:
                d[f] = v
        if self.pipelines:
            d["pipelines"] = self.pipelines
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ToolSpec":
        return cls(
            tool_id=d["tool_id"],
            name=d["name"],
            kind=ToolKind(d.get("kind", "execution")),
            entrypoint=d.get("entrypoint", ""),
            description=d.get("description", ""),
            read_only=d.get("read_only", True),
            side_effects=d.get("side_effects", []),
            produces_artifacts=d.get("produces_artifacts", []),
            timeout=d.get("timeout", 300),
            parallel_class=ParallelClass(d.get("parallel_class", "independent")),
            tags=d.get("tags", []),
            agent_roles=d.get("agent_roles", []),
            install_method=d.get("install_method", ""),
            install_cmd=d.get("install_cmd", ""),
            binary_path=d.get("binary_path", ""),
            version_cmd=d.get("version_cmd", ""),
            health_cmd=d.get("health_cmd", ""),
            category=d.get("category", ""),
            min_version=d.get("min_version", ""),
            pipelines=d.get("pipelines", []),
        )


class ToolRegistry:
    def __init__(self, registry_path: Optional[Path] = None):
        self._tools: Dict[str, ToolSpec] = {}
        if registry_path and registry_path.exists():
            self.load(registry_path)

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.tool_id] = spec

    def get(self, tool_id: str) -> Optional[ToolSpec]:
        return self._tools.get(tool_id)

    def find_by_kind(self, kind: ToolKind) -> List[ToolSpec]:
        return [t for t in self._tools.values() if t.kind == kind]

    def find_by_role(self, role: str) -> List[ToolSpec]:
        return [t for t in self._tools.values() if role in t.agent_roles or "all" in t.agent_roles]

    def find_by_category(self, category: str) -> List[ToolSpec]:
        return [t for t in self._tools.values() if t.category == category]

    def find_by_pipeline(self, pipeline: str) -> List[ToolSpec]:
        return [t for t in self._tools.values()
                if pipeline in t.pipelines or "all" in t.pipelines]

    def find_read_only(self) -> List[ToolSpec]:
        return [t for t in self._tools.values() if t.read_only]

    def list_all(self) -> List[ToolSpec]:
        return list(self._tools.values())

    def load(self, path: Path) -> None:
        with open(path) as f:
            if path.suffix in ('.yaml', '.yml'):
                data = yaml.safe_load(f)
            else:
                data = json.load(f)
        for item in data.get("tools", []):
            self.register(ToolSpec.from_dict(item))

    def save(self, path: Path) -> None:
        data = {"tools": [t.to_dict() for t in self._tools.values()]}
        with open(path, 'w') as f:
            if path.suffix in ('.yaml', '.yml'):
                yaml.dump(data, f, default_flow_style=False, sort_keys=False)
            else:
                json.dump(data, f, indent=2)

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, tool_id: str) -> bool:
        return tool_id in self._tools
