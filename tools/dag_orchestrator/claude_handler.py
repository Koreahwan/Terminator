#!/usr/bin/env python3
"""
Backend-aware CLI handler for DAG nodes.
Bridges dag.py execution to Claude Code or Codex/OMX subprocess execution.
"""
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, Any, Optional

from .dag import AgentNode
from .agent_bridge import ROLE_ARTIFACTS, check_artifacts, log_run_start, log_run_complete

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CODEX_SKIP_MODELS = {"sonnet", "opus", "haiku"}


class ArtifactMissingError(Exception):
    """Raised when expected agent artifacts are not found after execution."""
    pass


class BackendAgentHandler:
    """
    DAG node handler that spawns Claude Code agents via CLI subprocess.
    Used by dag.py's AgentDAG.run() to execute each pipeline node.
    """

    ROLE_MODELS = {
        "claude": {
            "reverser": "sonnet",
            "trigger": "sonnet",
            "solver": "opus",
            "chain": "opus",
            "critic": "opus",
            "verifier": "sonnet",
            "reporter": "sonnet",
            "scout": "sonnet",
            "analyst": "sonnet",
            "exploiter": "opus",
            "target_evaluator": "sonnet",
            "triager_sim": "opus",
            "architect": "opus",
        },
        "codex": {},
    }

    def __init__(self, work_dir: str, session_id: str, target: str,
                 backend: str = "claude", cli_path: str | None = None, dry_run: bool = False):
        self.work_dir = work_dir
        self.session_id = session_id
        self.target = target
        self.backend = backend
        self.cli_path = cli_path
        self.dry_run = dry_run

    @staticmethod
    def _canonical_role(role: str) -> str:
        return role.replace("_", "-")

    @staticmethod
    def _codex_model(model: str | None) -> str:
        value = (model or "").strip()
        lowered = value.lower()
        if not value or lowered in CODEX_SKIP_MODELS or lowered.startswith("claude"):
            return os.environ.get("TERMINATOR_CODEX_MODEL", "gpt-5.4")
        return value

    def _policy_for_role(self, role: str) -> dict:
        profile = os.environ.get("TERMINATOR_RUNTIME_PROFILE", "")
        cmd = ["python3", str(PROJECT_ROOT / "tools" / "runtime_policy.py")]
        if profile:
            cmd.extend(["--profile", profile])
        cmd.extend(["get-role", self._canonical_role(role)])
        result = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True)
        if result.returncode != 0:
            return {}
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {}

    def _active_profile(self) -> str:
        return os.environ.get("TERMINATOR_RUNTIME_PROFILE", "").strip()

    def _scope_contract_path(self) -> Path:
        return Path(self.work_dir) / "scope_contract.json"

    def _scope_gate_for_role(self, role: str) -> dict:
        """Return scope-first gate status for a role without mutating state."""
        profile = self._active_profile()
        active_pipeline = os.environ.get("TERMINATOR_ACTIVE_PIPELINE", "").strip()
        gate = {
            "enabled": profile == "scope-first-hybrid",
            "profile": profile,
            "pipeline": active_pipeline,
            "role": role,
            "status": "not_applicable",
            "scope_contract": str(self._scope_contract_path()),
            "scope_contract_sha256": "",
            "reason": "",
        }
        if not gate["enabled"]:
            return gate
        if active_pipeline and active_pipeline != "bounty":
            gate["status"] = "pipeline_exempt"
            return gate

        # Phase 0 roles may create or audit the contract; Phase 1+ may only
        # proceed after the deterministic contract exists and validates.
        exempt = {"target_evaluator", "target-evaluator", "target_discovery", "target-discovery"}
        if role in exempt:
            gate["status"] = "phase0_exempt"
            return gate

        contract_path = self._scope_contract_path()
        if not contract_path.exists():
            gate["status"] = "would_block" if self.dry_run else "block"
            gate["reason"] = "scope_contract_missing"
            return gate

        try:
            from tools.scope_contract import validate_contract
            rc, payload = validate_contract(contract_path)
        except Exception as exc:  # noqa: BLE001 - gate must fail closed.
            gate["status"] = "would_block" if self.dry_run else "block"
            gate["reason"] = f"scope_contract_validation_error:{type(exc).__name__}:{exc}"
            return gate

        if rc != 0:
            gate["status"] = "would_block" if self.dry_run else "block"
            gate["reason"] = "scope_contract_invalid"
            gate["validation"] = payload
            return gate

        gate["status"] = "pass"
        gate["scope_contract_sha256"] = payload.get("scope_contract_sha256", "")
        gate["policy_status"] = payload.get("policy_status", {})
        return gate

    def _effective_backend_model(self, role: str, node: AgentNode) -> tuple[str, str]:
        requested = self.backend
        policy = self._policy_for_role(role) if requested == "hybrid" else {}
        backend = policy.get("backend") if requested == "hybrid" else requested
        if backend not in {"claude", "codex"}:
            backend = "claude"
        default_model = self.ROLE_MODELS.get(backend, {}).get(role)
        if not default_model:
            default_model = "gpt-5.4" if backend == "codex" else "sonnet"
        model = policy.get("model") or node.model or default_model
        if backend == "codex":
            model = self._codex_model(model)
        return backend, model

    def create_handler(self, role: str) -> Callable:
        """Factory: returns a handler function for a specific agent role."""
        def handler(node: AgentNode, context: dict) -> dict:
            return self._execute_agent(node, role, context)
        return handler

    def _build_handoff_prompt(self, role: str, node: AgentNode, context: dict) -> str:
        """Build structured HANDOFF prompt for the agent."""
        # Collect previous agent outputs from context
        prev_outputs = []
        for key, value in context.items():
            if key.endswith("_output") and isinstance(value, dict):
                prev_role = key.replace("_output", "")
                artifacts = value.get("artifacts", [])
                if artifacts:
                    prev_outputs.append(
                        f"[HANDOFF from @{prev_role}]\n"
                        f"- Artifacts: {', '.join(artifacts)}\n"
                        f"- Status: {value.get('status', 'unknown')}"
                    )

        handoff_block = "\n\n".join(prev_outputs) if prev_outputs else "No previous agent outputs."

        contract_path = PROJECT_ROOT / "generated" / "role_contracts" / f"{self._canonical_role(role)}.txt"
        contract_hint = (
            f"- Prefer compact role contract: {contract_path}\n"
            if contract_path.exists()
            else f"- Follow all rules from your agent definition (.claude/agents/{role}.md)\n"
        )
        scope_contract_path = self._scope_contract_path()
        scope_contract_hint = ""
        if scope_contract_path.exists():
            try:
                data = json.loads(scope_contract_path.read_text(encoding="utf-8"))
                scope_contract_hint = (
                    "\n## Scope Contract\n"
                    f"- Path: {scope_contract_path}\n"
                    f"- scope_contract_sha256: {data.get('scope_contract_sha256', '')}\n"
                    "- Every produced artifact must include this exact scope_contract_sha256.\n"
                    "- Do not request or perform live actions outside tools/safety_wrapper.py verdicts.\n"
                )
            except (OSError, json.JSONDecodeError):
                scope_contract_hint = f"\n## Scope Contract\n- Present but unreadable: {scope_contract_path}\n"

        prompt = f"""You are the @{role} agent for target: {self.target}
Working directory: {self.work_dir}

## Previous Agent Results
{handoff_block}

## Your Task
{node.description}

## Rules
- Save all artifacts to: {self.work_dir}/
- Expected outputs: {', '.join(ROLE_ARTIFACTS.get(role, ['(none)']))}
- When done, output a summary of your findings.
{contract_hint.rstrip()}
{scope_contract_hint.rstrip()}
"""

        # Include performance constraints in handoff
        constraints = []
        if hasattr(node, 'effort') and node.effort != "default":
            constraints.append(f"effort: {node.effort}")
        if hasattr(node, 'max_turns') and node.max_turns:
            constraints.append(f"max_turns: {node.max_turns}")
        if constraints:
            prompt += f"\n[CONSTRAINTS] {', '.join(constraints)}\n"

        return prompt

    def _execute_agent(self, node: AgentNode, role: str, context: dict) -> dict:
        """Execute a single agent via Claude Code CLI."""
        prompt = self._build_handoff_prompt(role, node, context)
        effective_backend, model = self._effective_backend_model(role, node)
        scope_gate = self._scope_gate_for_role(role)
        context[f"{role}_scope_gate"] = scope_gate
        if scope_gate.get("status") == "block":
            raise RuntimeError(f"scope-first gate blocked @{role}: {scope_gate.get('reason')}")

        # DB logging
        run_id = log_run_start(
            self.session_id,
            role,
            self.target,
            model,
            backend=effective_backend,
            parallel_group_id=os.getenv("TERMINATOR_PARALLEL_GROUP_ID"),
        )
        start_time = time.time()

        if self.dry_run:
            print(f"  [DRY-RUN] Would execute @{role} via {effective_backend} (model={model})")
            print(f"  [DRY-RUN] Prompt length: {len(prompt)} chars")
            if scope_gate.get("enabled"):
                print(f"  [DRY-RUN] Scope gate: {scope_gate.get('status')} {scope_gate.get('reason', '')}")
            duration = 0
            log_run_complete(run_id, "DRY_RUN", 0, f"Dry run for {role}")
            return {"status": "dry_run", "role": role, "artifacts": [], "scope_gate": scope_gate}

        cli_path = self.cli_path or ("omx" if effective_backend == "codex" else "claude")

        if effective_backend == "codex":
            cmd = [
                cli_path,
                "exec",
                "--dangerously-bypass-approvals-and-sandbox",
                "-C",
                self.work_dir,
                "-m",
                model,
                "--json",
                "-",
            ]
            input_text = prompt
        else:
            cmd = [
                cli_path, "-p", prompt,
                "--permission-mode", "bypassPermissions",
                "--model", model,
                "--output-format", "json",
            ]
            input_text = None

        # Propagate effort level
        if hasattr(node, 'effort') and node.effort and node.effort != "default":
            cmd.extend(["--effort", node.effort])

        # Propagate maxTurns
        if hasattr(node, 'max_turns') and node.max_turns:
            cmd.extend(["--max-turns", str(node.max_turns)])

        try:
            result = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                timeout=node.timeout,
                cwd=self.work_dir,
                text=True,
            )

            duration = int(time.time() - start_time)

            # Parse output
            output_text = result.stdout
            try:
                output_json = json.loads(output_text)
                summary = output_json.get("result", output_text[:500])
            except (json.JSONDecodeError, TypeError):
                summary = output_text[:500] if output_text else "(no output)"

            if result.returncode != 0:
                error_msg = result.stderr[:500] if result.stderr else f"Exit code {result.returncode}"
                log_run_complete(run_id, "FAILED", duration, error_msg)
                raise RuntimeError(f"@{role} failed: {error_msg}")

            # Check artifacts
            artifact_check = check_artifacts(self.work_dir, role)
            if scope_gate.get("enabled") and scope_gate.get("scope_contract_sha256"):
                stale = []
                expected_sha = scope_gate["scope_contract_sha256"]
                for artifact in artifact_check["found"]:
                    path = Path(self.work_dir) / artifact
                    try:
                        if expected_sha not in path.read_text(encoding="utf-8", errors="ignore"):
                            stale.append(artifact)
                    except OSError:
                        stale.append(artifact)
                if stale:
                    log_run_complete(run_id, "FAILED", duration, f"Missing scope_contract_sha256 in artifacts: {stale}", artifact_check["found"])
                    raise ArtifactMissingError(f"@{role} artifacts missing scope_contract_sha256: {stale}")

            if not artifact_check["complete"] and artifact_check["expected"]:
                missing = artifact_check["missing"]
                log_run_complete(run_id, "PARTIAL", duration,
                                 f"Missing artifacts: {missing}",
                                 artifact_check["found"])
                # Don't fail hard — some agents (reporter) write elsewhere
                print(f"  [WARN] @{role} missing artifacts: {missing}")

            log_run_complete(
                run_id, "COMPLETED", duration, summary,
                artifact_check["found"]
            )

            return {
                "status": "completed",
                "role": role,
                "artifacts": artifact_check["found"],
                "missing": artifact_check["missing"],
                "duration": duration,
                "summary": summary,
                "scope_gate": scope_gate,
            }

        except subprocess.TimeoutExpired:
            duration = int(time.time() - start_time)
            log_run_complete(run_id, "TIMEOUT", duration, f"Timeout after {node.timeout}s")
            raise TimeoutError(f"@{role} timed out after {node.timeout}s")

    def attach_to_dag(self, dag) -> None:
        """Attach handlers to all nodes in a DAG based on their roles."""
        for name, node in dag.nodes.items():
            node.handler = self.create_handler(node.role)


ClaudeAgentHandler = BackendAgentHandler
