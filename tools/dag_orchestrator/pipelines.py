"""
Pre-defined active pipelines: target_discovery, bounty, ai_security,
client-pitch.
Each pipeline is a factory function that returns a configured AgentDAG.
"""
from .dag import AgentDAG, AgentNode

CLAUDE_OPUS_1M = "claude-opus-4-6[1m]"


def _make_node(name: str, role: str, model: str, description: str = "",
               effort: str = "default", max_turns: int = None) -> AgentNode:
    return AgentNode(name=name, role=role, model=model, description=description,
                     effort=effort, max_turns=max_turns)


def bounty_pipeline(target_name: str = "target") -> AgentDAG:
    """
    Bug Bounty v12 pipeline (Explore Lane + Prove Lane):
    EXPLORE LANE:
      target_evaluator → scout+analyst+threat_modeler+patch_hunter (parallel)
        → workflow_auditor+web_tester (parallel, Phase 1.5)
    PROVE LANE:
      → exploiter → reporter_draft → critic+architect (parallel)
        → triager_sim → reporter_final
    """
    dag = AgentDAG(name=f"bounty_{target_name}", max_workers=4)

    # Phase 0
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "GO/NO-GO gate: ROI, competition, tech stack match, novelty score"))
    dag.add_node(_make_node("scope_auditor", "scope-auditor", CLAUDE_OPUS_1M,
                             "Audit scope_contract.json and block unsafe/OOS active paths",
                             effort="high", max_turns=20))

    # Phase 1 (parallel) — Explore Lane
    dag.add_node(_make_node("scout", "scout", "sonnet",
                             "Recon + duplicate pre-screen + program context + workflow_map.md"))
    dag.add_node(_make_node("analyst", "analyst", "sonnet",
                             "CVE matching, source analysis, vulnerability candidates"))
    dag.add_node(_make_node("threat_modeler", "threat_modeler", "sonnet",
                             "Trust boundary map, role matrix, state machines, invariants"))
    dag.add_node(_make_node("patch_hunter", "patch_hunter", "sonnet",
                             "Security commit diff analysis, variant candidate search"))

    # Phase 1.5 (parallel) — Explore Lane deep
    dag.add_node(_make_node("workflow_auditor", "workflow_auditor", "sonnet",
                             "Workflow state transition mapping, anomaly detection"))
    dag.add_node(_make_node("web_tester", "web_tester", "sonnet",
                             "Request-level testing + workflow pack testing"))

    # Phase 2 — Prove Lane
    dag.add_node(_make_node("exploiter", "exploiter", CLAUDE_OPUS_1M,
                             "PoC development + Evidence Tier classification (E1-E4)",
                             effort="high", max_turns=60))

    # Phase 3
    dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                             "Draft report with CVSS"))

    # Phase 4 (parallel review)
    dag.add_node(_make_node("critic", "critic", CLAUDE_OPUS_1M,
                             "Fact-check: CWE, dates, function names, line numbers",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("architect", "architect", CLAUDE_OPUS_1M,
                             "Framing review: attacker perspective"))

    # Phase 4.5
    dag.add_node(_make_node("triager_sim", "triager_sim", CLAUDE_OPUS_1M,
                             "Adversarial triage simulation: SUBMIT/STRENGTHEN/KILL"))

    # Phase 5
    dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                             "Final report + ZIP packaging"))

    # Edges — Phase 0 → scope audit → Phase 1 (all 4 parallel)
    dag.add_edge("target_evaluator", "scope_auditor")
    dag.add_edge("scope_auditor", "scout")
    dag.add_edge("scope_auditor", "analyst")
    dag.add_edge("scope_auditor", "threat_modeler")
    dag.add_edge("scope_auditor", "patch_hunter")

    # Phase 1 → Phase 1.5
    # workflow_auditor depends on scout+analyst+threat_modeler+patch_hunter
    dag.add_edge("scout", "workflow_auditor")
    dag.add_edge("analyst", "workflow_auditor")
    dag.add_edge("threat_modeler", "workflow_auditor")
    dag.add_edge("patch_hunter", "workflow_auditor")
    # web_tester depends on scout+analyst
    dag.add_edge("scout", "web_tester")
    dag.add_edge("analyst", "web_tester")

    # Phase 1.5 → Phase 2
    dag.add_edge("workflow_auditor", "exploiter")
    dag.add_edge("web_tester", "exploiter")
    # Also feed Phase 1 outputs directly to exploiter
    dag.add_edge("threat_modeler", "exploiter")
    dag.add_edge("patch_hunter", "exploiter")

    # Phase 2 → Phase 3 → Phase 4
    dag.add_edge("exploiter", "reporter_draft")
    dag.add_edge("reporter_draft", "critic")
    dag.add_edge("reporter_draft", "architect")
    dag.add_edge("critic", "triager_sim")
    dag.add_edge("architect", "triager_sim")
    dag.add_edge("triager_sim", "reporter_final")
    # Feedback: triager_sim → reporter_draft for STRENGTHEN
    dag.add_edge("triager_sim", "reporter_draft", feedback=True)

    return dag


def target_discovery_pipeline(target_name: str = "bug-bounty-programs") -> AgentDAG:
    """
    Passive target discovery pipeline:
      target_discovery → target_evaluator → critic → reporter
    """
    dag = AgentDAG(name=f"target_discovery_{target_name}", max_workers=1)

    dag.add_node(_make_node("target_discovery", "target-discovery", "sonnet",
                             "Collect and rank public bug bounty programs using passive official metadata"))
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "Validate selected candidate scope, bounty status, OOS risk, and ROI"))
    dag.add_node(_make_node("critic", "critic", CLAUDE_OPUS_1M,
                             "Challenge target choice for scope violations, duplicate risk, and weak ROI",
                             effort="high", max_turns=20))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write target shortlist, selected target, and safe pipeline plan"))

    dag.add_edge("target_discovery", "target_evaluator")
    dag.add_edge("target_evaluator", "critic")
    dag.add_edge("critic", "reporter")
    dag.add_edge("critic", "target_evaluator", feedback=True)

    return dag


def ai_security_pipeline(target_name: str = "target") -> AgentDAG:
    """
    AI/LLM Security pipeline (bounty track with Gate 1/2):
    target_evaluator → ai_recon+analyst (parallel) → [Gate 1: triager_sim]
    → exploiter → [Gate 2: triager_sim] → reporter → critic → triager_sim → reporter(final)
    """
    dag = AgentDAG(name=f"ai_security_{target_name}", max_workers=2)

    # Phase 0: Target evaluation
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "AI program analysis: model type, scope, bounty table, AUP check"))

    # Phase 1: Discovery (parallel)
    dag.add_node(_make_node("ai_recon", "ai-recon", "sonnet",
                             "Model fingerprinting, system prompt probing, tool/plugin enumeration"))
    dag.add_node(_make_node("analyst", "analyst", "sonnet",
                             "OWASP LLM Top 10 analysis, AI vuln classification (domain=ai)"))

    # Gate 1: Finding viability
    dag.add_node(_make_node("gate1_triager", "triager_sim", "sonnet",
                             "Gate 1: finding viability (mode=finding-viability, domain=ai)"))

    # Phase 2: PoC development
    dag.add_node(_make_node("exploiter", "exploiter", CLAUDE_OPUS_1M,
                             "AI/LLM PoC: jailbreak, injection chains, agent hijack (domain=ai)"))

    # Gate 2: PoC destruction
    dag.add_node(_make_node("gate2_triager", "triager_sim", CLAUDE_OPUS_1M,
                             "Gate 2: PoC destruction (mode=poc-destruction, domain=ai)"))

    # Phase 3: Report
    dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                             "Draft report + CVSS + bugcrowd_form.md"))

    # Phase 4: Review
    dag.add_node(_make_node("critic", "critic", CLAUDE_OPUS_1M,
                             "Fact-check AI-specific claims, OWASP mapping verification"))

    # Phase 4.5: Report review
    dag.add_node(_make_node("triager_report", "triager_sim", CLAUDE_OPUS_1M,
                             "Report review (mode=report-review, domain=ai)"))

    # Phase 5: Final
    dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                             "Final report + ZIP packaging"))

    # Edges
    dag.add_edge("target_evaluator", "ai_recon")
    dag.add_edge("target_evaluator", "analyst")
    dag.add_edge("ai_recon", "gate1_triager")
    dag.add_edge("analyst", "gate1_triager")
    dag.add_edge("gate1_triager", "exploiter")
    dag.add_edge("exploiter", "gate2_triager")
    dag.add_edge("gate2_triager", "reporter_draft")
    dag.add_edge("reporter_draft", "critic")
    dag.add_edge("critic", "triager_report")
    dag.add_edge("triager_report", "reporter_final")
    # Feedback edges
    dag.add_edge("triager_report", "reporter_draft", feedback=True)
    dag.add_edge("gate2_triager", "exploiter", feedback=True)

    return dag


# Registry of all pipelines
PIPELINES = {
    "target_discovery": target_discovery_pipeline,
    "bounty": bounty_pipeline,
    "ai_security": ai_security_pipeline,
    "ai-security": ai_security_pipeline,
    "client-pitch": bounty_pipeline,
}


def get_pipeline(name: str, target: str = "target", **kwargs) -> AgentDAG:
    """Get a pipeline by name. Extra kwargs passed to factory (e.g. bounty_mode)."""
    if name not in PIPELINES:
        raise ValueError(f"Unknown pipeline '{name}'. Available: {list(PIPELINES.keys())}")
    return PIPELINES[name](target, **kwargs)
