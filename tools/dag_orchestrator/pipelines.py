"""
Pre-defined pipelines: ctf_pwn, ctf_rev, bounty, firmware,
ai_security, robotics, supplychain.
Each pipeline is a factory function that returns a configured AgentDAG.
"""
from .dag import AgentDAG, AgentNode


def _make_node(name: str, role: str, model: str, description: str = "",
               effort: str = "default", max_turns: int = None) -> AgentNode:
    return AgentNode(name=name, role=role, model=model, description=description,
                     effort=effort, max_turns=max_turns)


def ctf_pwn_pipeline(challenge_name: str = "challenge") -> AgentDAG:
    """
    CTF Pwn 6-agent pipeline (CLAUDE.md 기준):
    reverser → trigger → chain → critic → verifier → reporter
    """
    dag = AgentDAG(name=f"ctf_pwn_{challenge_name}", max_workers=1)  # sequential

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Binary structure analysis, attack surface mapping",
                             effort="high", max_turns=40))
    dag.add_node(_make_node("trigger", "trigger", "sonnet",
                             "Crash exploration, minimal reproduction, primitive identification"))
    dag.add_node(_make_node("chain", "chain", "opus",
                             "Exploit chain: leak → overwrite → shell",
                             effort="high", max_turns=60))
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Cross-validation of all artifacts, logic error detection",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("verifier", "verifier", "sonnet",
                             "Local 3x reproduction, then remote flag extraction"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write knowledge/challenges/<name>.md writeup"))

    dag.add_edge("reverser", "trigger")
    dag.add_edge("trigger", "chain")
    dag.add_edge("chain", "critic")
    dag.add_edge("critic", "verifier")
    # Feedback edge: verifier can send back to chain on failure
    dag.add_edge("verifier", "chain", feedback=True)
    dag.add_edge("verifier", "reporter")

    return dag


def ctf_rev_pipeline(challenge_name: str = "challenge") -> AgentDAG:
    """
    CTF Reversing/Crypto 4-agent pipeline:
    reverser → solver → critic → verifier → reporter
    """
    dag = AgentDAG(name=f"ctf_rev_{challenge_name}", max_workers=1)

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Binary/VM/algorithm analysis",
                             effort="high", max_turns=40))
    dag.add_node(_make_node("solver", "solver", "opus",
                             "Reverse computation, solver implementation (z3/GDB oracle)",
                             effort="high", max_turns=50))
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Verify solver logic and address calculations",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("verifier", "verifier", "sonnet",
                             "Run solve.py, verify flag format"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write writeup"))

    dag.add_edge("reverser", "solver")
    dag.add_edge("solver", "critic")
    dag.add_edge("critic", "verifier")
    dag.add_edge("critic", "solver", feedback=True)  # critic→solver feedback
    dag.add_edge("verifier", "reporter")

    return dag


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
    dag.add_node(_make_node("scope_auditor", "scope-auditor", "opus",
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
    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "PoC development + Evidence Tier classification (E1-E4)",
                             effort="high", max_turns=60))

    # Phase 3
    dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                             "Draft report with CVSS"))

    # Phase 4 (parallel review)
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check: CWE, dates, function names, line numbers",
                             effort="high", max_turns=30))
    dag.add_node(_make_node("architect", "architect", "opus",
                             "Framing review: attacker perspective"))

    # Phase 4.5
    dag.add_node(_make_node("triager_sim", "triager_sim", "opus",
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
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Challenge target choice for scope violations, duplicate risk, and weak ROI",
                             effort="high", max_turns=20))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Write target shortlist, selected target, and safe pipeline plan"))

    dag.add_edge("target_discovery", "target_evaluator")
    dag.add_edge("target_evaluator", "critic")
    dag.add_edge("critic", "reporter")
    dag.add_edge("critic", "target_evaluator", feedback=True)

    return dag


def firmware_pipeline(firmware_name: str = "firmware") -> AgentDAG:
    """
    Firmware analysis pipeline:
    reverser → scanner (parallel: CVE+secrets) → exploiter → reporter
    """
    dag = AgentDAG(name=f"firmware_{firmware_name}", max_workers=3)

    dag.add_node(_make_node("reverser", "reverser", "sonnet",
                             "Firmware unpacking, filesystem extraction, binary inventory"))

    # Parallel scanning
    dag.add_node(_make_node("cve_scanner", "analyst", "sonnet",
                             "Service/library version → CVE matching via searchsploit"))
    dag.add_node(_make_node("secret_scanner", "scout", "sonnet",
                             "Hardcoded credentials, API keys, private keys via trufflehog"))
    dag.add_node(_make_node("code_scanner", "analyst", "sonnet",
                             "Static analysis: command injection, buffer overflow patterns"))

    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "PoC for highest-value findings"))
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "Firmware security report"))

    dag.add_edge("reverser", "cve_scanner")
    dag.add_edge("reverser", "secret_scanner")
    dag.add_edge("reverser", "code_scanner")
    dag.add_edge("cve_scanner", "exploiter")
    dag.add_edge("secret_scanner", "exploiter")
    dag.add_edge("code_scanner", "exploiter")
    dag.add_edge("exploiter", "reporter")

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
    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "AI/LLM PoC: jailbreak, injection chains, agent hijack (domain=ai)"))

    # Gate 2: PoC destruction
    dag.add_node(_make_node("gate2_triager", "triager_sim", "opus",
                             "Gate 2: PoC destruction (mode=poc-destruction, domain=ai)"))

    # Phase 3: Report
    dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                             "Draft report + CVSS + bugcrowd_form.md"))

    # Phase 4: Review
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check AI-specific claims, OWASP mapping verification"))

    # Phase 4.5: Report review
    dag.add_node(_make_node("triager_report", "triager_sim", "opus",
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


def robotics_pipeline(target_name: str = "target") -> AgentDAG:
    """
    Robotics/ROS pipeline (CVE track — no bounty gates):
    target_evaluator → robo_scanner+analyst (parallel) → exploiter
    → reporter(CVE advisory) → critic → cve_manager
    """
    dag = AgentDAG(name=f"robotics_{target_name}", max_workers=2)

    # Phase 0
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "Robot model, ROS version, network accessibility, existing CVEs"))

    # Phase 1 (parallel)
    dag.add_node(_make_node("robo_scanner", "robo-scanner", "sonnet",
                             "ROS topology, node enumeration, firmware extraction, network scan"))
    dag.add_node(_make_node("analyst", "analyst", "sonnet",
                             "ROS auth bypass, node spoofing, parameter tampering (domain=robotics)"))

    # Phase 2: PoC (no Gate 1 — CVE track uses critic as quality check)
    dag.add_node(_make_node("exploiter", "exploiter", "opus",
                             "Node injection, topic hijack, firmware exploit PoC (domain=robotics)"))

    # Phase 3: CVE advisory report
    dag.add_node(_make_node("reporter", "reporter", "sonnet",
                             "CVE advisory format: CVSS, CWE, affected versions, timeline, credit"))

    # Phase 4: Review (lighter — no triager-sim for CVE track)
    dag.add_node(_make_node("critic", "critic", "opus",
                             "Fact-check: CWE mapping, affected versions, PoC reproducibility"))

    # Phase 5: CVE submission
    dag.add_node(_make_node("cve_manager", "cve-manager", "sonnet",
                             "CVE eligibility check, GHSA/MITRE submission prep"))

    # Edges
    dag.add_edge("target_evaluator", "robo_scanner")
    dag.add_edge("target_evaluator", "analyst")
    dag.add_edge("robo_scanner", "exploiter")
    dag.add_edge("analyst", "exploiter")
    dag.add_edge("exploiter", "reporter")
    dag.add_edge("reporter", "critic")
    dag.add_edge("critic", "cve_manager")
    # Feedback: critic can send back to reporter for fixes
    dag.add_edge("critic", "reporter", feedback=True)

    return dag


def supplychain_pipeline(target_name: str = "target", bounty_mode: bool = True) -> AgentDAG:
    """
    Supply Chain pipeline with bounty/CVE track branching:
    - bounty_mode=True: full Prove Lane (Gate 1/2 + triager-sim + submission-review)
    - bounty_mode=False: CVE track (reporter → critic → cve_manager)
    """
    dag = AgentDAG(
        name=f"supplychain_{target_name}",
        max_workers=2,
    )

    # Phase 0
    dag.add_node(_make_node("target_evaluator", "target_evaluator", "sonnet",
                             "Package manager detection, dependency count, CI/CD platform, bounty check"))

    # Phase 1 (parallel)
    dag.add_node(_make_node("sc_scanner", "sc-scanner", "sonnet",
                             "SBOM generation, dependency tree, namespace conflicts, build pipeline"))
    dag.add_node(_make_node("analyst", "analyst", "sonnet",
                             "Dependency confusion, typosquatting, build pipeline analysis (domain=supplychain)"))

    if bounty_mode:
        # --- Bounty Track (with Gate 1/2) ---

        # Gate 1
        dag.add_node(_make_node("gate1_triager", "triager_sim", "sonnet",
                                 "Gate 1: finding viability (mode=finding-viability, domain=supplychain)"))

        # Phase 2
        dag.add_node(_make_node("exploiter", "exploiter", "opus",
                                 "Dependency confusion PoC, build pipeline exploit (domain=supplychain)"))

        # Gate 2
        dag.add_node(_make_node("gate2_triager", "triager_sim", "opus",
                                 "Gate 2: PoC destruction (mode=poc-destruction, domain=supplychain)"))

        # Phase 3-5
        dag.add_node(_make_node("reporter_draft", "reporter", "sonnet",
                                 "Draft report + CVSS + platform form"))
        dag.add_node(_make_node("critic", "critic", "opus",
                                 "Fact-check supply chain claims, package names, versions"))
        dag.add_node(_make_node("triager_report", "triager_sim", "opus",
                                 "Report review (mode=report-review, domain=supplychain)"))
        dag.add_node(_make_node("reporter_final", "reporter", "sonnet",
                                 "Final report + ZIP packaging"))

        # Edges — Bounty track
        dag.add_edge("target_evaluator", "sc_scanner")
        dag.add_edge("target_evaluator", "analyst")
        dag.add_edge("sc_scanner", "gate1_triager")
        dag.add_edge("analyst", "gate1_triager")
        dag.add_edge("gate1_triager", "exploiter")
        dag.add_edge("exploiter", "gate2_triager")
        dag.add_edge("gate2_triager", "reporter_draft")
        dag.add_edge("reporter_draft", "critic")
        dag.add_edge("critic", "triager_report")
        dag.add_edge("triager_report", "reporter_final")
        # Feedback
        dag.add_edge("triager_report", "reporter_draft", feedback=True)
        dag.add_edge("gate2_triager", "exploiter", feedback=True)
    else:
        # --- CVE Track ---

        # Phase 2: PoC (no gates)
        dag.add_node(_make_node("exploiter", "exploiter", "opus",
                                 "Dependency confusion PoC, build pipeline exploit (domain=supplychain)"))

        # Phase 3: CVE advisory
        dag.add_node(_make_node("reporter", "reporter", "sonnet",
                                 "CVE advisory format: CVSS, CWE, affected packages, remediation"))

        # Phase 4: Review
        dag.add_node(_make_node("critic", "critic", "opus",
                                 "Fact-check: package names, versions, PoC reproducibility"))

        # Phase 5: CVE submission
        dag.add_node(_make_node("cve_manager", "cve-manager", "sonnet",
                                 "CVE eligibility check, GHSA/MITRE submission prep"))

        # Edges — CVE track
        dag.add_edge("target_evaluator", "sc_scanner")
        dag.add_edge("target_evaluator", "analyst")
        dag.add_edge("sc_scanner", "exploiter")
        dag.add_edge("analyst", "exploiter")
        dag.add_edge("exploiter", "reporter")
        dag.add_edge("reporter", "critic")
        dag.add_edge("critic", "cve_manager")
        dag.add_edge("critic", "reporter", feedback=True)

    return dag


# Registry of all pipelines
PIPELINES = {
    "target_discovery": target_discovery_pipeline,
    "ctf_pwn": ctf_pwn_pipeline,
    "ctf_rev": ctf_rev_pipeline,
    "bounty": bounty_pipeline,
    "firmware": firmware_pipeline,
    "ai_security": ai_security_pipeline,
    "robotics": robotics_pipeline,
    "supplychain": supplychain_pipeline,
}


def get_pipeline(name: str, target: str = "target", **kwargs) -> AgentDAG:
    """Get a pipeline by name. Extra kwargs passed to factory (e.g. bounty_mode)."""
    if name not in PIPELINES:
        raise ValueError(f"Unknown pipeline '{name}'. Available: {list(PIPELINES.keys())}")
    return PIPELINES[name](target, **kwargs)
