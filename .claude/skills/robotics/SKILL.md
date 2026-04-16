---
name: robotics
description: Start Robotics/ROS security testing pipeline. Auto-matches "robotics", "ROS", "robot security", "ROS2", "industrial robot"
argument-hint: [target-ip-or-ros-master-uri] [robot-model]
---

Launch Robotics/ROS Security pipeline via terminator.sh:

```bash
./terminator.sh robotics <ros-master-uri-or-ip> [robot-model]
```

Pipeline: `robotics` from `tools/dag_orchestrator/pipelines.py` (CVE track)
- Phase 0: target-evaluator (robot model, ROS version, existing CVEs)
- Phase 0.2: `python3 tools/bb_preflight.py init targets/<target>/ --domain robotics`
- Phase 0.5: robo-scanner (ROS topology auto-scan, Docker fallback for ROS2)
- Phase 1: robo-scanner + analyst(domain=robotics) in parallel
- Phase 1.5: fw-profiler → fw-inventory → fw-surface (firmware deep dive, optional)
- Phase 2: exploiter(domain=robotics) — simulator-first PoC
- Phase 3: reporter (CVE advisory format, credit: Kyunghwan Byun)
- Phase 4: critic (fact-check CWE, affected versions)
- Phase 5: cve-manager (GHSA/MITRE submission prep)

No bounty gates — CVE track uses critic as quality check.
Domain config: `--domain robotics` (threshold 70%, robo_endpoint_map.md)
Time-box: ~6.5hr. Docker: `docker run --rm --network host ros:humble`
