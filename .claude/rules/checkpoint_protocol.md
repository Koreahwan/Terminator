## Agent Checkpoint Protocol (MANDATORY)

All work agents (chain, solver, exploiter, analyst, reverser, trigger) must:
- **On start**: write `{"status":"in_progress", "phase":1, ...}`
- **On phase complete**: update (add to completed array, increment phase)
- **On full complete**: `"status":"completed"` + verify produced_artifacts
- **On error**: `"status":"error"` + error message

Required fields: `agent, status, phase, phase_name, completed, in_progress, critical_facts, expected_artifacts, produced_artifacts, timestamp`

Location: CTF=`<challenge_dir>/checkpoint.json`, BB=`targets/<target>/checkpoint.json`

### Orchestrator Idle Recovery
```
1. Read checkpoint.json
2. status=="completed" → verify artifacts exist → proceed
3. status=="in_progress" → FAKE IDLE. Send resume message once → still idle → respawn with checkpoint
4. status=="error" → fix environment → respawn
5. No checkpoint → agent never started → respawn immediately
```
**NEVER assume "artifact file exists = completed".** Only trust `status=="completed"`.
