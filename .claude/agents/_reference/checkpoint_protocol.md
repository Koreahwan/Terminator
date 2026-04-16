# Agent Checkpoint Protocol

All agents MUST maintain checkpoint.json at the start and throughout execution.

## Checkpoint Structure

```json
{
  "agent": "<agent_name>",
  "status": "in_progress|completed|error",
  "phase": 1,
  "phase_name": "<descriptive_phase>",
  "completed": [],
  "in_progress": "<current_step>",
  "critical_facts": [],
  "expected_artifacts": [],
  "produced_artifacts": [],
  "timestamp": "<ISO8601>"
}
```

## Checkpoint Lifecycle

**On Start:**
```json
{
  "agent": "reverser",
  "status": "in_progress",
  "phase": 1,
  "phase_name": "Binary Structure Analysis",
  "completed": [],
  "in_progress": "Loading binary and extracting metadata",
  "critical_facts": [],
  "expected_artifacts": ["reversal_map.md"],
  "produced_artifacts": [],
  "timestamp": "2026-04-03T10:30:00Z"
}
```

**On Phase Complete:**
- Add step name to `completed[]`
- Increment `phase`
- Update `phase_name`
- Update `in_progress` with next step

**On Full Completion:**
- Set `status`: `"completed"`
- Populate `produced_artifacts[]` with all file paths
- Verify: `produced_artifacts` matches `expected_artifacts`

**On Error:**
- Set `status`: `"error"`
- Add `"error_message": "<description>"`
- Include recovery suggestion if available

## Location Rules

- **CTF challenges**: `<challenge_dir>/checkpoint.json`
- **Bug Bounty**: `targets/<target>/checkpoint.json`

## Orchestrator Recovery

1. Read checkpoint.json
2. `status=="completed"` → verify artifacts exist → proceed
3. `status=="in_progress"` → FAKE IDLE if no new files → respawn with checkpoint
4. `status=="error"` → fix environment → respawn
5. No checkpoint → agent never started → spawn immediately

**CRITICAL**: Never assume artifact file exists = completed. Trust only `status=="completed"`.
