# Team

Organizational structure for the PowerScanner project.

```
Human Owner
  │
  ▼
Claude — PM / Planner
  │
  ▼
Task Board (tasks/)
  │
  ▼
Codex — Engineering Manager
  │  choose agent + model
  ▼
Specialist Agent
  │  implement
  ▼
Codex Verify
  │
  ▼
Claude Review
  │
  ▼
Human Approval
```

## Engineering Manager layer (Codex)

```
Claude (PM)
  │  task board
  ▼
Codex — Engineering Manager (Workflow orchestration layer)
  │  analyze task → pick specialist → pick model → dispatch
  ├── Backend Agent    (5.6 Terra / 5.6 Sol for crypto)
  ├── Frontend Agent   (5.6 Terra)
  ├── Database Agent    (n/a Phase 1 — no DB)
  ├── DevOps Agent      (5.6 Terra — tooling/rule pipeline)
  ├── Security Agent    (5.6 Sol — independent review)
  └── Testing Agent     (5.6 Terra)
        │
        ▼
   Implementation → Codex verify → Claude review → Human approval → DONE
```

Codex is not a person here — it is the **Workflow script** that routes each task
to a specialist subagent with the model chosen by `.ai/MODEL_ROUTER.md`.

## Environment reality

- Model routing uses the named tiers `5.6 Sol`, `5.6 Terra`, and `5.6 Luna`.
  See `.ai/MODEL_ROUTER.md` for task-level routing.
- The PM (Claude) writes scaffolding/markdown/orchestration directly. Feature
  code is delegated to specialist subagents with task-appropriate models.
- **Independent review**: the reviewing model differs from the implementing model
  (impl `5.6 Terra` → review `5.6 Sol`), per Master Prompt §9.
- Ultracode is enabled: substantial work is orchestrated via Workflow, not ad-hoc.

## Roles

| Role | Owner | Responsibility |
|------|-------|----------------|
| Project Manager | Claude | plan, delegate, review, track, document |
| Engineering Manager | Codex | choose specialist agent + model, verify work |
| Engineering | Specialist agents | implement tasks per the task board |
| Human Owner | User | direction and final approval |
