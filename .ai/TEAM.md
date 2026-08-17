# Team

Organizational structure for the PowerScanner project.

```
CEO (Human)
  │
  ▼
Claude — Project Manager / Orchestrator
  ├── Product Manager (analysis)
  ├── Solution Architect (design review)
  ├── Security Agent (crypto / threat model review)
  ├── QA Agent (test verification)
  └── Technical Writer (docs)
        │
        ▼
     Task Board (tasks/)
        │
        ▼
Engineering Team (implemented via subagents in this environment)
  ├── Core Engine (Rust lib)
  ├── GUI (egui)
  ├── Crypto
  ├── Signatures / Rules
  └── Testing
```

## Environment reality

- **Codex** in the original org chart maps to **subagents** (general-purpose,
  Explore, Plan) dispatched by the PM in this environment. There is no separate
  Codex process here.
- The PM (Claude) may write scaffolding, markdown, and orchestration files
  directly. Feature/engineering code is delegated to subagents where practical.
- Ultracode is enabled: substantial engineering work is orchestrated, not done
  ad-hoc.

## Roles

| Role | Owner | Responsibility |
|------|-------|----------------|
| Project Manager | Claude | plan, delegate, review, track, document |
| Engineering | Subagents | implement tasks per the task board |
| CEO | Human | direction, final approval on gated decisions |
