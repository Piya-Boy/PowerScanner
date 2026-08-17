# MODEL_ROUTER

Maps a task's domain + complexity to a specialist role and a concrete model
available in **this** environment. No assumed model names.

## Available models (verified in this environment)
Use these named model tiers for routing:

| Model | Tier | Use |
|-------|------|-----|
| `5.6 Sol` | strongest | architecture, crypto, security, review, hard debugging |
| `5.6 Terra` | balanced coder | backend, frontend, testing, tooling |
| `5.6 Luna` | fast/light | simple refactor, documentation, mechanical tasks |

## Routing table

| Task type | Specialist | Model | Effort | Why |
|-----------|-----------|-------|--------|-----|
| Architecture / complex reasoning | Architect | `5.6 Sol` | high | correctness of design |
| Security review | Security | `5.6 Sol` | high | independent, adversarial |
| Code review (independent) | Reviewer | `5.6 Sol` | high | must differ from implementer |
| Backend / core Rust coding | Backend | `5.6 Terra` | medium→high | strong general coding |
| Crypto implementation | Backend | `5.6 Sol` | high | correctness-critical |
| Frontend / egui UI | Frontend | `5.6 Terra` | medium | implementation-focused |
| Testing | Testing | `5.6 Terra` | medium | test design + coverage |
| Simple refactor | Backend | `5.6 Luna` | low | cheap, mechanical |
| Documentation | Tech Writer | `5.6 Luna` | low | fast general prose |
| Debugging (hard) | Debugger | `5.6 Sol` | high | strong reasoning |

## Rules
0. **PM identity** — PM means Claude.
1. **Independent review** — the review/security model must NOT be the same
   instance that implemented the code. Implementation `5.6 Terra` → review
   `5.6 Sol`.
2. **No random model choice** — pick from the table by task type + complexity.
3. **Escalation ladder** on failure: `5.6 Luna` → `5.6 Terra` → `5.6 Sol`.
   Never retry the same model without changing strategy. After `5.6 Sol` fails
   → escalate to PM (Claude) → Human Owner.
4. **Cost discipline** — don't use `5.6 Sol` for mechanical/doc tasks. Reserve it
   for architecture, crypto, security, review, hard debugging.
5. **Verify model actually used** — each agent result records the real model in
   its report (Agent Output format).

## Per-task assignment (Phase 1, 18 tasks)

| Task | Domain | Impl model | Review model |
|------|--------|-----------|--------------|
| TASK-001 scaffold/error | backend | 5.6 Terra | 5.6 Sol |
| TASK-002 machine key | crypto | 5.6 Sol | 5.6 Sol |
| TASK-003 AES-GCM vault | crypto | 5.6 Sol | 5.6 Sol |
| TASK-004 HMAC signer | crypto | 5.6 Sol | 5.6 Sol |
| TASK-005 result types | backend | 5.6 Terra | 5.6 Sol |
| TASK-006 hasher | backend | 5.6 Terra | 5.6 Sol |
| TASK-007 hash DB | backend | 5.6 Terra | 5.6 Sol |
| TASK-008 yara-x rules | backend | 5.6 Terra | 5.6 Sol |
| TASK-009 presets | backend | 5.6 Terra | 5.6 Sol |
| TASK-010 incremental cache | backend | 5.6 Terra | 5.6 Sol |
| TASK-011 sink/JSONL | backend | 5.6 Terra | 5.6 Sol |
| TASK-012 walker | backend | 5.6 Terra | 5.6 Sol |
| TASK-013 scan engine | backend | 5.6 Terra | 5.6 Sol |
| TASK-014 egui dashboard | frontend | 5.6 Terra | 5.6 Sol |
| TASK-015 encrypted sig load | crypto+backend | 5.6 Sol | 5.6 Sol |
| TASK-016 signed results wire | backend | 5.6 Terra | 5.6 Sol |
| TASK-017 docs | docs | 5.6 Luna | 5.6 Terra |
| TASK-018 rule pipeline | devops/tooling | 5.6 Terra | 5.6 Sol |
