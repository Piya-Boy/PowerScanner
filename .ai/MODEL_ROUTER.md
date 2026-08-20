# MODEL_ROUTER

Maps a task's domain + complexity to a specialist role and a concrete model
available in **this** environment. No assumed model names.

## Available models (verified in this environment)

The abstract tiers below drive routing. **Reality check (2026-08-20):** the Codex
CLI on this ChatGPT account serves exactly one concrete model, `gpt-5.5`. The
named `*-codex` and tier-named models return HTTP 400 "not supported". The
engineering loop (`tools/engineering_loop.py`) therefore realises each tier as
`gpt-5.5` at a different **reasoning effort**, not a different model:

| Tier | Concrete | Effort | Use |
|-------|----------|--------|-----|
| `5.6 Sol` | `gpt-5.5` | high | architecture, crypto, security, review, hard debugging |
| `5.6 Terra` | `gpt-5.5` | medium | backend, frontend, testing, tooling |
| `5.6 Luna` | `gpt-5.5` | low | simple refactor, documentation, mechanical tasks |

Override the concrete model with the `PS_LOOP_MODEL` env var if the account later
gains more models. The escalation ladder (rule 3) then climbs effort low→med→high.

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
| TASK-015 encrypted sig load (portable key) | crypto+backend | 5.6 Sol | 5.6 Sol |
| TASK-016 signed results wire | backend | 5.6 Terra | 5.6 Sol |
| TASK-017 docs | docs | 5.6 Luna | 5.6 Terra |
| TASK-018 rule pipeline | devops/tooling | 5.6 Terra | 5.6 Sol |
| TASK-019 build-time seal / Defender-safe ship | crypto+devops | 5.6 Sol | 5.6 Sol |
