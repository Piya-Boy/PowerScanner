#!/usr/bin/env python3
"""PowerScanner engineering loop.

Drives OpenAI Codex CLI (`codex exec`) task-by-task through the Phase 1 plan,
respecting the workflow in .ai/RULES.md:

    CLAUDE PLAN -> CODEX ROUTE -> CODEX EXECUTE -> CODEX VERIFY -> (report)

For each READY task (deps satisfied) it:
  1. routes an impl model from .ai/MODEL_ROUTER.md (via tasks/loop_tasks.json),
  2. builds a handoff prompt from the canonical plan + rules,
  3. runs `codex exec` non-interactively to implement it,
  4. verifies with the task's `verify` command (usually `cargo test`),
  5. on failure, escalates the model up the ladder (Luna->Terra->Sol) and retries
     ONCE per higher tier; a task still failing after Sol stops the loop for a
     human/PM decision (never silently skipped),
  6. records outcome to tasks/loop_state.json and appends to .ai/STATE.md.

This script never edits source itself and never commits — Codex does the work in
the shared repo; the loop only orchestrates, verifies, and records. Claude (PM)
still reviews the diff before anything is marked DONE.

Usage:
    python tools/engineering_loop.py                 # run until blocked/done
    python tools/engineering_loop.py --task TASK-001  # one task only
    python tools/engineering_loop.py --dry-run        # print prompts, run nothing
    python tools/engineering_loop.py --max 3          # at most 3 tasks this run
    python tools/engineering_loop.py --yes            # skip the pre-run confirm

Requires: `codex` and `cargo` on PATH. Python 3.10+.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TASKS_JSON = REPO / "tasks" / "loop_tasks.json"
STATE_JSON = REPO / "tasks" / "loop_state.json"
AI_STATE = REPO / ".ai" / "STATE.md"
PLAN = REPO / "docs" / "superpowers" / "plans" / "2026-08-17-powerscanner-phase1.md"

# Model escalation ladder (MODEL_ROUTER.md rule 3). A task starts at its routed
# tier; on verify failure it climbs, never repeating a tier.
LADDER = ["5.6 Luna", "5.6 Terra", "5.6 Sol"]

# The MODEL_ROUTER tiers (Luna/Terra/Sol) are ABSTRACT. This Codex/ChatGPT
# account only serves one concrete model (`gpt-5.5`); the *-codex and named
# tiers return HTTP 400 "not supported". We therefore realise the tiers as one
# model at three reasoning-effort levels — the ladder still climbs (more effort
# on retry), it just climbs effort instead of swapping models. Override with the
# PS_LOOP_MODEL env var if the account later gains more models.
import os

_MODEL = os.environ.get("PS_LOOP_MODEL", "gpt-5.5")
TIER_TO_EFFORT = {
    "5.6 Luna": "low",
    "5.6 Terra": "medium",
    "5.6 Sol": "high",
}


def resolve_model(tier: str) -> tuple[str, str]:
    """Map an abstract router tier to a concrete (model, reasoning_effort)."""
    return _MODEL, TIER_TO_EFFORT.get(tier, "medium")


def _now() -> str:
    return _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def preflight() -> list[str]:
    problems = []
    if shutil.which("codex") is None:
        problems.append("`codex` not on PATH (OpenAI Codex CLI required).")
    if shutil.which("cargo") is None:
        problems.append("`cargo` not on PATH (needed to verify Rust tasks).")
    if not TASKS_JSON.exists():
        problems.append(f"missing task metadata: {TASKS_JSON.relative_to(REPO)}")
    if not PLAN.exists():
        problems.append(f"missing canonical plan: {PLAN.relative_to(REPO)}")
    return problems


def tier_index(model: str) -> int:
    return LADDER.index(model) if model in LADDER else 1  # default to Terra slot


def escalation_chain(start_model: str) -> list[str]:
    """Models to try, in order, starting at the routed tier and climbing."""
    return LADDER[tier_index(start_model):]


def ready_tasks(tasks: list[dict], state: dict, extra_done: set[str] | None = None) -> list[dict]:
    """Tasks whose deps are all PASS and that are not themselves PASS yet.

    extra_done lets a dry run treat pretend-completed ids as satisfying deps
    without writing a real PASS to state.
    """
    done = {tid for tid, s in state.get("results", {}).items() if s.get("status") == "PASS"}
    done |= (extra_done or set())
    out = []
    for t in tasks:
        if t["id"] in done:
            continue
        if all(dep in done for dep in t.get("depends_on", [])):
            out.append(t)
    return out


def build_prompt(task: dict, model: str) -> str:
    """Handoff prompt fed to `codex exec`. Mirrors tasks/handoff/*.codex.md."""
    ac = "\n".join(f"  - {c}" for c in task.get("acceptance", []))
    files = "\n".join(f"  - {f}" for f in task.get("files", [])) or "  (see plan)"
    notes = task.get("notes", "")
    notes_block = f"\n## Task-specific guidance (overrides the plan where it conflicts)\n{notes}\n" if notes else ""
    return f"""You are the Engineering specialist on the PowerScanner project.
Implement {task['id']} — {task['title']} — EXACTLY per the canonical plan.
Do not change architecture or requirements. If the plan and reality conflict,
STOP and report BLOCKED; do not guess.

## Read first (source of truth, in priority order)
- docs/PRD.md, docs/ARCHITECTURE.md, docs/SECURITY.md
- .ai/RULES.md (hard constraints), .ai/MODEL_ROUTER.md
- {PLAN.relative_to(REPO).as_posix()} -> section for {task['id']} (exact code + tests)

## Objective
{task.get('objective', task['title'])}

## Files in scope
{files}
{notes_block}
## Method (TDD, per the plan)
1. Write the failing test(s) first.
2. Implement until they pass.
3. Run the verification command yourself before reporting.

## Acceptance criteria (ALL must hold)
{ac}

## Hard constraints
- Rust edition 2021, MSRV 1.74, Windows x64. `core` must not depend on any GUI crate.
- Authenticated encryption/signatures on all persisted files; no hardcoded keys/secrets.
- No `unwrap()`/`expect()` in library paths (tests excepted). No string concat into commands/paths.
- GIT BRANCH: you are ALREADY on the correct working branch. Do NOT run
  `git checkout`, `git switch`, or `git branch` — switching branches would
  discard prior tasks' work and the project tooling. Stay on the current branch.
- Do NOT `git add .` or `git add -A`. Stage ONLY the files in scope above.
- Conventional Commits. NO `Co-Authored-By` trailer. Author = git user.
- Commit atomically when the task is green: `{task.get('commit', 'feat: ' + task['title'])}`.

## Assigned model for this attempt: {model}

## Report at the end, verbatim block:
# Agent Result
## Task: {task['id']}
## Model: {model}
## Status: PASS | NEEDS_REVIEW | BLOCKED
## Changes: <files touched>
## Tests: <verify command output summary>
## Issues: <any>
"""


def run_codex(prompt: str, tier: str, sandbox: str, dry_run: bool) -> int:
    model, effort = resolve_model(tier)
    cmd = [
        "codex", "exec", prompt,
        "-m", model,
        "-c", f"model_reasoning_effort={effort}",
        "-C", str(REPO),
        "--skip-git-repo-check",
    ]
    # The Windows sandbox helper (codex-windows-sandbox-setup.exe) is absent in
    # this runtime, so `-s workspace-write` fails to launch ANY shell. The
    # account's own config already runs approval_policy=never +
    # danger-full-access, so the `bypass` sandbox is both what the operator set
    # and the only mode that starts here. `-s <mode>` remains selectable.
    if sandbox == "bypass":
        cmd.append("--dangerously-bypass-approvals-and-sandbox")
        shown = "--dangerously-bypass-approvals-and-sandbox"
    else:
        cmd[7:7] = ["-s", sandbox]  # insert after --skip-git-repo-check region
        shown = f"-s {sandbox}"
    print(f"  $ codex exec -m {model} -c model_reasoning_effort={effort} "
          f"({tier}) {shown} -C <repo>  (prompt {len(prompt)} chars)")
    if dry_run:
        print("  [dry-run] codex not invoked.")
        return 0
    # Inherit stdio so the operator sees Codex work in real time.
    return subprocess.run(cmd, cwd=REPO).returncode


def run_verify(task: dict, dry_run: bool) -> tuple[bool, str]:
    verify = task.get("verify")
    if not verify:
        return True, "(no verify command; skipped)"
    print(f"  $ {verify}")
    if dry_run:
        return True, "[dry-run] verify not run."
    proc = subprocess.run(verify, cwd=REPO, shell=True, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    tail = out.strip().splitlines()[-15:]
    if proc.returncode != 0:
        return False, "\n".join(tail)
    # `cargo test <filter>` exits 0 EVEN WHEN THE FILTER MATCHES NOTHING
    # ("running 0 tests"). That is how the loop previously recorded fake PASSes
    # for tasks Codex never implemented. For any task that declares it must run
    # tests (min_tests>0), require that many passing tests actually ran.
    min_tests = task.get("min_tests", 0)
    if min_tests > 0:
        import re
        passed = sum(int(m) for m in re.findall(r"(\d+) passed", out))
        if passed < min_tests:
            return False, (f"expected >= {min_tests} passing tests but only {passed} ran "
                           f"(likely the module/tests were never created).\n" + "\n".join(tail))
    return True, "\n".join(tail)


def append_ai_state(task: dict, status: str, model: str, note: str) -> None:
    if not AI_STATE.exists():
        return
    stamp = (
        f"\n\n---\n### Loop update {_now()}\n"
        f"- Task: {task['id']} — {task['title']}\n"
        f"- Result: **{status}** (model {model})\n"
        f"- Note: {note}\n"
    )
    with AI_STATE.open("a", encoding="utf-8") as fh:
        fh.write(stamp)


def process_task(task: dict, state: dict, args) -> str:
    print(f"\n=== {task['id']} — {task['title']} ===")
    routed = task.get("impl_model", "5.6 Terra")
    chain = escalation_chain(routed)
    last_note = ""
    for i, model in enumerate(chain):
        if i > 0:
            print(f"  ↑ escalating to {model} (previous tier failed verification)")
        rc = run_codex(build_prompt(task, model), model, args.sandbox, args.dry_run)
        if rc != 0 and not args.dry_run:
            last_note = f"codex exec exited {rc} on {model}"
            print(f"  ! {last_note}")
            continue
        ok, out = run_verify(task, args.dry_run)
        last_note = out.replace("\n", " | ")[:500]
        if ok:
            if args.dry_run:
                # A dry run proves nothing was built; never record a real PASS.
                print(f"  ~ [dry-run] would verify with {model} (state NOT written)")
                return "DRY"
            print(f"  ✓ verified with {model}")
            state.setdefault("results", {})[task["id"]] = {
                "status": "PASS", "model": model, "at": _now(), "note": "verified",
            }
            append_ai_state(task, "PASS", model, "verified; awaiting Claude review")
            return "PASS"
        print(f"  ✗ verify failed on {model}")
    # Exhausted the ladder.
    state.setdefault("results", {})[task["id"]] = {
        "status": "BLOCKED", "model": chain[-1], "at": _now(), "note": last_note,
    }
    append_ai_state(task, "BLOCKED", chain[-1], last_note or "failed after full escalation")
    return "BLOCKED"


def ensure_branch(branch: str, dry_run: bool) -> tuple[bool, str]:
    """Switch to (or create off current HEAD) the single working branch. All
    tasks run here; Codex is forbidden from switching branches, so this is the
    one place branch state is decided."""
    cur = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"],
                         cwd=REPO, capture_output=True, text=True).stdout.strip()
    if cur == branch:
        return True, f"already on {branch}"
    if dry_run:
        return True, f"[dry-run] would checkout {branch} (from {cur})"
    exists = subprocess.run(["git", "rev-parse", "--verify", "--quiet", branch],
                            cwd=REPO, capture_output=True, text=True).returncode == 0
    args = ["git", "checkout", branch] if exists else ["git", "checkout", "-b", branch]
    proc = subprocess.run(args, cwd=REPO, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()
    return True, f"on {branch} (from {cur}, {'existing' if exists else 'new'})"


def main() -> int:
    ap = argparse.ArgumentParser(description="PowerScanner Codex engineering loop.")
    ap.add_argument("--task", help="run only this task id (e.g. TASK-001)")
    ap.add_argument("--max", type=int, default=0, help="max tasks this run (0 = unlimited)")
    ap.add_argument("--dry-run", action="store_true", help="print prompts, run nothing")
    ap.add_argument("--yes", action="store_true", help="skip the pre-run confirmation")
    ap.add_argument("--branch", default="feature/phase1-impl",
                    help="single working branch for ALL tasks (created off the "
                         "current HEAD if absent). Codex is told never to switch "
                         "branches; the loop owns branch state so each task's "
                         "commits stack and deps actually build on each other.")
    ap.add_argument("--sandbox", default="bypass",
                    choices=["bypass", "read-only", "workspace-write", "danger-full-access"],
                    help="codex sandbox policy. Default 'bypass' uses "
                         "--dangerously-bypass-approvals-and-sandbox because the "
                         "Windows sandbox helper is missing in this runtime; the "
                         "account config already runs never/danger-full-access.")
    args = ap.parse_args()

    problems = preflight()
    if problems and not args.dry_run:
        print("Preflight failed:")
        for p in problems:
            print(f"  - {p}")
        return 2

    ok, msg = ensure_branch(args.branch, args.dry_run)
    print(f"Branch: {msg}")
    if not ok:
        print("Could not establish the working branch; aborting.")
        return 2

    meta = load_json(TASKS_JSON)
    tasks: list[dict] = meta.get("tasks", [])
    state = load_json(STATE_JSON)

    if args.task:
        tasks = [t for t in tasks if t["id"] == args.task]
        if not tasks:
            print(f"No such task: {args.task}")
            return 2

    processed = 0
    dry_done: set[str] = set()  # dry-run: pretend-completed ids so deps advance
    while True:
        if args.task:
            pending = [tasks[0]]
        else:
            pending = [t for t in ready_tasks(tasks, state, dry_done) if t["id"] not in dry_done]
        if not pending:
            done = sum(1 for r in state.get("results", {}).values() if r.get("status") == "PASS")
            print(f"\nNo READY tasks left. {done} PASS recorded. Loop done.")
            break

        task = pending[0]
        if not args.yes and not args.dry_run:
            ans = input(f"\nRun {task['id']} ({task['title']}) via Codex? [y/N] ").strip().lower()
            if ans != "y":
                print("Stopped by operator.")
                break

        result = process_task(task, state, args)
        if not args.dry_run:
            save_json(STATE_JSON, state)
        processed += 1

        if result == "DRY":
            dry_done.add(task["id"])
        if result == "BLOCKED":
            print(f"\n⛔ {task['id']} BLOCKED after full model escalation.")
            print("   Escalating to PM (Claude) / Human Owner per MODEL_ROUTER rule 3. Loop halts.")
            return 1
        if args.task:
            break
        if args.max and processed >= args.max:
            print(f"\nReached --max {args.max}. Stopping.")
            break

    if not args.dry_run:
        save_json(STATE_JSON, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
