# CLAUDE.md — SHADZ Project Operating Rules

These rules apply to every Claude Code task in the SHADZ project unless Mr.Zack explicitly overrides them.

Primary goal: reduce implementation mistakes, avoid unnecessary code changes, and protect the existing working production system.

SHADZ is a live production system. Bias toward caution over speed on non-trivial work. Use judgment on trivial tasks.

Current production system:
- FastAPI app behind Nginx
- Uvicorn service: shadz.service
- Project path on VPS: /opt/shadz-os
- Domain: https://shadz.io
- Admin: /admin protected by Basic Auth
- Database: SQLite
- Media storage: Cloudflare R2
- Media domain: media.shadz.io
- Core systems: Redirect Engine, Admin Core, Slug Naming System, Media Engine, Storage Manager

Default SHADZ workflow:
1. Inspect before writing.
2. Explain assumptions.
3. Make surgical changes only.
4. Verify locally where possible.
5. Show diff.
6. Ask before deploy unless Mr.Zack explicitly approved deployment.
7. After deploy, verify /, /health, /admin, and affected feature paths.

## Rule 0 — Production Safety First

SHADZ is a live production system. Do not deploy, restart services, alter Nginx, touch database schema, or modify authentication/security behavior unless the task explicitly requires it and Mr.Zack approves.

Before any risky action, state:
- what will be touched
- what can break
- rollback plan
- verification commands

## Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

## Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

## Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

## Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

## Rule 5 — Use the model only for judgment calls
Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

## Rule 6 — Token budgets are not advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

## Rule 8 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

## Rule 9 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

## Rule 10 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

## Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

## Rule 12 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

## Rule 13 — Local and VPS repo safety (resolved Phase T1A — 2026-06-30)

**Canonical local repo root:** `~/Desktop/shadz-os`
**Canonical VPS app/repo root:** `/opt/shadz-os`

Do NOT use any nested path of the form `…/Desktop/shadz-os/Desktop/shadz-os` or `/opt/shadz-os/Desktop/shadz-os` — these were the old nested layouts eliminated in Phase T1A. All project files now live directly at the repo root.

**Verify root before any git or VPS operation:**
```bash
pwd                   # local: ~/Desktop/shadz-os | VPS: /opt/shadz-os
git status --short    # confirm clean or expected changes
ls CLAUDE.md          # CLAUDE.md must exist here — if not, you are in the wrong place
```

For all git operations, stage files explicitly by name. Never use `git add .` or `git add -A`.

After `sudo systemctl restart shadz.service`, do not immediately run public curl checks — wait/poll local health (`curl http://127.0.0.1:8000/health`) until it returns 200, then run public checks.
