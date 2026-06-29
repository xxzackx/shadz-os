# CLAUDE.md — SHADZ Project Operating Rules

These rules apply to every Claude Code task in the SHADZ project unless Mr.Zack explicitly overrides them.

Primary goal: reduce implementation mistakes, avoid unnecessary code changes, and protect the existing working production system.

SHADZ is a live production system. Bias toward caution over speed on non-trivial work. Use judgment on trivial tasks.

Current production system:
- FastAPI app behind Nginx
- Uvicorn service: shadz.service
- Project path on VPS: /opt/shadz-os/Desktop/shadz-os
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

## Rule 13 — Local repo safety (Mac)

The local Mac repo at `/Users/Who Am I/Desktop/shadz-os` has its `.git` root at the home directory, not the project folder. This is a known unresolved issue. Do NOT run `git add .` or any broad staging command from that path — it will surface private home-directory contents. Use the clean clone at `/Users/Who Am I/Desktop/shadz-os-clean` for all git operations and stage files explicitly by name only. Do not move `.git` or restructure the local repo without an explicit approved plan.
