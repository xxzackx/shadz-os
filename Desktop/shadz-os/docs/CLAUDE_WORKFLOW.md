# SHADZ — Claude Code Workflow

Rules and operating procedure for all Claude Code sessions on this project.

---

## Canonical Claude Code Rules

The root-level `CLAUDE.md` file is now the canonical operating rules file for Claude Code in the SHADZ project.

Claude Code must read and follow `CLAUDE.md` before making non-trivial changes.

The SHADZ execution pattern remains:

Inspect → Plan → Write → Diff → Verify → Commit → Deploy only when approved.

---

## Core Sequence

Every task follows this order without exception:

1. **Inspect** — read the relevant file(s) before writing anything
2. **Plan** — identify exact targets: file, class, function, line range
3. **Write** — implement the minimum required change
4. **Diff** — run `git diff` and confirm only the intended files changed
5. **Report** — show changed sections and wait for approval
6. **Commit / Deploy** — only after explicit user approval

Never skip steps. Never write code before the plan is approved. Never deploy without being told to.

---

## Approval Gates

| Action | Requires approval |
|---|---|
| Writing code | Yes — plan must be approved first |
| Committing | Yes — user must say commit |
| Pushing | Yes — user must say push or deploy |
| Creating migrations | Yes — describe the migration first |
| Touching Nginx or systemd | Yes — describe the change first |

---

## File Protection Rules

**Do not modify these unless the task explicitly requires it:**

- `main.py` — backend logic, routes, endpoints, models, auth
- `database.py` — schema and migrations
- `models.py` — SQLAlchemy models
- `requirements.txt` — dependencies
- Nginx config files
- systemd unit files (`shadz.service`)
- `.env` / environment files
- `docker-compose.yml`, `Dockerfile`

**Safe to modify for UI/UX tasks:**
- `static/admin.html`
- `static/index.html`

---

## Backend Rules

- Do not change endpoints unless the task is a backend task
- Do not change HTTP methods
- Do not change auth behavior
- Do not change fetch URLs in frontend JS — they must match existing backend routes
- Do not rename or restructure database fields without a migration plan
- Credentials: all fetch calls use `credentials: 'same-origin'` — do not change this

---

## Auth Protection

- `/admin` must always return `401` for unauthenticated requests
- Do not bypass, weaken, or restructure Basic Auth without an explicit auth task
- Do not add any unauthenticated admin endpoints
- Future login/logout UI work is deferred — do not build it speculatively

---

## Diff Verification

Before reporting any task as complete, always run:

```bash
git diff --stat
git diff -- <changed file>
git diff --check
```

Confirm:
- Only the intended files appear in the diff
- No trailing whitespace errors
- No unintended deletions

If `git diff` shows unexpected changes, stop and investigate before proceeding.

---

## Post-Deploy Checks

After any deploy, verify with:

```bash
curl -I https://shadz.io/
curl -i https://shadz.io/health
curl -I https://shadz.io/admin
```

Expected results:

| Endpoint | Expected |
|---|---|
| `GET /` | `200 OK` |
| `GET /health` | `200 OK` with JSON body |
| `GET /admin` (no auth) | `401 Unauthorized` |
| `GET /admin` (with auth) | `200 OK` |

---

## Known Non-Bugs

- `HEAD` requests to most endpoints return `405 Method Not Allowed` — this is expected FastAPI behavior, not a bug
- Basic Auth browser popup is ugly — this is a known accepted state, not a regression
- Storage Manager shows only non-deleted assets — this is intentional behavior from v0.1.2

---

## Deployment Procedure

```bash
# On VPS
cd /opt/shadz-os/Desktop/shadz-os
git pull origin master
sudo systemctl restart shadz.service
sudo systemctl status shadz.service
```

Nginx does not need to restart for application code changes.
Nginx restart is only needed for Nginx config changes.

---

## Git Hygiene

- Commit message should describe the milestone version and intent
- Always use `git diff --check` before committing
- Do not force-push to `master`
- Do not amend commits that have already been pushed
- Worktree branches push to `master` via: `git push origin HEAD:master`

---

## Scope Discipline

- Do not add features, refactor, or introduce abstractions beyond what the task requires
- Do not add error handling for scenarios that cannot happen
- Do not add comments explaining what code does — only add comments for non-obvious WHY
- Do not create planning files or analysis documents unless explicitly asked
- Do not speculate about future requirements in code

---

## SHADZ Brand Reminder

The admin UI is a premium black/gold private command system.
- Sharp, controlled, high-contrast
- Not playful, not SaaS template, not a raw database dump
- Information density must be managed — compact panels, truncated values, no data sprawl
- Every UI change should feel like a command module, not a form
