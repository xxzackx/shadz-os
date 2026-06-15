# SHADZ — Project State

## Mission

SHADZ is a physical-digital private system brand.
NFC / physical touch becomes a controllable digital command system.
Not just NFC keychains — the platform is the command layer between physical objects and digital destinations.

---

## Architecture

| Layer | Technology |
|---|---|
| Application | FastAPI + Uvicorn |
| Process manager | systemd (`shadz.service`) |
| Reverse proxy | Nginx |
| Database | SQLite |
| Media storage | Cloudflare R2 |
| R2 bucket | `shadz-media` |
| R2 public domain | `media.shadz.io` |

**Uvicorn bind:**
```
/usr/local/bin/uvicorn main:app --host 127.0.0.1 --port 8000
```

Nginx proxies HTTPS traffic to `127.0.0.1:8000`.

---

## VPS

- Project path: `/opt/shadz-os/Desktop/shadz-os`
- systemd service: `shadz.service`

Useful commands:
```bash
sudo systemctl restart shadz.service
sudo systemctl status shadz.service
sudo journalctl -u shadz.service -n 50
```

---

## Live URLs

| Purpose | URL |
|---|---|
| Main site | https://shadz.io/ |
| Admin UI | https://shadz.io/admin |
| Health check | https://shadz.io/health |
| Media domain | https://media.shadz.io |

---

## Redirect Flow

NFC chips store a SHADZ slug URL, not the final destination URL.

```
NFC chip → shadz.io/{slug} → Nginx → FastAPI → DB lookup → destination redirect
```

- Scan count increments on each redirect hit.
- Slug format: `{content_type}-{randomID}` (e.g. `url-a1b2c3`, `media-x9y8z7`).
- Current content types: `url`, `media`, `page`.

---

## Admin System

- UI: `static/admin.html` (single-file, no build step)
- Auth: HTTP Basic Auth via browser popup
- Unauthenticated requests to `/admin` must return `401`
- No logout button yet — browser handles session
- Future: proper UI login/logout system

**Admin capabilities:**
- Create new SHADZ links (slug + client info)
- Update redirect destination for a slug
- Check Slug Info by phone/contact number
  - Destination row: View Full (inline expand) + Open ↗ (new tab) — `url` and `page` slugs only (Patch 5.2)
  - Archive slug (soft archive, recoverable) — Phase 2
  - Restore slug (clears archive state) — Phase 2
  - Show Archived toggle (active-only default; opt-in archived view) — Phase 2
  - Bulk Archive selected slugs — Patch 5
  - Bulk Restore selected slugs — Patch 5
  - Select All Visible result cards — Patch 5.1
  - Clear Selection — Patch 5.1
- Edit client info (name, phone, notes)
- Upload media assets to R2
- Attach / detach media assets to media slugs
- Storage Manager (browse all assets)
- Convert URL ↔ Media type — Phase 3 v0.1
- Export CSV — download all link/client records as CSV — Phase C

**Admin UI version:** Hotfix `edb2c2c` — Redirect update phone validation fix (deployed 2026-06-16), on top of Phase C CSV Export (`45d2656`, deployed 2026-06-13)

---

## Database Schema — Live State

### `redirect_links`

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER | PK |
| `slug` | VARCHAR | unique, indexed |
| `destination_url` | VARCHAR | not null |
| `scan_count` | INTEGER | default 0 |
| `content_type` | VARCHAR | url / media / page; nullable (legacy rows) |
| `client_name` | VARCHAR | nullable |
| `phone_number` | VARCHAR | indexed; nullable |
| `notes` | TEXT | nullable |
| `is_archived` | BOOLEAN | nullable — `NULL` treated as active (added Phase 2) |
| `archived_at` | DATETIME | nullable — set on archive, cleared on restore (added Phase 2) |
| `created_at` | DATETIME | |
| `updated_at` | DATETIME | |

### `media_assets`

One row per uploaded R2 file. Soft-deleted via `is_deleted=True`. Never auto-removed from R2.

### `slug_media`

Join between `redirect_links.slug` and `media_assets.id`. History preserved; only one row per slug has `is_active=True`.

### `nfc_records` / `scan_logs`

Legacy NFC system. Unchanged since v0.1.

---

## Media System

- Upload flow: Admin → presigned R2 PUT → confirm to FastAPI → `MediaAsset` row created
- Attach flow: Admin links `MediaAsset` to a `media` slug
- Render flow: `/{slug}` for media type serves the attached asset
- Detach: unlinks asset from slug; slug shows "Media not ready yet"
- Delete safety: deleting a `MediaAsset` still linked to active slugs is blocked

---

## Auth State

- Basic Auth is live and working
- Visually ugly (browser native popup)
- Acceptable for current private admin use
- Future hardening: UI login/logout, session management, role-based access

---

## Safe Operating Rules

- Do NOT use `curl -I` or HEAD-method requests to verify SHADZ routes. FastAPI routes currently only allow GET — HEAD returns `405 Method Not Allowed`. Use GET-based checks: `curl -s -o /dev/null -w "%{http_code}\n" <url>`
- URL content type is allowed to point at any destination including `media.shadz.io` for now — only admin can edit links
- Do not add backend validation blocking URL type from pointing to `media.shadz.io` until: client portal, staff roles, multi-admin, or API-based link creation is added
- Do not modify `main.py` unless the task explicitly requires backend changes
- Do not modify database models unless the task explicitly requires a migration
- Nginx config and systemd config should not be touched without a specific infra task
- Always verify `/admin` returns 401 unauthenticated after any auth-adjacent change
- `HEAD` or unsupported HTTP methods returning 405 is expected behavior, not a bug

---

## Known Issues

| Issue | Status |
|---|---|
| Basic Auth popup is ugly | Accepted, deferred |
| No clean logout / session flow | Deferred |
| No analytics / scan tracking chart | Planned |
| No role-based access control | Deferred until multi-admin needed |

---

## Front Page Hero State

**SHADZ Front Page v0.1.2 — Hero Logo Core Patch** — Deployed

- Hero visual replaced with final S-core emblem (`static/assets/shadz-logo-core.png`) + separate SHADZ wordmark layer (`static/assets/shadz-wordmark.png`)
- Core is animated/floating (CSS keyframe + subtle JS cursor tilt on hover)
- Wordmark is stable/static — no float animation
- Assets are true transparent PNGs stored under `static/assets/`
- Front page remains lightweight CSS + vanilla JS — no Three.js or heavy dependencies
- Mobile-first layout approved: logo stacks above hero copy, wordmark tightly grouped below core
- Hero assets served from `/static/assets/` — both return `200` in production
- Production Nginx has a `location ^~ /static/` alias route pointing to `/opt/shadz-os/Desktop/shadz-os/static/` (added manually on VPS)
- Backend / admin / redirect / media systems unchanged

---

## DevOps / Claude Code Rules

A root-level `CLAUDE.md` file now defines the mandatory operating rules for Claude Code in this project.

Purpose:
- reduce implementation mistakes
- avoid overengineering
- enforce read-before-write
- enforce surgical changes
- require verification before claiming completion
- prevent silent skipped tests or hidden uncertainty
- protect the live SHADZ production system

---

## Execution Context / Guardrails

This section exists to give Claude Code a compressed snapshot of current project state and active constraints. It is not a roadmap or task queue. Do not infer permission to start future work from anything written here.

### Completed milestones

- Link Lifecycle Control (Phase 2) — archive, restore, 410 expired page, no-cache headers — complete
- Bulk Archive / Bulk Restore (Patch 5) — complete
- Select All / Clear Selection (Patch 5.1) — complete
- Media Destination Row Fix (Patch 5.2, `b388288`, deployed 2026-06-01) — Admin result cards now show Destination row only for `url` and `page` slugs, not `media` slugs
- Type Conversion v0.1 (Phase 3, `660ac44`, deployed 2026-06-03) — URL ↔ Media conversion live; slug identity permanent, content_type controls behavior
- Admin Create Validation (Phase B, `0268da1`, deployed 2026-06-13) — phone_number required when creating new links/client records; trimmed before save; backend rejects missing/blank on create; existing-link redirect updates do not require phone after hotfix `edb2c2c`
- Admin CSV Export (Phase C, `45d2656`, deployed 2026-06-13) — protected GET /admin/links/export.csv; default exports all records including archived; optional include_archived and q filters; CSV includes slug/client/link/media/admin review fields; Export CSV button near top of admin panel; no schema migration
- Admin Hotfix — Redirect Update Phone Regression (`edb2c2c`, deployed 2026-06-16) — `upsert_link` update branch no longer requires phone_number; phone preserved if not provided; create flow still requires phone; no frontend change; no schema migration

### Active slug type policy

- Current official slug types: `url`, `media`, `page`
- `url` — behavior controlled by `destination_url`; admin shows Destination row with View Full / Open ↗
- `media` — behavior controlled by active `SlugMedia` / `MediaAsset` attachment; admin hides Destination row entirely
- `page` — reserved for future SHADZ-hosted internal landing page / mini site / Page Engine; until Page Engine exists, `page` temporarily keeps Destination row behavior
- **`slug` = permanent NFC identity; `content_type` = current behavior; `destination_url` = preserved even when slug converts to media**

### Type Conversion rules (v0.1)

- `url → media`: allowed; `destination_url` preserved; no media auto-attached; public shows media-not-ready until media attached
- `media → url`: requires `destination_url`; blocked if active `SlugMedia` exists (must detach first); public redirects on success
- `page` conversion: rejected in v0.1
- `null` / legacy `content_type`: conversion rejected
- Media attach endpoint guard unchanged: only `content_type == "media"` slugs can attach media
- Public redirect route: branches on `content_type`, not slug prefix — slug string never changes

### Not yet implemented

- Type Conversion v0.2 — page conversion, extended conversion rules (not started)
- Analytics / Scan Tracking Chart — not started
- Page Engine — not started
- Proper UI login/logout system — deferred; Basic Auth popup is accepted for now
- Role-based admin security — deferred until multi-admin use case arises

### Guardrails for future sessions

- Future work must be explicitly prompted per session
- Do not infer or start roadmap tasks from this document
- Do not implement Analytics, Page Engine, login/logout, or any other future feature unless the current prompt explicitly asks for it
- Do not modify `main.py`, database schema, Nginx, or auth unless the task explicitly requires it
- Always verify `/`, `/admin` (→ 401), `/health` (→ 200) after any deploy using GET-based curl only
