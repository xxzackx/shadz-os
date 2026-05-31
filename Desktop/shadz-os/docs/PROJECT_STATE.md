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
  - Destination row: View Full (inline expand) + Open ↗ (new tab) — v0.2.3 Phase 1
  - Archive slug (soft archive, recoverable) — Phase 2
  - Restore slug (clears archive state) — Phase 2
  - Show Archived toggle (active-only default; opt-in archived view) — Phase 2
- Edit client info (name, phone, notes)
- Upload media assets to R2
- Attach / detach media assets to media slugs
- Storage Manager (browse all assets)

**Admin UI version:** v0.2.3 Phase 2 — Link Lifecycle Control + Hotfix 4.1 (`5a744ae`, deployed 2026-05-31)

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

## Current Priorities

### Next: Patch 5 — Bulk Archive / Bulk Restore

**Target files:** `static/admin.html` (frontend) + `main.py` (backend)

Requirements:
1. Bulk selection checkboxes on Check Slug Info result cards
2. Selected count / action bar (shows how many selected)
3. Bulk Archive button
4. Bulk Restore button
5. Backend: `POST /admin/links/bulk-archive` endpoint
6. Backend: `POST /admin/links/bulk-restore` endpoint
7. Single Archive / Restore buttons must remain working
8. Show Archived toggle must remain working
9. Preserve v0.2.3 result card layout (2-column grid, equal height, bottom-pinned actions)
10. Preserve Destination row View Full / Open ↗ actions
11. Preserve Active Media panel
12. Preserve Edit Info flow
13. Do NOT touch Storage Manager
14. Do NOT touch Media Engine
15. Do NOT change public redirect behavior
16. Do NOT change Basic Auth
17. Do NOT hard delete slugs
18. `NULL is_archived` must be treated as active throughout
19. Bulk restore must support 100+ slugs (clients may have many keychains)
20. Test with test slugs first before touching live client slugs

### Backlog

1. Analytics / scan tracking chart
2. Proper UI login/logout system
3. Role-based admin security
