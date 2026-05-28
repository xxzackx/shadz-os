# SHADZ — Changelog

---

## 2026-05-28 — Add Claude Code operating rules

**Status:** Complete

**Summary:**
Added root-level `CLAUDE.md` containing the SHADZ Claude Code operating rules.

The rules enforce:
- production safety first
- think before coding
- simplicity first
- surgical changes
- goal-driven execution
- read before write
- checkpointing
- codebase convention matching
- fail-loud reporting

This is documentation/workflow only. No runtime code, backend, frontend, database, Nginx, service, or deployment changes.

**Touched:** `CLAUDE.md` (new), `docs/CLAUDE_WORKFLOW.md`, `docs/PROJECT_STATE.md`, `docs/CHANGELOG.md`
**Backend:** untouched
**Frontend:** untouched
**Endpoints:** untouched

---

## Front Page v0.1.2 — Hero Logo Core Patch

**Date:** 2026-05-10
**Status:** Complete, deployed, mobile-approved

**Summary:**
Replaced the CSS circular artifact in the hero section with two separate production assets: a floating animated core emblem and a stable SHADZ wordmark. Hero copy and CTA are unchanged.

**Changes:**
- Removed old CSS `.hero-wordmark` large "SHADZ" text from hero copy column
- Added `<img class="logo-img">` — `static/assets/shadz-logo-core.png` (transparent PNG, floating/animated)
- Added `<img class="wordmark-img">` — `static/assets/shadz-wordmark.png` (transparent PNG, stable/static)
- Core emblem: CSS float keyframe + subtle JS cursor tilt on hover (`hover: hover` gated)
- Wordmark: no float animation; `scaleY(1.12)` for stronger vertical presence; tightly grouped below core via negative `margin-top` calc
- Introduced `--logo-size` CSS custom property (decoupled from `--artifact-size` used by scan rings)
- Tuned all responsive breakpoints: desktop 280px core / 360px wordmark, tablet 195px / 285px, 540px 162px / 240px, 380px 130px / 195px
- Reduced mobile `.hero-inner` gap from `3rem` to `1.5rem` to tighten wordmark-to-eyebrow spacing
- `prefers-reduced-motion` gates all CSS animations; `hover: hover` gates JS tilt
- Mobile hero layout approved (logo above copy, single-column stack)

**Assets added:**
- `static/assets/shadz-logo-core.png`
- `static/assets/shadz-wordmark.png`

**Production deploy note:**
Nginx on VPS required a new `location ^~ /static/` block to serve the hero assets directly. Added manually to the HTTPS server block:
```
location ^~ /static/ {
    alias /opt/shadz-os/Desktop/shadz-os/static/;
    try_files $uri =404;
    access_log off;
    expires 7d;
}
```
Both assets confirmed live — `/static/assets/shadz-logo-core.png` and `/static/assets/shadz-wordmark.png` return `200`.

**Touched:** `static/index.html`, `static/assets/` (new files only), Nginx config (VPS only, manual)
**Backend:** untouched
**Admin:** untouched
**Endpoints:** untouched

---

## Front Page v0.1.1 — CTA Contact Patch

**Date:** 2026-05-07
**Commit:** `23aba99`
**Status:** Complete, deployed, browser-verified

**Summary:**
Final front page CTA button linked to Telegram contact. Previously pointed to `#concept` (a page anchor), which prevented potential clients from making contact.

**Changes:**
- Final CTA `.btn-primary` inside `#cta` section: `href="#concept"` → `href="https://t.me/xshadzx"` with `target="_blank" rel="noopener noreferrer"`
- Hero CTA (`class="hero-cta"`) remains `href="#cta"` — scrolls visitors to the final CTA section as intended
- Navbar links unchanged

**Verification:**
- Front page responds `200`
- Served HTML contains `t.me/xshadzx`
- `/health` returns `{"status":"ok"}`
- `/admin` still requires authentication
- Browser test confirmed final CTA opens Telegram correctly

**Touched:** `static/index.html` only
**Backend:** untouched
**Endpoints:** untouched

---

## v0.2.2 — Admin UI Result Card Redesign

**Date:** 2026-05-07
**Commit:** `dcdf879`
**Status:** Complete, deployed, live-tested

**Summary:**
Result cards in Check Slug Info redesigned into premium equal-height 2-column command modules.

**Changes:**
- Desktop/iPad: 2 cards per row (was 3)
- Mobile breakpoint moved to 700px (was 600px)
- `@media (max-width: 900px)` fallback removed
- `align-items: stretch` on grid for equal-height rows
- `#searchResults .stats-box` scoped to flex column — Storage Manager unaffected
- `.card-body` flex-expands data rows, pins action zone to card bottom
- `#searchResults .value-overflow` uses single-line ellipsis truncation (no more break-all wrapping)
- Active Media panel compacted: Asset ID, Type, truncated filename, `Open Media ↗` link — raw URL row removed
- Detach Media and Edit Info unchanged

**Touched:** `static/admin.html` only
**Backend:** untouched
**Endpoints:** untouched

---

## v0.2.1 — Admin UI Result Grid Layout

**Date:** 2026-05-07
**Commit:** `89a6a28`
**Status:** Functional but visually unsatisfactory — superseded by v0.2.2

**Summary:**
Check Slug Info and Storage Manager result cards converted to a responsive CSS grid.
Desktop 3 columns, tablet 2, mobile 1.
Live-tested and working but the 3-column desktop layout felt cramped and ugly.
Unequal card heights caused by Active Media blocks were unacceptable.
Superseded by v0.2.2.

**Touched:** `static/admin.html` only

---

## v0.2 Phase 1 — Admin Dashboard UI Shell

**Commit:** `83428eb`
**Status:** Complete

**Summary:**
Admin home screen reorganized into two labeled module groups: Link Engine and Media Engine.
CSS utility classes added for reuse across panels.

**Touched:** `static/admin.html` only
**Backend:** untouched

---

## v0.1 — SHADZ Front Page

**Commit:** `c7f91bf`
**Status:** Complete

**Summary:**
Live at https://shadz.io/
FastAPI `GET /` serves `static/index.html`.
Nginx HTTPS server block proxies root to FastAPI.

**Brand direction:**
- Cinematic black-gold
- Premium private system
- Physical-digital experience company — not just NFC keychains

**Hero copy:** `SHADZ / Touch to Unlock. / Start with one touch.`

**Touched:** `static/index.html`, Nginx config, `main.py` (`GET /` route)

---

## Media Engine v0.1.2 — Storage Manager Cleanup + Detach Patch

**Commit:** `196ba55`
**Status:** Complete

**Summary:**
Full media lifecycle now operational: Upload → Attach → Render → Detach → Safe Delete.

- Storage Manager hides deleted assets by default
- Check Slug Info shows Active Media panel
- Detach Media works; slug shows "Media not ready yet" after detach
- Active slug usage count updates correctly

**Touched:** `main.py`, `static/admin.html`

---

## Media Engine v0.1.1 — Delete Safety Patch

**Commit:** `6d4dec9`
**Status:** Complete

**Summary:**
Deleting a `MediaAsset` that is still linked to one or more active slugs is blocked.
Clear error returned instead of silently breaking active media slugs.

**Touched:** `main.py`

---

## Media Engine v0.1 — Core Upload + Attach + Render

**Status:** Complete

**Summary:**
- Admin media upload flow (presigned R2 PUT + confirm step)
- Storage Manager browse
- Upload Media Asset
- Attach Media to Slug
- Public media slug render

**Touched:** `main.py`, `static/admin.html`, R2 bucket config

---

## Naming + Logging System v0.3

**Status:** Complete

**Summary:**
- Auto-generated slug format: `{content_type}-{randomID}`
- Content types: `url`, `media`, `page`
- Admin can create links with client name, phone, notes, destination URL
- Check Slug Info searches by phone/contact
- One client can have multiple slug records
- Edit Info updates client name, phone, notes (separate from redirect URL)
- Update Redirect Link kept separate from Edit Info
- Backend validates `content_type`
- Legacy slugs preserved
- SQLite migration added client logging fields safely

**Touched:** `main.py`, `static/admin.html`, SQLite migration

---

## Redirect Engine v0.1

**Status:** Complete

**Summary:**
- Dynamic slug redirect system live
- `/{slug}` resolves through FastAPI to destination
- `scan_count` increments on each hit
- Old hardcoded Nginx redirects removed

**Touched:** `main.py`, Nginx config
