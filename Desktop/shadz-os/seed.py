"""
seed.py — one-shot database initialiser for SHADZ Redirect Engine v0.2

Run once on a fresh VPS (or whenever you need to add a new slug):
    python seed.py

Rules:
  - Creates all tables if they don't exist yet.
  - If slug "a" already exists, prints its current URL and does NOT overwrite it.
  - Only inserts slug "a" if it is missing.
  - Safe to run multiple times.
"""

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from database import Base, engine, SessionLocal
import models  # registers all models with Base


# ── 1. Create tables ─────────────────────────────────────────────────────────

Base.metadata.create_all(bind=engine)
print("[seed] Tables verified / created.")


# ── 2. Seed slug "a" ─────────────────────────────────────────────────────────

SLUG = "a"
DEFAULT_URL = "https://www.tiktok.com/@yourprofile"  # change to your real URL

db = SessionLocal()
try:
    existing = db.query(models.RedirectLink).filter(models.RedirectLink.slug == SLUG).first()

    if existing:
        print(f"[seed] Slug '{SLUG}' already exists — skipping insert.")
        print(f"         current URL : {existing.destination_url}")
        print(f"         scan count  : {existing.scan_count}")
        print(f"  To change the URL, run:")
        print(f"    curl -X POST http://127.0.0.1:8000/admin/link/{SLUG} \\")
        print(f"      -H 'X-API-Key: YOUR_KEY' \\")
        print(f"      -H 'Content-Type: application/json' \\")
        print(f"      -d '{{\"destination_url\": \"https://new-url.com\"}}'")
    else:
        link = models.RedirectLink(slug=SLUG, destination_url=DEFAULT_URL)
        db.add(link)
        db.commit()
        print(f"[seed] Slug '{SLUG}' inserted.")
        print(f"         destination : {DEFAULT_URL}")
        print(f"  IMPORTANT: Update the URL to your real destination before going live:")
        print(f"    curl -X POST http://127.0.0.1:8000/admin/link/{SLUG} \\")
        print(f"      -H 'X-API-Key: YOUR_KEY' \\")
        print(f"      -H 'Content-Type: application/json' \\")
        print(f"      -d '{{\"destination_url\": \"https://your-real-url.com\"}}'")
finally:
    db.close()

print("[seed] Done.")
