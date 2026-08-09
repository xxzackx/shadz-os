"""Regression tests for Activation Engine v1 — Production Hotfix H1E
(Timezone Display Correction).

Confirmed production bug: a slug created at 2026-08-10 00:35 UTC+7
(2026-08-09T17:35:38 UTC) was displayed in Admin as 2026-08-09 17:35 — 7
hours early. Root cause: RedirectLink.created_at/updated_at are always
written with datetime.now(timezone.utc), but SQLite/SQLAlchemy reads them
back naive; FastAPI/Pydantic then serialized the naive value to JSON with
no UTC offset, and the browser's `new Date(...)` calls already used
throughout static/admin.html (e.g. lines rendering `data.created_at` /
`r.created_at`) silently reinterpreted the offset-less string as local
time instead of UTC.

Fix: link_admin._as_utc, wired into LinkInfo and LinkSearchResult (the two
response models that carry RedirectLink.created_at/updated_at into the
live Admin JSON responses consumed by static/admin.html) via a
field_validator, tags a naive datetime as UTC before Pydantic serializes
it — so the JSON now carries an explicit "Z" suffix. No database, storage,
or write-path change.

Covers:
  - a naive DB-shaped datetime representing UTC serializes with explicit Z;
  - an already tz-aware UTC datetime is unaffected (no double +7 shift);
  - the live POST /admin/link and GET /admin/links/search response bodies
    (the exact endpoints static/admin.html reads created_at/updated_at
    from) carry the UTC-qualified timestamp;
  - unrelated response fields/behavior are unchanged.

Uses a dedicated FastAPI app with an isolated in-memory SQLite database —
never touches the real shadz.db.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timezone

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database import Base, get_db
from link_admin import LinkInfo, LinkSearchResult, register_link_admin_routes


class AsUtcSerializationTests(unittest.TestCase):
    """Unit-level proof on the response models themselves."""

    def test_naive_datetime_serializes_with_explicit_utc_offset(self):
        naive = datetime(2026, 8, 9, 17, 35, 38)
        info = LinkInfo(
            slug="url-h1e", destination_url="https://example.com",
            scan_count=0, created_at=naive, updated_at=naive,
        )
        payload = info.model_dump_json()
        self.assertIn('"created_at":"2026-08-09T17:35:38Z"', payload)
        self.assertIn('"updated_at":"2026-08-09T17:35:38Z"', payload)

    def test_already_aware_utc_datetime_is_unchanged_no_double_shift(self):
        aware = datetime(2026, 8, 9, 17, 35, 38, tzinfo=timezone.utc)
        info = LinkInfo(
            slug="url-h1e", destination_url="https://example.com",
            scan_count=0, created_at=aware, updated_at=aware,
        )
        payload = info.model_dump_json()
        # Same wall-clock UTC hour (17), not shifted by +7 a second time.
        self.assertIn('"created_at":"2026-08-09T17:35:38Z"', payload)

    def test_naive_and_aware_inputs_for_the_same_instant_serialize_identically(self):
        naive = datetime(2026, 8, 9, 17, 35, 38)
        aware = datetime(2026, 8, 9, 17, 35, 38, tzinfo=timezone.utc)
        naive_out = LinkInfo(
            slug="a", destination_url="https://e.com", scan_count=0,
            created_at=naive, updated_at=naive,
        ).model_dump_json()
        aware_out = LinkInfo(
            slug="a", destination_url="https://e.com", scan_count=0,
            created_at=aware, updated_at=aware,
        ).model_dump_json()
        self.assertEqual(naive_out, aware_out)

    def test_search_result_model_also_tags_naive_datetime_as_utc(self):
        naive = datetime(2026, 8, 9, 17, 35, 38)
        result = LinkSearchResult(
            slug="url-h1e", nfc_url="https://shadz.io/url-h1e",
            destination_url="https://example.com", scan_count=0,
            created_at=naive, updated_at=naive,
        )
        payload = result.model_dump_json()
        self.assertIn('"created_at":"2026-08-09T17:35:38Z"', payload)
        self.assertIn('"updated_at":"2026-08-09T17:35:38Z"', payload)


class LiveEndpointTimezoneTests(unittest.TestCase):
    """Proves the fix reaches the exact live JSON bodies static/admin.html
    reads created_at/updated_at from.
    """

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def test_create_link_response_created_at_carries_utc_offset(self):
        res = self.client.post(
            "/admin/link",
            json={
                "destination_url": "https://example.com",
                "content_type": "url",
                "phone_number": "5559999",
            },
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        for field in ("created_at", "updated_at"):
            value = body[field]
            self.assertTrue(
                value.endswith("Z") or value.endswith("+00:00"),
                f"{field}={value!r} has no explicit UTC offset",
            )

    def test_search_response_created_at_carries_utc_offset(self):
        create_res = self.client.post(
            "/admin/link",
            json={
                "destination_url": "https://example.com",
                "content_type": "url",
                "phone_number": "5551234",
            },
        )
        self.assertEqual(create_res.status_code, 201)

        search_res = self.client.get("/admin/links/search", params={"phone_number": "5551234"})
        self.assertEqual(search_res.status_code, 200)
        results = search_res.json()["results"]
        self.assertEqual(len(results), 1)
        for field in ("created_at", "updated_at"):
            value = results[0][field]
            self.assertTrue(
                value.endswith("Z") or value.endswith("+00:00"),
                f"{field}={value!r} has no explicit UTC offset",
            )

    def test_unrelated_response_fields_unchanged(self):
        res = self.client.post(
            "/admin/link",
            json={
                "destination_url": "https://example.com",
                "content_type": "url",
                "notes": "n",
                "phone_number": "5558888",
            },
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body["destination_url"], "https://example.com")
        self.assertEqual(body["content_type"], "url")
        self.assertEqual(body["notes"], "n")
        self.assertEqual(body["scan_count"], 0)
        self.assertTrue(body["slug"])


if __name__ == "__main__":
    unittest.main()
