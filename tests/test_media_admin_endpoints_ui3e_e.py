"""Regression tests for Admin UI v0.3 Phase UI3E-E (Media Admin endpoint coverage).

Locks the existing Media Admin backend contract in media_admin.py. Uses the
same isolated in-memory SQLite FastAPI-app pattern as test_page_admin.py /
test_media_asset_usage_ui3e_d2.py: nothing here touches the real shadz.db,
and no test makes a real network call to Cloudflare R2 — the R2 client is
monkeypatched at the smallest existing boundary (_get_r2_client) so
generate_presigned_url() never runs, and soft-delete tests assert that
boundary is never even invoked.

Does NOT duplicate GET /admin/media/assets/{id}/usage coverage — that
contract is already locked in test_media_asset_usage_ui3e_d2.py.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import media_admin
import models
from database import Base, get_db
from media_admin import register_media_admin_routes


class MediaAdminTestBase(unittest.TestCase):
    """Shared isolated-DB + TestClient harness for all Media Admin endpoint tests."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_media_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()
        self.client.close()
        self.engine.dispose()

    def _make_asset(self, **overrides):
        defaults = dict(
            media_type="image",
            storage_key="media/image/1_test.jpg",
            public_url="https://media.shadz.io/media/image/1_test.jpg",
            original_filename="test.jpg",
            mime_type="image/jpeg",
            file_size=100,
        )
        defaults.update(overrides)
        asset = models.MediaAsset(**defaults)
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def _make_slug(self, slug, content_type="media"):
        link = models.RedirectLink(slug=slug, destination_url="", content_type=content_type)
        self.db.add(link)
        self.db.commit()
        return link

    def _attach(self, slug, asset_id, is_active=True):
        sm = models.SlugMedia(slug=slug, media_asset_id=asset_id, is_active=is_active)
        self.db.add(sm)
        self.db.commit()
        return sm


# ── Asset listing ────────────────────────────────────────────────────────────

class ListMediaAssetsTests(MediaAdminTestBase):
    def test_default_listing_returns_only_active_assets(self):
        active = self._make_asset(storage_key="media/image/1_a.jpg")
        self._make_asset(storage_key="media/image/2_b.jpg", is_deleted=True)

        res = self.client.get("/admin/media/assets")
        self.assertEqual(res.status_code, 200)
        ids = [a["id"] for a in res.json()]
        self.assertEqual(ids, [active.id])

    def test_include_deleted_true_returns_active_and_removed(self):
        active = self._make_asset(storage_key="media/image/1_a.jpg")
        removed = self._make_asset(
            storage_key="media/image/2_b.jpg",
            display_name="Old Asset",
            is_deleted=True,
        )

        res = self.client.get("/admin/media/assets?include_deleted=true")
        ids = {a["id"] for a in res.json()}
        self.assertEqual(ids, {active.id, removed.id})

    def test_removed_asset_retains_all_expected_fields(self):
        removed = self._make_asset(
            storage_key="media/image/3_removed.jpg",
            display_name="Removed Asset",
            is_deleted=True,
        )
        self.db.refresh(removed)
        # deleted_at is only auto-populated by the DELETE route, so set it
        # directly here since this asset is created pre-deleted.
        removed.deleted_at = removed.created_at
        self.db.commit()

        res = self.client.get("/admin/media/assets?include_deleted=true")
        body = next(a for a in res.json() if a["id"] == removed.id)
        for field in (
            "id", "display_name", "media_type", "original_filename",
            "storage_key", "file_size", "usage_count", "is_deleted", "deleted_at",
        ):
            self.assertIn(field, body)
        self.assertEqual(body["display_name"], "Removed Asset")
        self.assertEqual(body["storage_key"], "media/image/3_removed.jpg")
        self.assertTrue(body["is_deleted"])
        self.assertIsNotNone(body["deleted_at"])

    def test_usage_count_reflects_only_active_attachments(self):
        asset = self._make_asset()
        self._make_slug("client-a")
        self._make_slug("client-b")
        self._attach("client-a", asset.id, is_active=True)
        self._attach("client-b", asset.id, is_active=False)  # historical only

        res = self.client.get("/admin/media/assets")
        body = next(a for a in res.json() if a["id"] == asset.id)
        self.assertEqual(body["usage_count"], 1)


# ── Upload lifecycle (upload-url + complete) ────────────────────────────────

class UploadLifecycleTests(MediaAdminTestBase):
    def setUp(self):
        super().setUp()
        # Smallest R2 boundary stub: generate_presigned_url must never make a
        # real network call in tests. Patched at the same seam the production
        # code already uses for lazy client init.
        self._orig_get_r2_client = media_admin._get_r2_client
        self._fake_client = MagicMock()
        self._fake_client.generate_presigned_url.return_value = "https://fake-r2.example/presigned"
        media_admin._get_r2_client = lambda: self._fake_client

    def tearDown(self):
        media_admin._get_r2_client = self._orig_get_r2_client
        super().tearDown()

    def test_upload_url_valid_media_type_returns_expected_metadata(self):
        res = self.client.post("/admin/media/upload-url", json={
            "filename": "my-video.mp4",
            "media_type": "video",
            "mime_type": "video/mp4",
            "file_size": 1000,
        })
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["upload_url"], "https://fake-r2.example/presigned")
        self.assertTrue(body["storage_key"].startswith("media/video/"))
        self.assertTrue(body["storage_key"].endswith("_my-video.mp4"))
        self.assertIn(body["storage_key"], body["public_url"])
        # No real network call was made — only the stubbed presign helper ran.
        self._fake_client.generate_presigned_url.assert_called_once()

    def test_upload_url_invalid_media_type_rejected(self):
        res = self.client.post("/admin/media/upload-url", json={
            "filename": "f.exe",
            "media_type": "executable",
            "mime_type": "application/octet-stream",
            "file_size": 10,
        })
        self.assertEqual(res.status_code, 400)

    def test_upload_url_mime_type_not_allowed_for_media_type_rejected(self):
        res = self.client.post("/admin/media/upload-url", json={
            "filename": "f.png",
            "media_type": "video",
            "mime_type": "image/png",
            "file_size": 10,
        })
        self.assertEqual(res.status_code, 400)

    def test_upload_url_sanitizes_unsafe_filename_characters(self):
        res = self.client.post("/admin/media/upload-url", json={
            "filename": "my file!@#$.PNG",
            "media_type": "image",
            "mime_type": "image/png",
            "file_size": 10,
        })
        storage_key = res.json()["storage_key"]
        # Only safe characters survive; unsafe ones become underscores.
        import re as _re
        tail = storage_key.split("_", 1)[1]  # strip the leading timestamp_
        self.assertRegex(tail, r"^[a-zA-Z0-9._-]+$")
        self.assertNotIn("!", storage_key)
        self.assertNotIn("#", storage_key)
        self.assertNotIn("$", storage_key)
        self.assertNotIn(" ", storage_key)

    def test_complete_upload_creates_expected_media_asset(self):
        res = self.client.post("/admin/media/complete", json={
            "media_type": "image",
            "storage_key": "media/image/1234_photo.jpg",
            "public_url": "https://media.shadz.io/media/image/1234_photo.jpg",
            "original_filename": "photo.jpg",
            "mime_type": "image/jpeg",
            "file_size": 2048,
            "display_name": "  My Photo  ",
        })
        self.assertEqual(res.status_code, 201)
        asset_id = res.json()["media_asset_id"]

        asset = self.db.query(models.MediaAsset).filter(models.MediaAsset.id == asset_id).first()
        self.assertEqual(asset.storage_key, "media/image/1234_photo.jpg")
        self.assertEqual(asset.original_filename, "photo.jpg")
        self.assertEqual(asset.file_size, 2048)
        self.assertEqual(asset.display_name, "My Photo")  # trimmed
        self.assertFalse(asset.is_deleted)

    def test_complete_upload_blank_display_name_stored_as_none(self):
        res = self.client.post("/admin/media/complete", json={
            "media_type": "gif",
            "storage_key": "media/gif/1_spin.gif",
            "public_url": "https://media.shadz.io/media/gif/1_spin.gif",
            "original_filename": "spin.gif",
            "mime_type": "image/gif",
            "file_size": 500,
            "display_name": "   ",
        })
        asset_id = res.json()["media_asset_id"]
        asset = self.db.query(models.MediaAsset).filter(models.MediaAsset.id == asset_id).first()
        self.assertIsNone(asset.display_name)

    def test_complete_upload_invalid_media_type_rejected(self):
        res = self.client.post("/admin/media/complete", json={
            "media_type": "executable",
            "storage_key": "media/executable/1_f.exe",
            "public_url": "https://media.shadz.io/media/executable/1_f.exe",
            "original_filename": "f.exe",
            "mime_type": "application/octet-stream",
            "file_size": 10,
        })
        self.assertEqual(res.status_code, 400)

    def test_complete_upload_missing_required_field_rejected(self):
        res = self.client.post("/admin/media/complete", json={
            "media_type": "image",
            "storage_key": "media/image/1_a.jpg",
            # missing public_url, original_filename, mime_type, file_size
        })
        self.assertEqual(res.status_code, 422)


# ── Attach / detach / replacement ───────────────────────────────────────────

class AttachDetachReplaceTests(MediaAdminTestBase):
    def test_attach_valid_asset_to_media_slug_succeeds(self):
        asset = self._make_asset()
        self._make_slug("client-a")
        res = self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": asset.id,
        })
        self.assertEqual(res.status_code, 200)
        sm = self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "client-a").first()
        self.assertEqual(sm.media_asset_id, asset.id)
        self.assertTrue(sm.is_active)

    def test_attach_nonexistent_slug_returns_404(self):
        asset = self._make_asset()
        res = self.client.post("/admin/media/attach", json={
            "slug": "no-such-slug", "media_asset_id": asset.id,
        })
        self.assertEqual(res.status_code, 404)

    def test_attach_to_non_media_slug_rejected(self):
        asset = self._make_asset()
        self._make_slug("redirect-slug", content_type="redirect")
        res = self.client.post("/admin/media/attach", json={
            "slug": "redirect-slug", "media_asset_id": asset.id,
        })
        self.assertEqual(res.status_code, 400)

    def test_attach_nonexistent_asset_returns_404(self):
        self._make_slug("client-a")
        res = self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": 999,
        })
        self.assertEqual(res.status_code, 404)

    def test_attach_soft_deleted_asset_rejected(self):
        asset = self._make_asset(is_deleted=True)
        self._make_slug("client-a")
        res = self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": asset.id,
        })
        self.assertEqual(res.status_code, 400)

    def test_replacement_deactivates_old_and_activates_new(self):
        old_asset = self._make_asset(storage_key="media/image/1_old.jpg")
        new_asset = self._make_asset(storage_key="media/image/2_new.jpg")
        self._make_slug("client-a")
        self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": old_asset.id,
        })
        res = self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": new_asset.id,
        })
        self.assertEqual(res.status_code, 200)

        rows = self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "client-a").all()
        active_rows = [r for r in rows if r.is_active]
        self.assertEqual(len(active_rows), 1)
        self.assertEqual(active_rows[0].media_asset_id, new_asset.id)
        inactive_rows = [r for r in rows if not r.is_active]
        self.assertEqual({r.media_asset_id for r in inactive_rows}, {old_asset.id})

    def test_replacement_updates_usage_counts_on_both_assets(self):
        old_asset = self._make_asset(storage_key="media/image/1_old.jpg")
        new_asset = self._make_asset(storage_key="media/image/2_new.jpg")
        self._make_slug("client-a")
        self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": old_asset.id,
        })
        self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": new_asset.id,
        })

        res = self.client.get("/admin/media/assets")
        by_id = {a["id"]: a for a in res.json()}
        self.assertEqual(by_id[old_asset.id]["usage_count"], 0)
        self.assertEqual(by_id[new_asset.id]["usage_count"], 1)

    def test_detach_deactivates_active_attachment(self):
        asset = self._make_asset()
        self._make_slug("client-a")
        self.client.post("/admin/media/attach", json={
            "slug": "client-a", "media_asset_id": asset.id,
        })
        res = self.client.post("/admin/media/detach", json={"slug": "client-a"})
        self.assertEqual(res.status_code, 200)
        sm = self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "client-a").first()
        self.assertFalse(sm.is_active)

    def test_detach_with_no_active_media_rejected(self):
        self._make_slug("client-a")
        res = self.client.post("/admin/media/detach", json={"slug": "client-a"})
        self.assertEqual(res.status_code, 400)

    def test_detach_nonexistent_slug_returns_404(self):
        res = self.client.post("/admin/media/detach", json={"slug": "no-such-slug"})
        self.assertEqual(res.status_code, 404)


# ── Soft delete ──────────────────────────────────────────────────────────────

class SoftDeleteTests(MediaAdminTestBase):
    def setUp(self):
        super().setUp()
        # Track whether the R2 client boundary is ever touched by delete.
        self._orig_get_r2_client = media_admin._get_r2_client
        self._r2_client_calls = []
        media_admin._get_r2_client = lambda: self._r2_client_calls.append(1) or MagicMock()

    def tearDown(self):
        media_admin._get_r2_client = self._orig_get_r2_client
        super().tearDown()

    def test_delete_zero_usage_succeeds_and_sets_deleted_state(self):
        asset = self._make_asset()
        res = self.client.delete(f"/admin/media/assets/{asset.id}")
        self.assertEqual(res.status_code, 200)

        self.db.refresh(asset)
        self.assertTrue(asset.is_deleted)
        self.assertIsNotNone(asset.deleted_at)
        # Row remains present (soft delete, not a physical DROP).
        still_present = self.db.query(models.MediaAsset).filter(
            models.MediaAsset.id == asset.id
        ).first()
        self.assertIsNotNone(still_present)

    def test_delete_active_usage_refused_and_leaves_state_untouched(self):
        asset = self._make_asset()
        self._make_slug("client-a")
        self._attach("client-a", asset.id, is_active=True)

        res = self.client.delete(f"/admin/media/assets/{asset.id}")
        self.assertEqual(res.status_code, 400)

        self.db.refresh(asset)
        self.assertFalse(asset.is_deleted)
        self.assertIsNone(asset.deleted_at)
        sm = self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "client-a").first()
        self.assertTrue(sm.is_active)

    def test_delete_nonexistent_asset_returns_404(self):
        res = self.client.delete("/admin/media/assets/999")
        self.assertEqual(res.status_code, 404)

    def test_delete_already_deleted_asset_returns_400(self):
        asset = self._make_asset(is_deleted=True)
        res = self.client.delete(f"/admin/media/assets/{asset.id}")
        self.assertEqual(res.status_code, 400)

    def test_delete_never_touches_r2_client(self):
        asset = self._make_asset()
        self.client.delete(f"/admin/media/assets/{asset.id}")
        self.assertEqual(self._r2_client_calls, [])


# ── Rename / metadata update ────────────────────────────────────────────────

class UpdateDisplayNameTests(MediaAdminTestBase):
    def test_update_display_name_sets_new_value(self):
        asset = self._make_asset()
        res = self.client.patch(
            f"/admin/media/assets/{asset.id}", json={"display_name": "New Name"}
        )
        self.assertEqual(res.status_code, 200)
        self.db.refresh(asset)
        self.assertEqual(asset.display_name, "New Name")

    def test_update_display_name_blank_clears_it(self):
        asset = self._make_asset(display_name="Old Name")
        self.client.patch(f"/admin/media/assets/{asset.id}", json={"display_name": "   "})
        self.db.refresh(asset)
        self.assertIsNone(asset.display_name)

    def test_update_display_name_does_not_touch_other_fields(self):
        asset = self._make_asset(original_filename="keep-me.jpg", storage_key="media/image/keep.jpg")
        self.client.patch(f"/admin/media/assets/{asset.id}", json={"display_name": "X"})
        self.db.refresh(asset)
        self.assertEqual(asset.original_filename, "keep-me.jpg")
        self.assertEqual(asset.storage_key, "media/image/keep.jpg")

    def test_update_display_name_nonexistent_asset_returns_404(self):
        res = self.client.patch("/admin/media/assets/999", json={"display_name": "X"})
        self.assertEqual(res.status_code, 404)

    def test_update_display_name_works_on_soft_deleted_asset(self):
        asset = self._make_asset(is_deleted=True)
        res = self.client.patch(
            f"/admin/media/assets/{asset.id}", json={"display_name": "Still Editable"}
        )
        self.assertEqual(res.status_code, 200)


if __name__ == "__main__":
    unittest.main()
