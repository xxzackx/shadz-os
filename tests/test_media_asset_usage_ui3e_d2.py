"""Regression tests for Admin UI v0.3 Phase UI3E-D2 (Delete Dependency Warning).

Covers GET /admin/media/assets/{id}/usage — the read-only asset-to-slug
lookup added to preflight delete. Uses the same isolated in-memory SQLite
FastAPI-app pattern as test_page_admin.py: nothing here touches the real
shadz.db.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from database import Base, get_db
from media_admin import register_media_admin_routes


class MediaAssetUsageTests(unittest.TestCase):
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
        asset = models.MediaAsset(
            media_type="image",
            storage_key="media/image/1_test.jpg",
            public_url="https://media.shadz.io/media/image/1_test.jpg",
            original_filename="test.jpg",
            mime_type="image/jpeg",
            file_size=100,
            **overrides,
        )
        self.db.add(asset)
        self.db.commit()
        self.db.refresh(asset)
        return asset

    def _attach(self, slug, asset_id, is_active=True):
        sm = models.SlugMedia(slug=slug, media_asset_id=asset_id, is_active=is_active)
        self.db.add(sm)
        self.db.commit()
        return sm

    def test_nonexistent_asset_returns_404(self):
        res = self.client.get("/admin/media/assets/999/usage")
        self.assertEqual(res.status_code, 404)

    def test_zero_active_attachments_returns_empty(self):
        asset = self._make_asset()
        res = self.client.get(f"/admin/media/assets/{asset.id}/usage")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["media_asset_id"], asset.id)
        self.assertEqual(body["active_usage_count"], 0)
        self.assertEqual(body["slugs"], [])

    def test_single_active_attachment_returns_exact_slug(self):
        asset = self._make_asset()
        self._attach("client-a", asset.id)
        res = self.client.get(f"/admin/media/assets/{asset.id}/usage")
        body = res.json()
        self.assertEqual(body["active_usage_count"], 1)
        self.assertEqual(body["slugs"], ["client-a"])

    def test_multiple_active_attachments_all_returned(self):
        asset = self._make_asset()
        self._attach("client-b", asset.id)
        self._attach("client-a", asset.id)
        self._attach("product-demo", asset.id)
        res = self.client.get(f"/admin/media/assets/{asset.id}/usage")
        body = res.json()
        self.assertEqual(body["active_usage_count"], 3)
        self.assertEqual(sorted(body["slugs"]), ["client-a", "client-b", "product-demo"])

    def test_inactive_historical_attachments_excluded(self):
        asset = self._make_asset()
        self._attach("still-active", asset.id, is_active=True)
        self._attach("old-detached", asset.id, is_active=False)
        res = self.client.get(f"/admin/media/assets/{asset.id}/usage")
        body = res.json()
        self.assertEqual(body["active_usage_count"], 1)
        self.assertEqual(body["slugs"], ["still-active"])

    def test_endpoint_is_read_only(self):
        asset = self._make_asset()
        self._attach("client-a", asset.id)
        self.client.get(f"/admin/media/assets/{asset.id}/usage")

        # Neither the asset nor its SlugMedia row should be mutated by a GET.
        self.db.refresh(asset)
        self.assertFalse(asset.is_deleted)
        sm = self.db.query(models.SlugMedia).filter(
            models.SlugMedia.media_asset_id == asset.id
        ).first()
        self.assertTrue(sm.is_active)


if __name__ == "__main__":
    unittest.main()
