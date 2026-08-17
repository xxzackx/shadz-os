"""Regression tests for Safety Engine v1 Phase S2 (NFC Safety Identity /
Public Entry — GET /safety/c/{secure_token}).

Two groups:

1. Route/model behaviour — a minimal FastAPI app registers only the S2
   route (safety_public.serve_safety_entry) with get_db overridden to an
   isolated in-memory SQLite database. Never imports main.py, so no test in
   this class can create, open, or write to the real shadz.db.

2. Migration behaviour — the actual main.py `_run_migrations()` additive
   column/backfill/index logic must be exercised for real, so this group
   runs main.py in a fresh subprocess with DATABASE_URL pointed at a throwaway
   temp SQLite file, matching the repo's existing safety rule that no test
   imports main.py in-process. This proves the production migration path
   (add column -> backfill existing NULL rows -> create unique index) without
   ever touching the repository's real shadz.db.
"""
import os
import subprocess
import sqlite3
import sys
import tempfile
import textwrap
import unittest
from datetime import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from database import Base, get_db
from safety_public import serve_safety_entry

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SafetyPublicEntryRouteTests(unittest.TestCase):
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

        @app.get("/safety/c/{secure_token}")
        def safety_entry(secure_token: str, db=Depends(get_db)):
            return serve_safety_entry(secure_token, db)

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

    def _make_user(self, nfc_token="nfc-1", is_active=True, **kwargs):
        user = models.SafetyUser(
            display_name=kwargs.pop("display_name", "Alice"),
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            is_active=is_active,
            **kwargs,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    # ── secure_token generation ──────────────────────────────────────────

    def test_new_user_automatically_receives_secure_token(self):
        user = self._make_user()
        self.assertTrue(user.secure_token)

    def test_secure_token_is_sufficiently_long(self):
        user = self._make_user()
        self.assertGreaterEqual(len(user.secure_token), 32)

    def test_secure_token_distinct_from_nfc_token(self):
        user = self._make_user(nfc_token="nfc-distinct")
        self.assertNotEqual(user.secure_token, user.nfc_token)

    def test_secure_token_uniqueness_enforced(self):
        self._make_user(nfc_token="nfc-a")
        second = models.SafetyUser(
            display_name="Bob",
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token="nfc-b",
        )
        # Force a collision to prove the DB-level unique constraint exists.
        first = self.db.query(models.SafetyUser).first()
        second.secure_token = first.secure_token
        self.db.add(second)
        with self.assertRaises(Exception):
            self.db.commit()
        self.db.rollback()

    def test_caller_need_not_provide_secure_token(self):
        # _make_user never passes secure_token explicitly.
        user = self._make_user(nfc_token="nfc-implicit")
        self.assertIsNotNone(user.secure_token)

    # ── route behaviour ──────────────────────────────────────────────────

    def test_active_valid_token_returns_200_html(self):
        user = self._make_user(display_name="Alice Safe")
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])

    def test_response_includes_display_name(self):
        user = self._make_user(display_name="Carla Rivers")
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn("Carla Rivers", resp.text)

    def test_unknown_token_returns_404(self):
        resp = self.client.get("/safety/c/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_inactive_token_returns_identical_404(self):
        active_missing_resp = self.client.get("/safety/c/does-not-exist")
        user = self._make_user(nfc_token="nfc-inactive", is_active=False)
        inactive_resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(inactive_resp.status_code, 404)
        self.assertEqual(inactive_resp.json(), active_missing_resp.json())

    # ── zero runtime side effects ────────────────────────────────────────

    def test_get_creates_no_check_in_alert_or_emergency_rows(self):
        user = self._make_user()
        self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 0)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    # ── HTML escaping ───────────────────────────────────────────────────

    def test_display_name_is_html_escaped(self):
        user = self._make_user(
            nfc_token="nfc-xss", display_name="<script>alert(1)</script>"
        )
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", resp.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", resp.text)


class ReservedSlugBehaviorTests(unittest.TestCase):
    """Proves the generic RedirectLink slug surface actually rejects/reserves
    "safety" via the existing public /{slug} catch-all (main.redirect_slug),
    not just that the string appears in RESERVED_SLUGS. Runs main.py in a
    subprocess against a throwaway temp SQLite file — matching this suite's
    existing rule that no test imports main.py in-process, to avoid touching
    the real shadz.db."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let create_all build it fresh

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_bare_safety_slug_is_rejected_as_reserved(self):
        script = textwrap.dedent(
            f"""
            import sys, json
            sys.path.insert(0, {REPO_ROOT!r})
            import main
            from fastapi.testclient import TestClient
            client = TestClient(main.app)
            resp = client.get("/safety")
            print(json.dumps({{"status_code": resp.status_code, "body": resp.json()}}))
            """
        )
        env = dict(os.environ)
        env["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        import json as _json
        payload = _json.loads(result.stdout.strip().splitlines()[-1])
        self.assertEqual(payload["status_code"], 404)
        self.assertIn("reserved path", payload["body"]["detail"])


class SafetyUserMigrationTests(unittest.TestCase):
    """Exercises the real main.py `_run_migrations()` additive
    column/backfill/unique-index logic for safety_users.secure_token, in a
    subprocess against a throwaway temp SQLite file — never the real
    shadz.db."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let create_all build it fresh

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _seed_pre_s2_row_without_secure_token(self):
        """Create a safety_users table shaped like pre-S2 production (no
        secure_token column) with one existing row, simulating an upgrade
        of a non-empty table."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE safety_users (
                id INTEGER PRIMARY KEY,
                display_name VARCHAR NOT NULL,
                timezone VARCHAR NOT NULL,
                daily_deadline TIME NOT NULL,
                early_reminder_minutes INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                nfc_token VARCHAR NOT NULL UNIQUE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT INTO safety_users "
            "(display_name, timezone, daily_deadline, early_reminder_minutes, "
            " is_active, nfc_token, created_at, updated_at) "
            "VALUES ('Existing User', 'UTC', '21:00:00', 30, 1, 'pre-s2-nfc', "
            " '2026-01-01 00:00:00', '2026-01-01 00:00:00')"
        )
        conn.commit()
        conn.close()

    def _seed_column_exists_with_null_tokens_no_index(self):
        """Simulates a migration interrupted after ALTER TABLE but before
        backfill/index: secure_token column present, two rows with NULL/
        empty tokens, no secure-token unique index yet."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE safety_users (
                id INTEGER PRIMARY KEY,
                display_name VARCHAR NOT NULL,
                timezone VARCHAR NOT NULL,
                daily_deadline TIME NOT NULL,
                early_reminder_minutes INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                nfc_token VARCHAR NOT NULL UNIQUE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                secure_token VARCHAR
            )
            """
        )
        for nfc, token in (("partial-1", None), ("partial-2", "")):
            conn.execute(
                "INSERT INTO safety_users "
                "(display_name, timezone, daily_deadline, early_reminder_minutes, "
                " is_active, nfc_token, created_at, updated_at, secure_token) "
                "VALUES ('Existing User', 'UTC', '21:00:00', 30, 1, ?, "
                " '2026-01-01 00:00:00', '2026-01-01 00:00:00', ?)",
                (nfc, token),
            )
        conn.commit()
        conn.close()

    def _seed_column_with_valid_tokens_no_index(self):
        """Simulates a migration interrupted after backfill but before index
        creation: secure_token column present with a real value already
        assigned, no secure-token unique index yet."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            CREATE TABLE safety_users (
                id INTEGER PRIMARY KEY,
                display_name VARCHAR NOT NULL,
                timezone VARCHAR NOT NULL,
                daily_deadline TIME NOT NULL,
                early_reminder_minutes INTEGER NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                nfc_token VARCHAR NOT NULL UNIQUE,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL,
                secure_token VARCHAR
            )
            """
        )
        conn.execute(
            "INSERT INTO safety_users "
            "(display_name, timezone, daily_deadline, early_reminder_minutes, "
            " is_active, nfc_token, created_at, updated_at, secure_token) "
            "VALUES ('Existing User', 'UTC', '21:00:00', 30, 1, 'no-index-nfc', "
            " '2026-01-01 00:00:00', '2026-01-01 00:00:00', "
            " 'already-backfilled-token-1234567890')"
        )
        conn.commit()
        conn.close()

    def _unique_secure_token_index_names(self):
        """Names of every unique index that covers secure_token alone."""
        conn = sqlite3.connect(self.db_path)
        index_rows = conn.execute("PRAGMA index_list('safety_users')").fetchall()
        names = []
        for row in index_rows:
            name, is_unique = row[1], row[2]
            if not is_unique:
                continue
            cols = [c[2] for c in conn.execute(f"PRAGMA index_info('{name}')").fetchall()]
            if cols == ["secure_token"]:
                names.append(name)
        conn.close()
        return names

    def _run_main_import(self):
        script = textwrap.dedent(
            f"""
            import sys
            sys.path.insert(0, {REPO_ROOT!r})
            import main  # noqa: F401 -- import triggers _run_migrations()
            print("OK")
            """
        )
        env = dict(os.environ)
        env["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        return result

    def test_migration_backfills_existing_row_without_secure_token(self):
        self._seed_pre_s2_row_without_secure_token()
        result = self._run_main_import()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT secure_token FROM safety_users WHERE nfc_token = 'pre-s2-nfc'"
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertTrue(row[0])
        self.assertGreaterEqual(len(row[0]), 32)

    def test_migration_is_idempotent(self):
        self._seed_pre_s2_row_without_secure_token()
        first = self._run_main_import()
        self.assertEqual(first.returncode, 0, msg=first.stderr)

        conn = sqlite3.connect(self.db_path)
        token_after_first = conn.execute(
            "SELECT secure_token FROM safety_users WHERE nfc_token = 'pre-s2-nfc'"
        ).fetchone()[0]
        conn.close()

        second = self._run_main_import()
        self.assertEqual(second.returncode, 0, msg=second.stderr)

        conn = sqlite3.connect(self.db_path)
        token_after_second = conn.execute(
            "SELECT secure_token FROM safety_users WHERE nfc_token = 'pre-s2-nfc'"
        ).fetchone()[0]
        conn.close()

        self.assertEqual(token_after_first, token_after_second)

    def test_partial_migration_recovers_null_tokens_and_missing_index(self):
        self._seed_column_exists_with_null_tokens_no_index()
        result = self._run_main_import()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        conn = sqlite3.connect(self.db_path)
        tokens = [
            row[0]
            for row in conn.execute("SELECT secure_token FROM safety_users").fetchall()
        ]
        conn.close()

        self.assertTrue(all(tokens))
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertEqual(len(self._unique_secure_token_index_names()), 1)

        # Rerun must preserve the tokens just generated.
        second = self._run_main_import()
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        conn = sqlite3.connect(self.db_path)
        tokens_after_rerun = [
            row[0]
            for row in conn.execute("SELECT secure_token FROM safety_users").fetchall()
        ]
        conn.close()
        self.assertEqual(tokens, tokens_after_rerun)
        self.assertEqual(len(self._unique_secure_token_index_names()), 1)

    def test_missing_index_recovery_preserves_existing_tokens(self):
        self._seed_column_with_valid_tokens_no_index()
        result = self._run_main_import()
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        conn = sqlite3.connect(self.db_path)
        token = conn.execute(
            "SELECT secure_token FROM safety_users WHERE nfc_token = 'no-index-nfc'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(token, "already-backfilled-token-1234567890")
        self.assertEqual(len(self._unique_secure_token_index_names()), 1)

        # Rerun stays idempotent: same token, still exactly one index.
        second = self._run_main_import()
        self.assertEqual(second.returncode, 0, msg=second.stderr)
        conn = sqlite3.connect(self.db_path)
        token_after_rerun = conn.execute(
            "SELECT secure_token FROM safety_users WHERE nfc_token = 'no-index-nfc'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(token_after_rerun, "already-backfilled-token-1234567890")
        self.assertEqual(len(self._unique_secure_token_index_names()), 1)


if __name__ == "__main__":
    unittest.main()
