import os

# Load .env file if present (python-dotenv); silently skip if not installed.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# Default to SQLite for simple MVP/VPS setup.
# Set DATABASE_URL=postgresql://... in .env (or environment) to use PostgreSQL instead.
_DEFAULT_DB = "sqlite:///./shadz.db"
DATABASE_URL = os.environ.get("DATABASE_URL", _DEFAULT_DB)

# SQLite needs check_same_thread=False; the kwarg is ignored by other drivers.
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
