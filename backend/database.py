import os

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

configured_database_url = os.getenv("DATABASE_URL", "").strip()
if configured_database_url.startswith("postgres://"):
    configured_database_url = configured_database_url.replace("postgres://", "postgresql+psycopg://", 1)
elif configured_database_url.startswith("postgresql://"):
    configured_database_url = configured_database_url.replace("postgresql://", "postgresql+psycopg://", 1)

# Vercel's function filesystem is ephemeral. This fallback keeps onboarding usable
# when DATABASE_URL has not been added yet; production workspaces should use Postgres.
DATABASE_URL = configured_database_url or (
    "sqlite:////tmp/weber_ai_runtime.db" if os.getenv("VERCEL") else "sqlite:///./webare_ai.db"
)
DATABASE_SOURCE = "managed-postgres" if configured_database_url.startswith("postgresql+") else "temporary-vercel-sqlite" if os.getenv("VERCEL") else "local-sqlite"

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()
