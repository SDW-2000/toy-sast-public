import os

os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost/unused")
os.environ.setdefault("SESSION_SECRET", "test-only-secret")
