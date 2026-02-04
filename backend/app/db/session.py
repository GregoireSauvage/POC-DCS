from time import perf_counter

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.observability.perf import record_ms

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)


@event.listens_for(engine, "before_cursor_execute")
def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    context._perf_start_time = perf_counter()


@event.listens_for(engine, "after_cursor_execute")
def _after_cursor_execute(conn, cursor, statement, parameters, context, executemany):
    start = getattr(context, "_perf_start_time", None)
    if start is None:
        return
    record_ms("db_ms", (perf_counter() - start) * 1000.0)


SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
