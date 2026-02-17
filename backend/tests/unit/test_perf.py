from app.api.routers import perf as perf_router
from app.core.config import settings
from app.services.perf_service import write_perf


class FakeSession:
    def __init__(self, query_obj=None):
        self.added = []
        self.committed = False
        self.query_obj = query_obj

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True

    def query(self, *args, **kwargs):
        return self.query_obj


class FakeQuery:
    def __init__(self, rows=None):
        self.filters = []
        self.rows = rows or []

    def order_by(self, *args, **kwargs):
        return self

    def filter(self, *conds):
        self.filters.extend(conds)
        return self

    def limit(self, *args, **kwargs):
        return self

    def group_by(self, *args, **kwargs):
        return self

    def all(self):
        return self.rows


def _filters_include_value(filters, value):
    for expr in filters:
        right = getattr(expr, "right", None)
        if right is not None and getattr(right, "value", None) == value:
            return True
    return False


def test_write_perf_sets_source():
    db = FakeSession()
    write_perf(
        db=db,
        request_id="req-1",
        tenant_id="t1",
        subject_user_id=None,
        subject_role=None,
        action="film.read",
        resource_type="film",
        dcs_enabled=True,
        perf=None,
    )
    assert db.added, "expected a perf log to be added"
    assert db.added[0].source == settings.PERF_SOURCE


def test_list_perf_defaults_source_filter():
    query = FakeQuery([])
    db = FakeSession(query)
    perf_router.list_perf(db=db, _=None, limit=10, action=None, source=None)
    assert _filters_include_value(query.filters, settings.PERF_SOURCE)


def test_list_perf_explicit_source_filter():
    query = FakeQuery([])
    db = FakeSession(query)
    perf_router.list_perf(db=db, _=None, limit=10, action=None, source="go")
    assert _filters_include_value(query.filters, "go")


def test_perf_summary_defaults_source_filter():
    query = FakeQuery([])
    db = FakeSession(query)
    perf_router.perf_summary(
        db=db,
        _=None,
        action=None,
        cache_level=None,
        all_cache_levels=False,
        source=None,
    )
    assert _filters_include_value(query.filters, settings.PERF_SOURCE)
