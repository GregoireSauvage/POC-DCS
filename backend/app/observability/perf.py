from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from time import perf_counter
from typing import Any

_perf_ctx: ContextVar["PerfContext | None"] = ContextVar("perf_ctx", default=None)


class PerfContext:
    def __init__(self) -> None:
        self._start = perf_counter()
        self.metrics: dict[str, float] = {}

    def add(self, key: str, ms: float) -> None:
        self.metrics[key] = self.metrics.get(key, 0.0) + ms

    def set(self, key: str, value: float) -> None:
        self.metrics[key] = value

    def elapsed_ms(self) -> float:
        return (perf_counter() - self._start) * 1000.0


def set_perf_context(ctx: PerfContext) -> Any:
    return _perf_ctx.set(ctx)


def reset_perf_context(token: Any) -> None:
    _perf_ctx.reset(token)


def get_perf_context() -> PerfContext | None:
    return _perf_ctx.get()


def record_ms(key: str, ms: float) -> None:
    ctx = get_perf_context()
    if ctx is None:
        return
    ctx.add(key, ms)


@contextmanager
def perf_span(key: str):
    ctx = get_perf_context()
    if ctx is None:
        yield
        return
    start = perf_counter()
    try:
        yield
    finally:
        ctx.add(key, (perf_counter() - start) * 1000.0)
