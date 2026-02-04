from __future__ import annotations

from collections.abc import Callable, Hashable
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Generic, TypeVar

from app.core.config import settings
from app.core.runtime_settings import get_cache_level

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


@dataclass
class _Entry(Generic[V]):
    value: V
    expires_at: float


class TTLCache(Generic[K, V]):
    def __init__(self, max_entries: int, default_ttl_seconds: int) -> None:
        self._max_entries = max(1, int(max_entries))
        self._default_ttl = max(1, int(default_ttl_seconds))
        self._store: dict[K, _Entry[V]] = {}
        self._lock = Lock()

    def get(self, key: K) -> V | None:
        now = monotonic()
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._store.pop(key, None)
                return None
            return entry.value

    def set(self, key: K, value: V, ttl_seconds: int | None = None) -> None:
        ttl = self._default_ttl if ttl_seconds is None else max(1, int(ttl_seconds))
        expires_at = monotonic() + ttl
        with self._lock:
            if len(self._store) >= self._max_entries:
                # Simple eviction: drop an arbitrary entry
                self._store.pop(next(iter(self._store)))
            self._store[key] = _Entry(value=value, expires_at=expires_at)

    def get_or_set(self, key: K, factory: Callable[[], V], ttl_seconds: int | None = None) -> V:
        cached = self.get(key)
        if cached is not None:
            return cached
        value = factory()
        self.set(key, value, ttl_seconds)
        return value


def cache_level_enabled(level: int) -> bool:
    return get_cache_level() >= level


def clear_all_caches() -> None:
    with classification_cache._lock:
        classification_cache._store.clear()
    with pdp_cache._lock:
        pdp_cache._store.clear()
    with kms_cache._lock:
        kms_cache._store.clear()
    with pepper_cache._lock:
        pepper_cache._store.clear()


classification_cache: TTLCache[str, dict[str, str]] = TTLCache(
    max_entries=settings.CACHE_MAX_ENTRIES,
    default_ttl_seconds=settings.CACHE_TTL_CLASSIF_SEC,
)

pdp_cache: TTLCache[tuple, object] = TTLCache(
    max_entries=settings.CACHE_MAX_ENTRIES,
    default_ttl_seconds=settings.CACHE_TTL_PDP_SEC,
)

kms_cache: TTLCache[str, str] = TTLCache(
    max_entries=settings.CACHE_MAX_ENTRIES,
    default_ttl_seconds=settings.CACHE_TTL_KMS_SEC,
)

pepper_cache: TTLCache[str, bytes] = TTLCache(
    max_entries=8,
    default_ttl_seconds=settings.CACHE_TTL_PEPPER_SEC,
)
