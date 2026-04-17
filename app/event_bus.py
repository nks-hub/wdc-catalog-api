"""In-process async pub/sub event bus for SSE live audit tail.

Design rationale
----------------
* **Drop-oldest backpressure**: when a slow subscriber's queue is full we
  discard the *oldest* pending event rather than blocking the publisher or
  raising an exception.  The publisher is on the hot path (every mutation
  site) so it must never block; simultaneously we want slow consumers to
  miss the least-recent data rather than the most-recent.

* **Thread-safety via threading.Lock**: FastAPI runs in a single process but
  route handlers execute inside Starlette's thread pool for sync routes.
  A ``threading.Lock`` around the subscriber registry guarantees that
  ``subscribe()`` / ``_register`` / ``_unregister`` are safe across threads.
  The actual ``asyncio.Queue`` operations (``put_nowait`` / ``get_nowait``)
  are already thread-safe on CPython because of the GIL, so they need no
  additional protection.

* **Subscriber cap (MAX_SUBSCRIBERS = 32)**: unbounded subscriber growth
  would turn each ``publish()`` call into an O(n) operation and exhaust
  memory.  32 concurrent SSE connections is well above expected load for
  a single-process deployment; raising ``RuntimeError`` on the 33rd is a
  deliberate hard ceiling.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from typing import AsyncIterator

MAX_SUBSCRIBERS = 32
_QUEUE_MAXSIZE = 128


class _EventBus:
    """Registry of active subscriber queues."""

    def __init__(self) -> None:
        self._queues: set[asyncio.Queue[dict]] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal registry helpers
    # ------------------------------------------------------------------

    def _register(self, queue: asyncio.Queue[dict]) -> None:
        with self._lock:
            if len(self._queues) >= MAX_SUBSCRIBERS:
                raise RuntimeError("event bus saturated")
            self._queues.add(queue)

    def _unregister(self, queue: asyncio.Queue[dict]) -> None:
        with self._lock:
            self._queues.discard(queue)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(self, event: dict) -> None:
        """Broadcast *event* to every subscriber queue synchronously.

        Never blocks and never raises: if a subscriber queue is full the
        oldest item is evicted first (drop-oldest) and the new event is
        then placed at the back.
        """
        with self._lock:
            queues = list(self._queues)
        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # give up rather than blocking

    @contextlib.asynccontextmanager
    async def subscribe(self) -> AsyncIterator[AsyncIterator[dict]]:
        """Async context manager that yields an async iterator of events.

        Registers a bounded queue on entry and removes it on exit, so
        callers that disconnect do not leak memory or slow down publish().

        Raises ``RuntimeError("event bus saturated")`` when MAX_SUBSCRIBERS
        is already reached.
        """
        queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._register(queue)
        try:
            yield self._drain(queue)
        finally:
            self._unregister(queue)

    @staticmethod
    async def _drain(queue: asyncio.Queue[dict]) -> AsyncIterator[dict]:
        """Yield events from *queue* indefinitely."""
        while True:
            yield await queue.get()


_bus = _EventBus()


def subscribe() -> contextlib.AbstractAsyncContextManager[AsyncIterator[dict]]:
    """Module-level shortcut — see ``_EventBus.subscribe``."""
    return _bus.subscribe()


def publish(event: dict) -> None:
    """Module-level shortcut — see ``_EventBus.publish``."""
    _bus.publish(event)


__all__ = ["subscribe", "publish", "MAX_SUBSCRIBERS"]
