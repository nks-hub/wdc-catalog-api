"""In-process async pub/sub event bus for SSE live audit tail.

Design rationale
----------------
* **Drop-oldest backpressure**: when a slow subscriber's queue is full we
  discard the *oldest* pending event rather than blocking the publisher or
  raising an exception.  The publisher is on the hot path (every mutation
  site) so it must never block; simultaneously we want slow consumers to
  miss the least-recent data rather than the most-recent.

* **Thread-safety via loop.call_soon_threadsafe**: FastAPI runs sync
  route handlers inside Starlette's threadpool, so ``publish()`` is
  routinely invoked from worker threads while the SSE consumer runs on
  the event loop thread.  ``asyncio.Queue`` is NOT thread-safe — calling
  ``put_nowait`` from a foreign thread can corrupt internal state
  (waiters list, ``_unfinished_tasks`` counter) and silently drop events.
  To fix this each subscriber's queue is registered together with the
  loop it was created on; ``publish()`` routes queue mutations through
  ``loop.call_soon_threadsafe`` when called from any non-loop thread and
  does a direct ``put_nowait`` when already on the loop thread (fast
  path, avoids a scheduler round-trip).  A ``threading.Lock`` still
  guards the subscriber-registry set so ``subscribe()`` / ``publish()``
  can race safely on the registry itself.

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


def _deliver(queue: asyncio.Queue[dict], event: dict) -> None:
    """Put *event* on *queue* with drop-oldest eviction on overflow.

    Must run on the loop thread that owns *queue* — callers are
    responsible for scheduling this via ``call_soon_threadsafe`` when
    invoked from a foreign thread.
    """
    try:
        queue.put_nowait(event)
    except asyncio.QueueFull:
        try:
            queue.get_nowait()
        except asyncio.QueueEmpty:
            pass
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # give up rather than blocking


class _EventBus:
    """Registry of active subscriber queues."""

    def __init__(self) -> None:
        # Each entry pairs the queue with the loop it was created on so
        # publish() can hop back to that loop via call_soon_threadsafe
        # when invoked from a worker thread.
        self._queues: set[tuple[asyncio.Queue[dict], asyncio.AbstractEventLoop]] = set()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal registry helpers
    # ------------------------------------------------------------------

    def _register(self, queue: asyncio.Queue[dict]) -> None:
        loop = asyncio.get_event_loop()
        with self._lock:
            if len(self._queues) >= MAX_SUBSCRIBERS:
                raise RuntimeError("event bus saturated")
            self._queues.add((queue, loop))

    def _unregister(self, queue: asyncio.Queue[dict]) -> None:
        with self._lock:
            self._queues = {(q, l) for (q, l) in self._queues if q is not queue}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def publish(self, event: dict) -> None:
        """Broadcast *event* to every subscriber queue.

        Thread-safe: callable from any thread (including FastAPI's
        sync-route threadpool). Never blocks and never raises; if a
        subscriber queue is full the oldest item is evicted first
        (drop-oldest) and the new event is then placed at the back.

        When called from the loop thread owning a subscriber's queue
        delivery happens inline; from any other thread delivery is
        scheduled via ``loop.call_soon_threadsafe`` so the queue is
        only ever mutated on its own loop.
        """
        with self._lock:
            targets = list(self._queues)

        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        for queue, loop in targets:
            if loop is current_loop:
                _deliver(queue, event)
            else:
                try:
                    loop.call_soon_threadsafe(_deliver, queue, event)
                except RuntimeError:
                    # Loop already closed — subscriber will be reaped
                    # on its next cleanup. Drop silently.
                    pass

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
