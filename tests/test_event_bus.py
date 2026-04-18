"""Unit tests for app.event_bus — async pub/sub event bus."""

from __future__ import annotations

import asyncio
import threading

import pytest

from app.event_bus import MAX_SUBSCRIBERS, _EventBus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fresh() -> _EventBus:
    """Return an isolated _EventBus instance so tests don't share state."""
    return _EventBus()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_single_subscriber_receives_published_event() -> None:
    b = _fresh()
    async with b.subscribe() as events:
        b.publish({"action": "created"})
        result = await asyncio.wait_for(events.__anext__(), timeout=1.0)
    assert result == {"action": "created"}


async def test_fanout_two_subscribers() -> None:
    b = _fresh()
    event = {"action": "updated"}

    async with b.subscribe() as ev1, b.subscribe() as ev2:
        b.publish(event)
        r1 = await asyncio.wait_for(ev1.__anext__(), timeout=1.0)
        r2 = await asyncio.wait_for(ev2.__anext__(), timeout=1.0)

    assert r1 == event
    assert r2 == event


async def test_drop_oldest_when_queue_full() -> None:
    b = _fresh()
    async with b.subscribe() as events:
        # Fill the queue beyond maxsize (128).  The first item published
        # should be evicted to make room for the last one.
        for i in range(129):
            b.publish({"seq": i})

        # The oldest item (seq=0) must have been dropped.
        first = await asyncio.wait_for(events.__anext__(), timeout=1.0)
        assert first["seq"] != 0, (
            f"expected oldest event dropped, got seq={first['seq']}"
        )

        # The newest item (seq=128) must still be present somewhere in the queue.
        received = [first]
        for _ in range(127):
            received.append(await asyncio.wait_for(events.__anext__(), timeout=1.0))

        seqs = [e["seq"] for e in received]
        assert 128 in seqs, f"newest event (seq=128) missing; got {seqs}"


async def test_subscriber_cap_rejects_33rd() -> None:
    b = _fresh()
    contexts = []
    try:
        for _ in range(MAX_SUBSCRIBERS):
            ctx = b.subscribe()
            await ctx.__aenter__()
            contexts.append(ctx)

        with pytest.raises(RuntimeError, match="event bus saturated"):
            async with b.subscribe():
                pass
    finally:
        for ctx in contexts:
            await ctx.__aexit__(None, None, None)


async def test_unsubscribe_on_context_exit() -> None:
    b = _fresh()

    async with b.subscribe():
        pass  # enter and immediately exit

    # After exiting the context the internal queue set must be empty.
    assert len(b._queues) == 0

    # Publishing after unsubscribe must not raise.
    b.publish({"action": "after-unsub"})


async def test_publish_from_worker_thread_delivers_to_loop_consumer() -> None:
    """publish() must be safe when called from a non-event-loop thread.

    FastAPI runs sync route handlers in Starlette's threadpool, so the
    audit hook routinely calls publish() from a worker thread while the
    SSE consumer lives on the main loop.  asyncio.Queue is NOT thread-
    safe, so publish() must route through call_soon_threadsafe.
    """
    b = _fresh()
    async with b.subscribe() as events:
        done = threading.Event()

        def worker() -> None:
            try:
                for i in range(10):
                    b.publish({"seq": i, "from": "worker"})
            finally:
                done.set()

        t = threading.Thread(target=worker)
        t.start()

        received: list[dict] = []
        for _ in range(10):
            evt = await asyncio.wait_for(events.__anext__(), timeout=2.0)
            received.append(evt)

        t.join(timeout=2.0)
        assert done.is_set(), "worker thread failed to complete"

    assert [e["seq"] for e in received] == list(range(10))
    assert all(e["from"] == "worker" for e in received)


async def test_concurrent_publish_and_subscribe_no_corruption() -> None:
    """subscribe() racing with publish() from a worker must not corrupt state."""
    b = _fresh()
    stop = threading.Event()

    def publisher() -> None:
        i = 0
        while not stop.is_set():
            b.publish({"seq": i})
            i += 1

    t = threading.Thread(target=publisher)
    t.start()
    try:
        # Open + close several subscribers while the worker floods publish().
        for _ in range(5):
            async with b.subscribe() as events:
                try:
                    await asyncio.wait_for(events.__anext__(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
    finally:
        stop.set()
        t.join(timeout=2.0)

    # After all subscribers exit the registry must be clean.
    assert len(b._queues) == 0
