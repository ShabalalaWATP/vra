"""In-process async event bus for scan progress streaming."""

import asyncio
import logging
import uuid
from collections import defaultdict
from typing import Any, AsyncIterator

logger = logging.getLogger(__name__)


class EventBus:
    """Simple pub/sub event bus using asyncio.Queue per subscriber."""

    def __init__(self) -> None:
        self._subscribers: dict[uuid.UUID, list[asyncio.Queue]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def publish(self, scan_id: uuid.UUID, event: dict[str, Any]) -> None:
        """Publish an event to all subscribers of a scan."""
        async with self._lock:
            queues = list(self._subscribers.get(scan_id, []))
        for queue in queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Event queue full for scan %s, dropping event", scan_id)

    async def subscribe(self, scan_id: uuid.UUID) -> AsyncIterator[dict[str, Any]]:
        """Subscribe to events for a scan. Yields events as they arrive."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        async with self._lock:
            self._subscribers[scan_id].append(queue)
        try:
            while True:
                event = await queue.get()
                if event is None:  # Sentinel for completion
                    break
                yield event
        finally:
            async with self._lock:
                self._subscribers[scan_id].remove(queue)
                if not self._subscribers[scan_id]:
                    del self._subscribers[scan_id]

    async def complete(self, scan_id: uuid.UUID) -> None:
        """Signal that a scan is done, unblock all subscribers."""
        async with self._lock:
            queues = list(self._subscribers.get(scan_id, []))
        for queue in queues:
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                logger.warning("Queue full during complete for scan %s", scan_id)


# Global singleton
event_bus = EventBus()
