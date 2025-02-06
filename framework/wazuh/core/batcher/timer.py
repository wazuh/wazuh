import asyncio
from typing import Optional


class TimerManager:
    """Manage the timer for sending the buffer.

    Parameters
    ----------
    max_time_seconds : int
        Maximum time in seconds before triggering the timeout event.
    """

    def __init__(self, max_time_seconds: int):
        self.max_time_seconds = max_time_seconds
        self._timeout_event = asyncio.Event()
        self._timeout_task: Optional[asyncio.Future] = None

    async def _event_timer(self):
        """Asynchronous timer that waits for the configured max time before setting the timeout event."""
        await asyncio.sleep(self.max_time_seconds)
        self._timeout_event.set()

    def start_timer(self):
        """Create an asynchronous task to start the event timer."""
        self._timeout_task = asyncio.create_task(self._event_timer())

    def reset_timer(self):
        """Reset the timer by canceling the current timer task (if any) and clearing the timeout event."""
        if self._timeout_task is not None:
            self._timeout_task.cancel()
            self._timeout_task = None
        self._timeout_event.clear()

    async def wait_timeout_event(self):
        """Asynchronously wait for the timeout event to be set."""
        return await self._timeout_event.wait()
