"""
Assignment 11 — Rate Limiter starter (TODO).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        if invocation_context is None:
            user_id = "anonymous"
        elif isinstance(invocation_context, dict):
            user_id = invocation_context.get("user_id", "anonymous")
        else:
            user_id = getattr(invocation_context, "user_id", None) or "anonymous"

        now = time.time()
        window = self.user_windows[user_id]
        # Sliding window implementation
        while window and window[0] <= now - self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            wait = max(0.0, self.window_seconds - (now - window[0]))
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Try again in {wait:.0f}s."
            )

        window.append(now)
        return None
