"""robots.txt policy helper."""

from __future__ import annotations

from urllib import robotparser
from urllib.parse import urlparse

import httpx


class RobotsPolicy:
    """robots.txt parser wrapper for allow checks."""

    def __init__(self, parser: robotparser.RobotFileParser | None, enabled: bool, user_agent: str) -> None:
        self._parser = parser
        self._enabled = enabled
        self._user_agent = user_agent

    def allows(self, url: str) -> bool:
        if not self._enabled or self._parser is None:
            return True
        return self._parser.can_fetch(self._user_agent, url)


async def load_policy(client: httpx.AsyncClient, base_url: str, enabled: bool, user_agent: str) -> RobotsPolicy:
    """Fetch and parse robots.txt policy if enabled."""
    if not enabled:
        return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)

    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    rp = robotparser.RobotFileParser()
    rp.set_url(robots_url)

    try:
        response = await client.get(robots_url)
        if response.status_code >= 400:
            return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)
        rp.parse(response.text.splitlines())
        return RobotsPolicy(parser=rp, enabled=True, user_agent=user_agent)
    except (httpx.HTTPError, httpx.TimeoutException):
        return RobotsPolicy(parser=None, enabled=False, user_agent=user_agent)
