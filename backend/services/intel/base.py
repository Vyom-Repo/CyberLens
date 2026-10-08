"""Base class and common structures for Threat Intelligence API clients."""

from abc import ABC, abstractmethod
from typing import Any, Dict

DEFAULT_TIMEOUT_SECONDS = 8.0


class BaseIntelClient(ABC):
    """Abstract interface for threat intelligence client implementations."""

    @abstractmethod
    async def fetch_intelligence(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Fetch threat intelligence for an indicator.

        Returns a dictionary containing:
            - status: SUCCESS, NOT_FOUND, RATE_LIMITED, FAILED, or OFFLINE_MOCK
            - data: Raw response data from the provider
            - message: Optional diagnostic or error detail
        """
        pass
