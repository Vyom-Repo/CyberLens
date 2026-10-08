"""Threat Intelligence Dispatcher Service.

Coordinates concurrent, asynchronous execution of intelligence queries
across supported providers using asyncio.gather.
"""

import asyncio
from typing import Any, Dict, List, Optional

from backend.services.intel.abuseipdb import AbuseIPDBClient
from backend.services.intel.virustotal import VirusTotalClient


class IntelDispatcher:
    """Dispatches threat intelligence requests to appropriate vendor clients in parallel."""

    def __init__(
        self,
        vt_client: Optional[VirusTotalClient] = None,
        abuse_client: Optional[AbuseIPDBClient] = None,
    ):
        self.vt_client = vt_client or VirusTotalClient()
        self.abuse_client = abuse_client or AbuseIPDBClient()

    async def dispatch(
        self,
        ioc: str,
        ioc_type: str,
        supported_sources: List[str],
    ) -> Dict[str, Any]:
        """Dispatch queries to all supported threat feeds concurrently.

        Args:
            ioc: Sanitized IOC string.
            ioc_type: Confirmed IOC type (IPv4, Domain, etc.).
            supported_sources: List of providers to query.

        Returns:
            Dictionary containing individual raw vendor responses and metadata.
        """
        tasks = []
        task_names = []

        if "virustotal" in supported_sources:
            tasks.append(self.vt_client.fetch_intelligence(ioc, ioc_type))
            task_names.append("virustotal")

        if "abuseipdb" in supported_sources:
            tasks.append(self.abuse_client.fetch_intelligence(ioc, ioc_type))
            task_names.append("abuseipdb")

        # Execute all outbound queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        raw_intel: Dict[str, Any] = {
            "virustotal": None,
            "abuseipdb": None,
        }

        for name, result in zip(task_names, results):
            if isinstance(result, Exception):
                raw_intel[name] = {
                    "status": "FAILED",
                    "data": {},
                    "message": f"Unhandled client error: {str(result)}",
                }
            else:
                raw_intel[name] = result

        return raw_intel
