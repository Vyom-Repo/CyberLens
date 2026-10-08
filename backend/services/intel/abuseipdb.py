"""AbuseIPDB API v2 Client Implementation."""

from typing import Any, Dict
import httpx

from backend.core.config import settings
from backend.services.intel.base import BaseIntelClient, DEFAULT_TIMEOUT_SECONDS
from backend.services.intel.mock_data import get_mock_abuseipdb_data


class AbuseIPDBClient(BaseIntelClient):
    """Asynchronous client for AbuseIPDB API v2."""

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str = "", offline_mode: bool = False):
        self.api_key = api_key or settings.abuseipdb_api_key
        self.offline_mode = offline_mode or settings.offline_mode

    async def fetch_intelligence(self, ioc: str, ioc_type: str = "IPv4") -> Dict[str, Any]:
        """Fetch IP reputation intelligence from AbuseIPDB API v2 or local offline mock."""
        # AbuseIPDB only supports IP addresses
        if ioc_type.upper() not in ("IPV4", "IPV6"):
            return {
                "status": "NOT_QUERIED",
                "data": {},
                "message": f"AbuseIPDB does not support IOC type '{ioc_type}'.",
            }

        # Check if offline mode is explicitly active or no API key is configured
        if self.offline_mode or not self.api_key:
            mock_payload = get_mock_abuseipdb_data(ioc)
            return {
                "status": "SUCCESS",
                "data": mock_payload.get("data", {}),
                "message": "Served via offline intelligence simulation.",
            }

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "CTI-Dashboard-SOC/1.0",
        }
        params = {
            "ipAddress": ioc,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
                response = await client.get(self.BASE_URL, headers=headers, params=params)

                if response.status_code == 200:
                    payload = response.json()
                    return {
                        "status": "SUCCESS",
                        "data": payload.get("data", {}),
                        "message": "Intelligence retrieved successfully.",
                    }

                elif response.status_code == 404:
                    return {
                        "status": "NOT_FOUND",
                        "data": {},
                        "message": "IP address has not been reported to AbuseIPDB.",
                    }

                elif response.status_code == 429:
                    return {
                        "status": "RATE_LIMITED",
                        "data": {},
                        "message": "AbuseIPDB API rate limit/quota reached.",
                    }

                elif response.status_code in (401, 403):
                    return {
                        "status": "FAILED",
                        "data": {},
                        "message": "AbuseIPDB authorization failed. Invalid API key.",
                    }

                else:
                    return {
                        "status": "FAILED",
                        "data": {},
                        "message": f"AbuseIPDB returned unexpected HTTP {response.status_code}.",
                    }

        except httpx.TimeoutException:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"AbuseIPDB request timed out after {DEFAULT_TIMEOUT_SECONDS} seconds.",
            }
        except httpx.RequestError as exc:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"Network error connecting to AbuseIPDB: {str(exc)}",
            }
        except Exception as exc:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"Unexpected error querying AbuseIPDB: {str(exc)}",
            }
