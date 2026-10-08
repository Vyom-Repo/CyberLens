"""VirusTotal API v3 Client Implementation."""

import base64
from typing import Any, Dict
import httpx

from backend.core.config import settings
from backend.services.intel.base import BaseIntelClient, DEFAULT_TIMEOUT_SECONDS
from backend.services.intel.mock_data import get_mock_virustotal_data


class VirusTotalClient(BaseIntelClient):
    """Asynchronous client for VirusTotal API v3."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = "", offline_mode: bool = False):
        self.api_key = api_key or settings.vt_api_key
        self.offline_mode = offline_mode or settings.offline_mode

    def _get_url_identifier(self, url: str) -> str:
        """VirusTotal v3 requires base64url encoding without padding for URL identifiers."""
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
        return encoded.strip("=")

    def _build_endpoint(self, ioc: str, ioc_type: str) -> str:
        """Map IOC type to the correct VirusTotal v3 endpoint path."""
        upper_type = ioc_type.upper()
        if upper_type in ("IPV4", "IPV6"):
            return f"{self.BASE_URL}/ip_addresses/{ioc}"
        elif upper_type == "DOMAIN":
            return f"{self.BASE_URL}/domains/{ioc}"
        elif upper_type == "URL":
            url_id = self._get_url_identifier(ioc)
            return f"{self.BASE_URL}/urls/{url_id}"
        elif upper_type in ("MD5", "SHA-1", "SHA-256"):
            return f"{self.BASE_URL}/files/{ioc.lower()}"
        else:
            raise ValueError(f"Unsupported IOC type for VirusTotal: {ioc_type}")

    async def fetch_intelligence(self, ioc: str, ioc_type: str) -> Dict[str, Any]:
        """Fetch threat intelligence from VirusTotal API v3 or local offline mock."""
        # Check if offline mode is explicitly active or no API key is configured
        if self.offline_mode or not self.api_key:
            mock_payload = get_mock_virustotal_data(ioc, ioc_type)
            return {
                "status": "SUCCESS",
                "data": mock_payload.get("data", {}),
                "message": "Served via offline intelligence simulation.",
            }

        endpoint = self._build_endpoint(ioc, ioc_type)
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json",
            "User-Agent": "CTI-Dashboard-SOC/1.0",
        }

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers)

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
                        "message": "Indicator has not been observed or cataloged by VirusTotal.",
                    }

                elif response.status_code == 429:
                    return {
                        "status": "RATE_LIMITED",
                        "data": {},
                        "message": "VirusTotal API rate limit/quota reached.",
                    }

                elif response.status_code in (401, 403):
                    return {
                        "status": "FAILED",
                        "data": {},
                        "message": "VirusTotal authorization failed. Invalid API key.",
                    }

                else:
                    return {
                        "status": "FAILED",
                        "data": {},
                        "message": f"VirusTotal returned unexpected HTTP {response.status_code}.",
                    }

        except httpx.TimeoutException:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"VirusTotal API request timed out after {DEFAULT_TIMEOUT_SECONDS} seconds.",
            }
        except httpx.RequestError as exc:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"Network error connecting to VirusTotal: {str(exc)}",
            }
        except Exception as exc:
            return {
                "status": "FAILED",
                "data": {},
                "message": f"Unexpected error querying VirusTotal: {str(exc)}",
            }
