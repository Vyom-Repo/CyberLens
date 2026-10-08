"""Mock Threat Intelligence data fixtures for discrete offline evaluation mode.

Provides authentic raw VirusTotal and AbuseIPDB API response structures
so that normalization, risk scoring, SQLite persistence, and UI rendering
execute identically whether online or offline.
"""

from typing import Any, Dict, Optional

# Realistic VirusTotal v3 mock responses
MOCK_VT_RESPONSES: Dict[str, Dict[str, Any]] = {
    # Clean IPv4
    "8.8.8.8": {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "network": "8.8.8.0/24",
                "as_owner": "GOOGLE",
                "country": "US",
                "reputation": 120,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 78,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 10,
                    "timeout": 0,
                },
            },
        }
    },
    # Clean IPv4
    "1.1.1.1": {
        "data": {
            "id": "1.1.1.1",
            "type": "ip_address",
            "attributes": {
                "network": "1.1.1.0/24",
                "as_owner": "CLOUDFLARENET",
                "country": "AU",
                "reputation": 150,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 82,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 6,
                    "timeout": 0,
                },
            },
        }
    },
    # Malicious IPv4 (Tor Exit Node / High consensus)
    "185.220.101.5": {
        "data": {
            "id": "185.220.101.5",
            "type": "ip_address",
            "attributes": {
                "network": "185.220.101.0/24",
                "as_owner": "Zwiebelfreunde e.V.",
                "country": "DE",
                "reputation": -42,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 24,
                    "malicious": 14,
                    "suspicious": 3,
                    "undetected": 47,
                    "timeout": 0,
                },
            },
        }
    },
    # Suspicious / Medium IPv4
    "193.142.59.82": {
        "data": {
            "id": "193.142.59.82",
            "type": "ip_address",
            "attributes": {
                "network": "193.142.59.0/24",
                "as_owner": "Hosting Services Inc.",
                "country": "NL",
                "reputation": -15,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 45,
                    "malicious": 4,
                    "suspicious": 2,
                    "undetected": 37,
                    "timeout": 0,
                },
            },
        }
    },
    # Clean Domain
    "example.com": {
        "data": {
            "id": "example.com",
            "type": "domain",
            "attributes": {
                "reputation": 80,
                "last_analysis_date": 1728400000,
                "categories": {"Forcepoint ThreatSeeker": "information technology"},
                "last_analysis_stats": {
                    "harmless": 84,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 4,
                    "timeout": 0,
                },
            },
        }
    },
    # Malicious Phishing Domain
    "secure-bank-login-verify.top": {
        "data": {
            "id": "secure-bank-login-verify.top",
            "type": "domain",
            "attributes": {
                "reputation": -58,
                "last_analysis_date": 1728400000,
                "categories": {"CRDF Labs": "phishing"},
                "last_analysis_stats": {
                    "harmless": 10,
                    "malicious": 18,
                    "suspicious": 4,
                    "undetected": 56,
                    "timeout": 0,
                },
            },
        }
    },
    # Malicious URL
    "http://malicious-payload-drop.org/exe.bin": {
        "data": {
            "id": "u-mock-id-malicious-url",
            "type": "url",
            "attributes": {
                "url": "http://malicious-payload-drop.org/exe.bin",
                "reputation": -60,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 5,
                    "malicious": 22,
                    "suspicious": 5,
                    "undetected": 56,
                    "timeout": 0,
                },
            },
        }
    },
    # Malicious MD5 Hash
    "44d88612fea8a8f36de82e1278abb02f": {
        "data": {
            "id": "44d88612fea8a8f36de82e1278abb02f",
            "type": "file",
            "attributes": {
                "meaningful_name": "eicar.com.txt",
                "type_description": "DOS executable",
                "reputation": -90,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 0,
                    "malicious": 62,
                    "suspicious": 1,
                    "undetected": 9,
                    "timeout": 0,
                },
            },
        }
    },
    # Malicious SHA-256 Ransomware Hash
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "data": {
            "id": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "type": "file",
            "attributes": {
                "meaningful_name": "wannacry_payload.exe",
                "type_description": "Win32 EXE",
                "reputation": -95,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 0,
                    "malicious": 58,
                    "suspicious": 0,
                    "undetected": 14,
                    "timeout": 0,
                },
            },
        }
    },
}

# Realistic AbuseIPDB v2 mock responses
MOCK_ABUSEIPDB_RESPONSES: Dict[str, Dict[str, Any]] = {
    # Clean Google DNS
    "8.8.8.8": {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Google LLC",
            "domain": "google.com",
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
        }
    },
    # Clean Cloudflare DNS
    "1.1.1.1": {
        "data": {
            "ipAddress": "1.1.1.1",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": True,
            "abuseConfidenceScore": 0,
            "countryCode": "AU",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Cloudflare, Inc.",
            "domain": "cloudflare.com",
            "totalReports": 2,
            "numDistinctUsers": 2,
            "lastReportedAt": "2026-09-15T08:00:00+00:00",
        }
    },
    # Malicious Tor Node
    "185.220.101.5": {
        "data": {
            "ipAddress": "185.220.101.5",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 88,
            "countryCode": "DE",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Zwiebelfreunde e.V.",
            "domain": "zwiebelfreunde.de",
            "totalReports": 142,
            "numDistinctUsers": 31,
            "lastReportedAt": "2026-10-08T14:30:00+00:00",
        }
    },
    # Suspicious / Medium IP
    "193.142.59.82": {
        "data": {
            "ipAddress": "193.142.59.82",
            "isPublic": True,
            "ipVersion": 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 38,
            "countryCode": "NL",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Hosting Services Inc.",
            "domain": "hostingservices.net",
            "totalReports": 12,
            "numDistinctUsers": 5,
            "lastReportedAt": "2026-10-07T11:20:00+00:00",
        }
    },
}


def get_mock_virustotal_data(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """Retrieve pre-seeded mock VirusTotal payload, or generate realistic fallback."""
    if ioc in MOCK_VT_RESPONSES:
        return MOCK_VT_RESPONSES[ioc]

    # Generate a realistic clean/unreported fallback response for novel inputs
    return {
        "data": {
            "id": ioc,
            "type": ioc_type.lower(),
            "attributes": {
                "reputation": 0,
                "last_analysis_date": 1728400000,
                "last_analysis_stats": {
                    "harmless": 72,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 16,
                    "timeout": 0,
                },
            },
        }
    }


def get_mock_abuseipdb_data(ip: str) -> Dict[str, Any]:
    """Retrieve pre-seeded mock AbuseIPDB payload, or generate realistic fallback."""
    if ip in MOCK_ABUSEIPDB_RESPONSES:
        return MOCK_ABUSEIPDB_RESPONSES[ip]

    # Generate realistic clean fallback response
    return {
        "data": {
            "ipAddress": ip,
            "isPublic": True,
            "ipVersion": 6 if ":" in ip else 4,
            "isWhitelisted": False,
            "abuseConfidenceScore": 0,
            "countryCode": "US",
            "usageType": "Commercial",
            "isp": "Local Network Transit Provider",
            "domain": None,
            "totalReports": 0,
            "numDistinctUsers": 0,
            "lastReportedAt": None,
        }
    }
