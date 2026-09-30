"""
SentinelScope Threat Intelligence Dual-Source Enrichment Engine.

Provides asynchronous querying for:
- IP: VirusTotal v3 AND AbuseIPDB v2
- Domain: VirusTotal v3 AND URLhaus API (host)
- URL: VirusTotal v3 (url_id base64 safe) AND URLhaus API (url)
- Hash: VirusTotal v3 AND MalwareBazaar API

Features:
- httpx.AsyncClient with 10s timeout
- In-memory TTLCache (cachetools)
- Resilient error handling (404 not found, 429 rate limit, 401/403, and timeouts)
"""

import asyncio
import base64
import os
from typing import Any, Dict

import httpx
from cachetools import TTLCache
from dotenv import load_dotenv

# Load API credentials from environment
load_dotenv()
load_dotenv("api-keys.env")

VT_API_KEY: str = os.getenv("VT_API_KEY", "").strip()
ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ABUSE_CH_API_KEY: str = os.getenv("ABUSE_CH_API_KEY", "").strip()

# In-memory TTL cache: max 2048 indicators, TTL = 10 minutes (600 seconds)
ENRICHMENT_CACHE: TTLCache = TTLCache(maxsize=2048, ttl=600)

HTTP_TIMEOUT_SECONDS: float = 10.0


async def query_virustotal(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """
    Queries VirusTotal v3 API for IP, Domain, URL, or File Hash.
    Catches 404s, 429s, and timeouts gracefully.
    """
    if not VT_API_KEY:
        return {
            "status": "unconfigured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "message": "VirusTotal API key not configured in .env",
        }

    headers = {"x-apikey": VT_API_KEY}

    # Construct endpoint based on IOC type
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"
    elif ioc_type == "url":
        # Base64 URL-safe encoding without '=' padding
        encoded_url = base64.urlsafe_b64encode(ioc_value.encode("utf-8")).decode("ascii").rstrip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return {"status": "error", "message": f"Unsupported IOC type for VirusTotal: {ioc_type}"}

    try:
        response = await client.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = sum(stats.values()) if stats else 0

            ptc = attributes.get("popular_threat_classification", {})
            suggested_label = ptc.get("suggested_threat_label") or attributes.get("suggested_threat_label")

            return {
                "status": "success",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
                "reputation": attributes.get("reputation", 0),
                "as_owner": attributes.get("as_owner", attributes.get("network")),
                "asn": attributes.get("asn"),
                "network": attributes.get("network"),
                "country": attributes.get("country"),
                "meaningful_name": attributes.get("meaningful_name"),
                "registrar": attributes.get("registrar"),
                "tags": attributes.get("tags", []),
                "categories": attributes.get("categories", {}),
                "popular_threat_classification": ptc,
                "suggested_threat_label": suggested_label,
            }

        elif response.status_code == 404:
            return {
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0,
                "message": "Indicator not cataloged in VirusTotal",
            }

        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0,
                "message": "VirusTotal API rate limit exceeded",
            }

        elif response.status_code in (401, 403):
            return {
                "status": "auth_error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0,
                "message": "VirusTotal authentication error or invalid API key",
            }

        else:
            return {
                "status": "error",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total": 0,
                "message": f"VirusTotal returned HTTP {response.status_code}",
            }

    except httpx.TimeoutException:
        return {
            "status": "timeout",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "message": "VirusTotal request timed out",
        }
    except Exception as exc:
        return {
            "status": "error",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "total": 0,
            "message": str(exc),
        }


async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    """
    Queries AbuseIPDB v2 API for IP reputation and abuse confidence score.
    Catches 404s, 429s, and timeouts gracefully.
    """
    if not ABUSEIPDB_API_KEY:
        return {
            "status": "unconfigured",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "message": "AbuseIPDB API key not configured in .env",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
    }

    try:
        response = await client.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json().get("data", {})
            reports = data.get("reports", [])
            cat_id_map = {
                1: "DNS Compromise", 3: "Fraud VoIP", 4: "DDoS Attack", 9: "Open Proxy",
                10: "Web Spam", 11: "Email Spam", 14: "Port Scan", 15: "Hacking",
                18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
                21: "Web App Attack", 22: "SSH Brute-Force", 23: "IoT Targeted",
            }
            extracted_cats = set()
            if isinstance(reports, list):
                for rep in reports:
                    for cid in rep.get("categories", []):
                        if cid in cat_id_map:
                            extracted_cats.add(cat_id_map[cid])

            return {
                "status": "success",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "usageType": data.get("usageType"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_tor": data.get("isTor", False),
                "last_reported_at": data.get("lastReportedAt"),
                "attack_categories": sorted(list(extracted_cats)),
            }

        elif response.status_code == 404:
            return {
                "status": "not_found",
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "message": "IP address not found in AbuseIPDB database",
            }

        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "message": "AbuseIPDB rate limit exceeded",
            }

        elif response.status_code in (401, 403):
            return {
                "status": "auth_error",
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "message": "AbuseIPDB authentication failed or invalid API key",
            }

        else:
            return {
                "status": "error",
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "message": f"AbuseIPDB returned HTTP {response.status_code}",
            }

    except httpx.TimeoutException:
        return {
            "status": "timeout",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "message": "AbuseIPDB request timed out",
        }
    except Exception as exc:
        return {
            "status": "error",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "message": str(exc),
        }


async def query_urlhaus(client: httpx.AsyncClient, ioc_type: str, ioc_value: str) -> Dict[str, Any]:
    """
    Queries URLhaus API (abuse.ch) for Domain (host) or URL.
    Catches 404s, 429s, and authentication errors gracefully.
    """
    api_key = os.getenv("ABUSE_CH_API_KEY", "").strip()
    headers = {"Auth-Key": api_key}

    if ioc_type == "domain":
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        payload = {"host": ioc_value}
    elif ioc_type == "url":
        url = "https://urlhaus-api.abuse.ch/v1/url/"
        payload = {"url": ioc_value}
    else:
        return {"status": "error", "message": f"Unsupported IOC type for URLhaus: {ioc_type}"}

    try:
        response = await client.post(url, data=payload, headers=headers)

        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status", "unknown")

            if query_status == "ok":
                # For host: examine urlhaus_status or check URL list
                urlhaus_status = data.get("urlhaus_status", "")
                url_status = data.get("url_status", "")
                threat = data.get("threat", "")
                url_count = data.get("url_count", 0)

                active_threat = False
                historical_threat = False

                # Evaluate active vs historical status
                if ioc_type == "domain":
                    urls = data.get("urls", [])
                    has_online = any(u.get("url_status") == "online" for u in urls)
                    if urlhaus_status in ("online", "active") or has_online:
                        active_threat = True
                        urlhaus_status = "active"
                    elif url_count > 0 or urlhaus_status in ("offline", "historical"):
                        historical_threat = True
                        urlhaus_status = "offline"
                else:  # URL
                    if url_status == "online" or threat == "malware_download":
                        active_threat = True
                        urlhaus_status = "active"
                    elif url_status == "offline":
                        historical_threat = True
                        urlhaus_status = "offline"

                tags = data.get("tags", [])
                if not tags and ioc_type == "domain":
                    for u in data.get("urls", []):
                        u_tags = u.get("tags", [])
                        if isinstance(u_tags, list):
                            tags.extend(u_tags)
                tags = list(dict.fromkeys(tags))

                return {
                    "status": "success",
                    "query_status": query_status,
                    "urlhaus_status": urlhaus_status or "offline",
                    "url_status": url_status,
                    "threat": threat,
                    "active_threat": active_threat,
                    "historical_threat": historical_threat,
                    "url_count": url_count,
                    "tags": tags,
                }

            elif query_status in ("no_results", "host_not_found", "url_not_found"):
                return {
                    "status": "not_found",
                    "query_status": query_status,
                    "urlhaus_status": "none",
                    "active_threat": False,
                    "historical_threat": False,
                    "message": "Indicator not cataloged in URLhaus",
                }

            else:
                return {
                    "status": "not_found",
                    "query_status": query_status,
                    "urlhaus_status": "none",
                    "active_threat": False,
                    "historical_threat": False,
                    "message": f"URLhaus query status: {query_status}",
                }

        elif response.status_code == 404:
            return {
                "status": "not_found",
                "urlhaus_status": "none",
                "active_threat": False,
                "historical_threat": False,
                "message": "URLhaus host/url not found",
            }

        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "urlhaus_status": "none",
                "active_threat": False,
                "historical_threat": False,
                "message": "URLhaus rate limit exceeded",
            }

        elif response.status_code in (401, 403):
            return {
                "status": "auth_error",
                "urlhaus_status": "none",
                "active_threat": False,
                "historical_threat": False,
                "message": "URLhaus authentication failed or invalid Auth-Key",
            }

        else:
            return {
                "status": "error",
                "urlhaus_status": "none",
                "active_threat": False,
                "historical_threat": False,
                "message": f"URLhaus returned HTTP {response.status_code}",
            }

    except httpx.TimeoutException:
        return {
            "status": "timeout",
            "urlhaus_status": "none",
            "active_threat": False,
            "historical_threat": False,
            "message": "URLhaus request timed out",
        }
    except Exception as exc:
        return {
            "status": "error",
            "urlhaus_status": "none",
            "active_threat": False,
            "historical_threat": False,
            "message": str(exc),
        }


async def query_malwarebazaar(client: httpx.AsyncClient, file_hash: str) -> Dict[str, Any]:
    """
    Queries MalwareBazaar API (abuse.ch) for file hash intelligence.
    Catches 404s, 429s, and authentication errors gracefully.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    api_key = os.getenv("ABUSE_CH_API_KEY", "").strip()
    headers = {"Auth-Key": api_key}

    payload = {
        "query": "get_info",
        "hash": file_hash,
    }

    try:
        response = await client.post(url, data=payload, headers=headers)

        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status", "unknown")

            if query_status == "ok":
                samples = data.get("data", [])
                sample = samples[0] if samples else {}
                return {
                    "status": "success",
                    "query_status": "ok",
                    "confirmed": True,
                    "signature": sample.get("signature"),
                    "file_type": sample.get("file_type"),
                    "delivery_method": sample.get("delivery_method"),
                    "first_seen": sample.get("first_seen"),
                    "file_name": sample.get("file_name"),
                    "tags": sample.get("tags", []),
                }
            elif query_status in ("hash_not_found", "no_results"):
                return {
                    "status": "not_found",
                    "query_status": query_status,
                    "confirmed": False,
                    "message": "Hash not found in MalwareBazaar",
                }
            else:
                return {
                    "status": "not_found",
                    "query_status": query_status,
                    "confirmed": False,
                    "message": f"MalwareBazaar query status: {query_status}",
                }

        elif response.status_code == 404:
            return {
                "status": "not_found",
                "confirmed": False,
                "message": "Hash not cataloged in MalwareBazaar",
            }

        elif response.status_code == 429:
            return {
                "status": "rate_limited",
                "confirmed": False,
                "message": "MalwareBazaar rate limit exceeded",
            }

        elif response.status_code in (401, 403):
            return {
                "status": "auth_error",
                "confirmed": False,
                "message": "MalwareBazaar authentication failed or invalid Auth-Key",
            }

        else:
            return {
                "status": "error",
                "confirmed": False,
                "message": f"MalwareBazaar returned HTTP {response.status_code}",
            }

    except httpx.TimeoutException:
        return {
            "status": "timeout",
            "confirmed": False,
            "message": "MalwareBazaar request timed out",
        }
    except Exception as exc:
        return {
            "status": "error",
            "confirmed": False,
            "message": str(exc),
        }


async def enrich_ioc(ioc_type: str, refanged_ioc: str) -> Dict[str, Any]:
    """
    Performs dual-source threat intelligence querying concurrently using asyncio.gather.
    Caches results in-memory using TTLCache.
    """
    cache_key = f"{ioc_type}:{refanged_ioc}"
    if cache_key in ENRICHMENT_CACHE:
        return ENRICHMENT_CACHE[cache_key]

    raw_metrics: Dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        if ioc_type == "ip":
            vt_task = query_virustotal(client, "ip", refanged_ioc)
            abuse_task = query_abuseipdb(client, refanged_ioc)
            vt_res, abuse_res = await asyncio.gather(vt_task, abuse_task, return_exceptions=True)

            raw_metrics["virustotal"] = (
                vt_res if isinstance(vt_res, dict) else {"status": "error", "message": str(vt_res), "malicious": 0, "total": 0}
            )
            raw_metrics["abuseipdb"] = (
                abuse_res if isinstance(abuse_res, dict) else {"status": "error", "message": str(abuse_res), "abuse_confidence_score": 0}
            )

        elif ioc_type == "domain":
            vt_task = query_virustotal(client, "domain", refanged_ioc)
            urlhaus_task = query_urlhaus(client, "domain", refanged_ioc)
            vt_res, urlhaus_res = await asyncio.gather(vt_task, urlhaus_task, return_exceptions=True)

            raw_metrics["virustotal"] = (
                vt_res if isinstance(vt_res, dict) else {"status": "error", "message": str(vt_res), "malicious": 0, "total": 0}
            )
            raw_metrics["urlhaus"] = (
                urlhaus_res if isinstance(urlhaus_res, dict) else {"status": "error", "message": str(urlhaus_res), "urlhaus_status": "none"}
            )

        elif ioc_type == "url":
            vt_task = query_virustotal(client, "url", refanged_ioc)
            urlhaus_task = query_urlhaus(client, "url", refanged_ioc)
            vt_res, urlhaus_res = await asyncio.gather(vt_task, urlhaus_task, return_exceptions=True)

            raw_metrics["virustotal"] = (
                vt_res if isinstance(vt_res, dict) else {"status": "error", "message": str(vt_res), "malicious": 0, "total": 0}
            )
            raw_metrics["urlhaus"] = (
                urlhaus_res if isinstance(urlhaus_res, dict) else {"status": "error", "message": str(urlhaus_res), "urlhaus_status": "none"}
            )

        elif ioc_type == "hash":
            vt_task = query_virustotal(client, "hash", refanged_ioc)
            mb_task = query_malwarebazaar(client, refanged_ioc)
            vt_res, mb_res = await asyncio.gather(vt_task, mb_task, return_exceptions=True)

            raw_metrics["virustotal"] = (
                vt_res if isinstance(vt_res, dict) else {"status": "error", "message": str(vt_res), "malicious": 0, "total": 0}
            )
            raw_metrics["malwarebazaar"] = (
                mb_res if isinstance(mb_res, dict) else {"status": "error", "message": str(mb_res), "confirmed": False}
            )

    # Cache successful lookup
    ENRICHMENT_CACHE[cache_key] = raw_metrics
    return raw_metrics
