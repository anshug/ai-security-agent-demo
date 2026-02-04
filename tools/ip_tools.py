import ipaddress
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
import dns.resolver


# ----------------------------
# Utilities
# ----------------------------

def validate_ip(ip: str) -> str:
    """Raises ValueError if invalid."""
    ipaddress.ip_address(ip)
    return ip

def http_get_json(url: str, timeout: int = 10) -> Dict[str, Any]:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "ai-sec-agent/1.0"})
    r.raise_for_status()
    return r.json()

# Simple in-memory cache for classroom demo
_CACHE: Dict[str, Any] = {}
_CACHE_TTL_S = 300

def cache_get(key: str):
    v = _CACHE.get(key)
    if not v:
        return None
    ts, payload = v
    if time.time() - ts > _CACHE_TTL_S:
        _CACHE.pop(key, None)
        return None
    return payload

def cache_set(key: str, payload: Any):
    _CACHE[key] = (time.time(), payload)


# ----------------------------
# 1) Geolocation via ip-api.com (no key)
# ----------------------------

def geo_lookup_ipapi(ip: str) -> Dict[str, Any]:
    ip = validate_ip(ip)
    cache_key = f"geo:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    # ip-api supports "fields" to keep payload small
    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,query,country,regionName,city,lat,lon,timezone,isp,org,as"
    )
    data = http_get_json(url)
    if data.get("status") != "success":
        raise RuntimeError(f"ip-api failed: {data.get('message')}")
    cache_set(cache_key, data)
    return data


# ----------------------------
# 2) WHOIS-ish via RDAP (JSON, standards-based)
# ----------------------------

def rdap_ip_lookup(ip: str) -> Dict[str, Any]:
    """
    RDAP bootstrap can be complex. For a class demo:
    - Try rdap.org proxy endpoint first.
    - If it fails, you can swap in a proper bootstrap later.
    """
    ip = validate_ip(ip)
    cache_key = f"rdap:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    # rdap.org commonly exposes /ip/<ip>
    url = f"https://rdap.org/ip/{ip}"
    data = http_get_json(url)

    # Keep only the useful parts for reporting
    useful = {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "type": data.get("type"),
        "startAddress": data.get("startAddress"),
        "endAddress": data.get("endAddress"),
        "country": data.get("country"),
        "parentHandle": data.get("parentHandle"),
        "entities": data.get("entities", []),
        "remarks": data.get("remarks", []),
        "links": data.get("links", []),
    }
    cache_set(cache_key, useful)
    return useful


# ----------------------------
# 3) ASN lookup via Team Cymru (DNS interface)
# ----------------------------

def asn_lookup_team_cymru(ip: str) -> Dict[str, Any]:
    """
    Team Cymru DNS-based IP->ASN:
    - Reverse IP into the origin.asn.cymru.com zone.
    - Parse TXT record for ASN, prefix, CC, registry, allocated date.
    """
    ip = validate_ip(ip)
    cache_key = f"asn:{ip}"
    cached = cache_get(cache_key)
    if cached:
        return cached

    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        reversed_ip = ".".join(reversed(ip.split(".")))
        qname = f"{reversed_ip}.origin.asn.cymru.com"
    else:
        # IPv6: reverse nibble format for origin6.asn.cymru.com
        nibbles = addr.exploded.replace(":", "")
        reversed_nibbles = ".".join(reversed(list(nibbles)))
        qname = f"{reversed_nibbles}.origin6.asn.cymru.com"

    answers = dns.resolver.resolve(qname, "TXT")
    txt = str(answers[0]).strip('"')
    # Example format: "15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
    parts = [p.strip() for p in txt.split("|")]
    result = {
        "asn": parts[0] if len(parts) > 0 else None,
        "prefix": parts[1] if len(parts) > 1 else None,
        "country": parts[2] if len(parts) > 2 else None,
        "registry": parts[3] if len(parts) > 3 else None,
        "allocated": parts[4] if len(parts) > 4 else None,
        "raw": txt,
        "query": qname,
    }
    cache_set(cache_key, result)
    return result


# ----------------------------
# 4) Reputation / Blacklist via Spamhaus ZEN DNSBL
# ----------------------------

def spamhaus_zen_check(ip: str) -> Dict[str, Any]:
    """
    DNSBL check: reverse IPv4 and query <rev>.zen.spamhaus.org
    If listed, you'll get A records like 127.0.0.x
    """
    ip = validate_ip(ip)
    addr = ipaddress.ip_address(ip)
    if addr.version != 4:
        return {"supported": False, "listed": None, "reason": "Spamhaus ZEN is typically used for IPv4 DNSBL lookups."}

    reversed_ip = ".".join(reversed(ip.split(".")))
    qname = f"{reversed_ip}.zen.spamhaus.org"

    try:
        answers = dns.resolver.resolve(qname, "A")
        codes = [str(a) for a in answers]
        return {"supported": True, "listed": True, "codes": codes, "query": qname}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"supported": True, "listed": False, "codes": [], "query": qname}
