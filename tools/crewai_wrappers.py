from crewai.tools import tool
from tools.ip_tools import (
    geo_lookup_ipapi,
    rdap_ip_lookup,
    asn_lookup_team_cymru,
    spamhaus_zen_check,
)

@tool("geo_lookup")
def geo_lookup_tool(ip: str) -> dict:
    """Geolocate an IP address (country/region/city/lat/lon + basic ISP/org if available)."""
    return geo_lookup_ipapi(ip)

@tool("rdap_lookup")
def rdap_lookup_tool(ip: str) -> dict:
    """Fetch RDAP (WHOIS replacement) registration data for an IP range."""
    return rdap_ip_lookup(ip)

@tool("asn_lookup")
def asn_lookup_tool(ip: str) -> dict:
    """Get ASN and announced prefix for an IP using Team Cymru mapping."""
    return asn_lookup_team_cymru(ip)

@tool("spamhaus_zen_check")
def spamhaus_zen_check_tool(ip: str) -> dict:
    """Check if an IPv4 is listed on Spamhaus ZEN DNSBL (returns listing codes)."""
    return spamhaus_zen_check(ip)
