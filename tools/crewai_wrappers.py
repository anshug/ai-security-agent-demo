from crewai_tools import BaseTool
from pydantic import BaseModel, Field

from tools.ip_tools import (
    geo_lookup_ipapi,
    rdap_ip_lookup,
    asn_lookup_team_cymru,
    spamhaus_zen_check,
)

class IPInput(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to investigate.")

class GeoLookupTool(BaseTool):
    name: str = "geo_lookup"
    description: str = "Geolocate an IP address (country/region/city/lat/lon + basic ISP/org if available)."
    args_schema = IPInput

    def _run(self, ip: str):
        return geo_lookup_ipapi(ip)

class RDAPLookupTool(BaseTool):
    name: str = "rdap_lookup"
    description: str = "Fetch RDAP (WHOIS replacement) registration data for an IP range."
    args_schema = IPInput

    def _run(self, ip: str):
        return rdap_ip_lookup(ip)

class ASNLookupTool(BaseTool):
    name: str = "asn_lookup"
    description: str = "Get ASN and announced prefix for an IP using Team Cymru mapping."
    args_schema = IPInput

    def _run(self, ip: str):
        return asn_lookup_team_cymru(ip)

class SpamhausZenTool(BaseTool):
    name: str = "spamhaus_zen_check"
    description: str = "Check if an IPv4 is listed on Spamhaus ZEN DNSBL (returns listing codes)."
    args_schema = IPInput

    def _run(self, ip: str):
        return spamhaus_zen_check(ip)
