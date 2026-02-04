import os
from crewai import Agent, Task, Crew, Process
from tools.crewai_wrappers import GeoLookupTool, RDAPLookupTool, ASNLookupTool, SpamhausZenTool

# CrewAI will use your OpenAI key from env (.env or exported)
assert os.getenv("OPENAI_API_KEY"), "OPENAI_API_KEY is required"

geo_tool = GeoLookupTool()
rdap_tool = RDAPLookupTool()
asn_tool = ASNLookupTool()
zen_tool = SpamhausZenTool()

enrichment_agent = Agent(
    role="IP Enrichment Analyst",
    goal="Enrich an IP with geo + ownership + ASN using reliable free sources.",
    backstory="You are a SOC analyst who produces clean, structured enrichment for downstream detection.",
    tools=[geo_tool, rdap_tool, asn_tool],
    verbose=True,
)

reputation_agent = Agent(
    role="Reputation & Blocklist Analyst",
    goal="Assess whether an IP is known-bad or suspicious using free DNSBL checks and produce a risk signal.",
    backstory="You specialize in email/network reputation signals and understand DNSBL result codes.",
    tools=[zen_tool],
    verbose=True,
)

report_agent = Agent(
    role="Security Report Writer",
    goal="Generate an executive-ready report and JSON output with confidence and recommended actions.",
    backstory="You turn raw signals into clear decisions: benign/suspicious/malicious and what to do next.",
    tools=[],
    verbose=True,
)

def build_crew(ip: str) -> Crew:
    t1 = Task(
        description=f"Enrich IP={ip}. Return JSON with geo, rdap ownership, and ASN details.",
        expected_output="A JSON object containing geo, rdap, asn sections.",
        agent=enrichment_agent,
    )

    t2 = Task(
        description=f"Check reputation for IP={ip}. Use Spamhaus ZEN tool. Provide listed status + codes and a short interpretation.",
        expected_output="A JSON object containing dnsbl results and a reputation assessment.",
        agent=reputation_agent,
        context=[t1],
    )

    t3 = Task(
        description=(
            f"Using enrichment + reputation results for IP={ip}, produce:\n"
            "1) A final JSON object with fields: ip, geo, rdap, asn, reputation, risk_rating (low/med/high), rationale, recommended_actions.\n"
            "2) A short human summary (5-8 bullets)."
        ),
        expected_output="Final JSON + bullet summary.",
        agent=report_agent,
        context=[t1, t2],
    )

    return Crew(
        agents=[enrichment_agent, reputation_agent, report_agent],
        tasks=[t1, t2, t3],
        process=Process.sequential,
        verbose=True,
    )
