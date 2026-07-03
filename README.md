# AI Security Agent

An open source, from-scratch AI Security Agent that takes a suspicious IP address and autonomously performs geolocation lookup, RDAP/WHOIS enrichment, ASN identification, and DNSBL blacklist reputation checks, then produces a risk-rated, human-readable analyst report.

Built to prove a simple point: you do not need a commercial black box to get agentic security tooling. You can build one yourself, understand every piece of it, and extend it to your own environment.

This project is the companion tool for the Black Hat Arsenal Europe 2026 session and the "Building an AI Security Agent from Scratch" full-day training by Anshu Gupta.

## What it does

Give the agent an IP address. It runs a three-stage pipeline and hands back a complete report, no manual lookups required.

**Task 1, Enrichment**
- Geolocation lookup via ip-api
- RDAP ownership and registry data (the modern, JSON-based successor to WHOIS)
- ASN identification via a Team Cymru DNS query

**Task 2, Reputation**
- Spamhaus ZEN DNSBL query
- Blacklist status code decoding

**Task 3, Final Report**
- Risk rating
- Recommended actions
- Human-readable analyst summary

## Architecture

- **Orchestration**: CrewAI, with defined agent roles and a task execution pipeline
- **LLM layer**: OpenAI GPT, temperature 0, for deterministic and reproducible output
- **Threat intelligence sources**: ip-api (geo), RDAP (ownership/ASN registry data), Team Cymru (ASN), Spamhaus ZEN (blacklist)
- **Language**: Python 3.12
- **Guardrails**: input sanitization to reduce prompt injection risk, rate limiting and cost control, full action logging for auditability

The agent follows a think-act-observe loop: it reasons about which tool to call next, calls it, observes the result, and decides the next step, until it has enough information to generate the final report.

## Repository structure

```
ai-security-agent-demo/
├── src/           # Core agent logic
├── tools/         # Individual tool implementations (geo, RDAP, ASN, DNSBL)
├── crew.py        # CrewAI orchestration: agents, roles, tasks
├── main.py        # Entry point
└── LICENSE
```

## Prerequisites

- Basic Python familiarity
- Familiarity with core security concepts (SIEM, SOC, threat intelligence) is helpful but not required
- Python 3.12 (CrewAI requires 3.10 or higher; 3.12 is recommended to avoid dependency issues with newer Python releases)
- An OpenAI API key

## Setup

**1. Install Python 3.12**

```bash
brew install python@3.12
python3 --version
```

**2. Clone the repository**

```bash
git clone https://github.com/anshug/ai-security-agent-demo.git
cd ai-security-agent-demo
```

**3. Create and activate a virtual environment**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**4. Install dependencies**

```bash
pip3 install crewai
pip3 install 'crewai[tools]'
pip install dnspython
```

**5. Configure your API key**

Create a `.env` file in the project root:

```
OPENAI_API_KEY=your_key_here
```

Make sure `.env` is listed in `.gitignore` so you never commit your key.

## Usage

```bash
python3 main.py [IP_ADDRESS]
```

The agent will run through enrichment, reputation checks, and report generation, then print a risk-rated analyst summary to the terminal.

## Guardrails

This project treats guardrails as a default, not an afterthought:

- **Input sanitization**: reduces prompt injection risk at the tool and system prompt layer
- **Rate limiting and cost control**: protects against runaway agent loops
- **Action logging**: every tool call and agent decision is logged for auditability
- **Human-in-the-loop**: the pattern is designed so consequential actions can be gated behind human review before extension into production environments

## Extending the agent

The `check_ip_reputation` pattern in `tools/` is designed as a template. Natural extensions include:

- A phishing content analyzer
- A log file triage assistant
- A vulnerability report summarizer
- Multi-agent coordination across several specialized agents
- Web search tool integration (e.g. Tavily) for live threat intel context

## Troubleshooting

- **"python: command not found"**: use `python3` instead of `python`
- **CrewAI install fails on newer Python versions**: CrewAI's dependency `tiktoken` has version ceilings; use Python 3.12 rather than the latest release
- **Missing Rust compiler**: install via `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Stale package managers**: run `pip install --upgrade pip` and `brew upgrade`

## Background

This tool was built as part of a full-day hands-on training, "Building an AI Security Agent from Scratch," and is presented as a live demo at Black Hat Arsenal Europe 2026. The goal is to close the gap between AI agents as theoretical concepts or commercial black boxes, and AI agents as systems security practitioners can design, build, and deploy themselves.

## About the author

[Anshu Gupta](https://www.linkedin.com/in/fromanshu/) is Founder and CISO at Fixin Security, and Founder of [Tejas Cyber Network](https://www.tejascybernetwork.com/), a global vendor-agnostic cybersecurity community. He is co-author of the AI Security Guide and a 20+ year cybersecurity executive.

Questions, collaboration ideas, or want to talk about extending this agent for your environment? [Book time here:](https://calendly.com/fixinsecurity/30-minute-consult?month=2026-07)

## License

This project is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0). See [LICENSE](LICENSE) for details.
