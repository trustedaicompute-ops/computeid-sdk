# ComputeID SDK

**Cryptographic identity for AI compute infrastructure and agentic AI systems.**

> Every GPU needs a passport. Every AI agent needs an identity.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![PyPI version](https://img.shields.io/badge/pypi-v1.0.0-blue)](https://pypi.org/project/computeid-sdk/)
[![compute-id.com](https://img.shields.io/badge/docs-compute--id.com-00b4ff)](https://compute-id.com)

---

## What is ComputeID?

ComputeID provides two things:

1. **DeviceID** — Cryptographic passports for GPUs, servers, and compute hardware
2. **AgentID** — Cryptographic passports for AI agents and autonomous systems

Think of it as a passport system for AI infrastructure. Every device and every agent gets a unique cryptographic identity, a certificate of what it is allowed to do, and an immutable audit trail of everything it has done.

---

## Installation

```bash
pip install computeid-sdk
```

---

## Quick Start

### GPU / Device Identity

```python
from computeid import register_gpu

# Register a GPU and get a cryptographic passport
passport = register_gpu(
    name="NVIDIA A100 #1",
    ip_address="192.168.1.10",
    api_key="your-api-key"  # optional for free tier
)

print(passport.device_code)  # GPU-001
print(passport.is_valid())   # True
```

### AI Agent Identity

```python
from computeid import issue_agent_passport

# Issue a passport for your AI agent
passport = issue_agent_passport(
    agent_name="ResearchAgent",
    owner_org="Acme Corp",
    owner_email="admin@acme.com",
    trust_level="standard",
    model="claude-sonnet-4-5"
)

# Check if trusted before giving access
if passport.is_trusted():
    run_your_agent(passport=passport)

# Log every action the agent takes
passport.log_action("web_search", {"query": "market research"}, "success")

# Revoke instantly if needed
passport.revoke(reason="Unexpected behaviour detected")
```

---

## Agent Trust Levels

| Level | Description | Use Case |
|-------|-------------|----------|
| `restricted` | Read only, human oversight required | Testing, low-risk tasks |
| `standard` | Web browsing, API calls, file read | Most production agents |
| `elevated` | Code execution, spawn child agents | Advanced automation |
| `autonomous` | Full autonomy | Mission-critical systems |

---

## Full Example — Agentic AI with PassportSystem

```python
from computeid import (
    AgentPassport,
    AgentCapabilities,
    TrustRegistry,
    requires_passport
)

# 1. Create capabilities for your agent
caps = AgentCapabilities(
    can_browse_web=True,
    can_call_apis=True,
    can_execute_code=False,   # not allowed
    trust_level="standard",
    human_in_loop=True,
    max_actions_per_hour=100
)

# 2. Issue a passport
passport = AgentPassport.issue(
    agent_name="DataAnalysisAgent",
    agent_type="analyst",
    owner_org="Acme Corp",
    owner_email="admin@acme.com",
    capabilities=caps,
    model="claude-sonnet-4-5",
    version="2.1.0"
)

# 3. Protect your functions with passport checks
@requires_passport(capability="browse_web")
def search_web(query: str, passport: AgentPassport):
    # This function can only be called by agents
    # with a valid passport that has browse_web capability
    results = do_search(query)
    return results

# 4. Call protected function
results = search_web("GPU rental prices", passport=passport)

# 5. View the audit trail
for entry in passport.get_audit_log():
    print(f"{entry['timestamp']} | {entry['action']} | {entry['outcome']}")

# 6. Multi-agent trust chain
orchestrator = AgentPassport.issue(
    agent_name="OrchestratorAgent",
    agent_type="orchestrator",
    owner_org="Acme Corp",
    owner_email="admin@acme.com",
    capabilities=AgentCapabilities.elevated(),
    model="claude-opus-4-6"
)

# Spawn a child agent — only works if orchestrator has can_spawn_agents=True
child_agent = AgentPassport.issue(
    agent_name="SubAgent-1",
    agent_type="worker",
    owner_org="Acme Corp",
    owner_email="admin@acme.com",
    capabilities=AgentCapabilities.standard(),
    model="claude-sonnet-4-5",
    parent_passport=orchestrator   # establishes trust chain
)

# 7. Organisation-wide trust registry
registry = TrustRegistry(org_name="Acme Corp")
registry.register_agent(orchestrator)
registry.register_agent(child_agent)

# Check trust
if registry.is_trusted(child_agent.agent_id):
    print("Agent is trusted")

# Get full audit report
report = registry.get_audit_report()
print(f"Total agents: {report['total_agents']}")
print(f"Active agents: {report['active_agents']}")
```

---

## Why Agent Passports Matter

The rise of agentic AI creates a new security challenge:

- **Who built this agent?** — No way to verify
- **What is it allowed to do?** — No standard capability model
- **What has it done?** — No audit trail
- **Can we stop it?** — No revocation mechanism
- **Which agents trust each other?** — No trust chain

ComputeID AgentID solves all of these with cryptographic guarantees.

---

## Free Tier

| Feature | Free | Growth ($499/mo) | Enterprise ($1,999/mo) |
|---------|------|------------------|------------------------|
| Device passports | 3 devices | 50 devices | Unlimited |
| Agent passports | 5 agents | 100 agents | Unlimited |
| Audit log retention | 7 days | 90 days | 1 year |
| Quantum-safe certs | ❌ | ✅ | ✅ |
| Custom CA | ❌ | ❌ | ✅ |
| API access | ✅ | ✅ | ✅ |

**Get started free at [compute-id.com](https://compute-id.com)**

---

## Regulatory Compliance

ComputeID helps you meet:

- **EU AI Act** — requires audit trails for high-risk AI systems
- **NIST AI RMF** — AI risk management framework
- **SOC2 Type II** — compute infrastructure audit logs
- **NSA CNSA 2.0** — post-quantum cryptography by 2030

---

## Contributing

ComputeID SDK is open source under the MIT license.

We welcome contributions — especially:
- Client libraries for other languages (Go, Rust, Java)
- Integration examples with popular AI frameworks
- Protocol specification improvements

```bash
git clone https://github.com/trustedaicompute-ops/computeid-sdk
cd computeid-sdk
pip install -e ".[dev]"
```

---

## Links

- **Website:** [compute-id.com](https://compute-id.com)
- **Dashboard:** [aicomputeid.com](https://aicomputeid.com)
- **GitHub:** [github.com/trustedaicompute-ops](https://github.com/trustedaicompute-ops)
- **Email:** hello@compute-id.com

---

## License

MIT License — free to use, modify and distribute.

Copyright 2026 ComputeID / TrustedAI Compute
