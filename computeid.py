"""
ComputeID SDK v1.1.0
====================
Cryptographic identity for AI agents.

Products:
  AgentPassport   — Cryptographic passports for AI agents
  PassportOffice  — Organisation-wide agent identity management

Install:
  pip install computeid-sdk

Docs:   https://compute-id.com
GitHub: https://github.com/trustedaicompute-ops/computeid-sdk
"""

import hashlib
import json
import uuid
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

COMPUTEID_API = "https://api.aicomputeid.com"
SDK_VERSION   = "1.1.0"

class ComputeIDError(Exception): pass
class AuthenticationError(ComputeIDError): pass
class RegistrationError(ComputeIDError): pass
class RevocationError(ComputeIDError): pass
class TrustError(ComputeIDError): pass


class AgentCapabilities:
    """
    Defines what an AI agent is allowed to do.
    Embed this in every AgentPassport.

    Example:
        caps = AgentCapabilities.standard()
        caps = AgentCapabilities(can_browse_web=True, can_execute_code=False)
    """
    def __init__(self, can_browse_web=False, can_execute_code=False,
                 can_access_files=False, can_call_apis=True, can_spawn_agents=False,
                 can_access_database=False, can_send_email=False,
                 max_actions_per_hour=100, trust_level="restricted",
                 human_in_loop=True, allowed_domains=None, allowed_tools=None,
                 max_token_budget=None, custom_permissions=None, **kwargs):
        self.can_browse_web       = can_browse_web
        self.can_execute_code     = can_execute_code
        self.can_access_files     = can_access_files
        self.can_call_apis        = can_call_apis
        self.can_spawn_agents     = can_spawn_agents
        self.can_access_database  = can_access_database
        self.can_send_email       = can_send_email
        self.max_actions_per_hour = max_actions_per_hour
        self.trust_level          = trust_level
        self.human_in_loop        = human_in_loop
        self.allowed_domains      = allowed_domains or []
        self.allowed_tools        = allowed_tools or []
        self.max_token_budget     = max_token_budget
        self.custom_permissions   = custom_permissions or {}

    def to_dict(self):
        return self.__dict__

    @classmethod
    def restricted(cls):
        """Minimal permissions — read only, human oversight required"""
        return cls(trust_level="restricted", human_in_loop=True, max_actions_per_hour=50)

    @classmethod
    def standard(cls):
        """Standard permissions — web browsing, API calls, file read"""
        return cls(can_browse_web=True, can_call_apis=True, can_access_files=True,
                   trust_level="standard", human_in_loop=True, max_actions_per_hour=200)

    @classmethod
    def elevated(cls):
        """Elevated permissions — code execution, spawn child agents"""
        return cls(can_browse_web=True, can_execute_code=True, can_call_apis=True,
                   can_access_files=True, can_spawn_agents=True,
                   trust_level="elevated", human_in_loop=False, max_actions_per_hour=1000)

    @classmethod
    def autonomous(cls):
        """Full autonomy — use with extreme caution"""
        return cls(can_browse_web=True, can_execute_code=True, can_call_apis=True,
                   can_access_files=True, can_spawn_agents=True,
                   can_access_database=True, can_send_email=True,
                   trust_level="autonomous", human_in_loop=False, max_actions_per_hour=10000)


class AgentPassport:
    """
    A cryptographic passport for an AI agent.

    Every agent that acts autonomously must hold a valid AgentPassport
    issued by ComputeID. Passports carry the agent's identity, declared
    capability scope, and an audit trail of logged actions.

    Example (server-backed, recommended):
        import requests
        r = requests.post("https://api.aicomputeid.com/v1/agents/register", json={
            "name": "ResearchAgent",
            "organization": "Acme Corp",
            "capabilities": ["read", "web_browse", "api_call"]
        })
        passport_id = r.json()["passport_id"]

    Example (local prototype):
        passport = AgentPassport.issue(
            agent_name="ResearchAgent",
            agent_type="researcher",
            owner_org="Acme Corp",
            owner_email="admin@acme.com",
            capabilities=AgentCapabilities.standard(),
            model="claude-sonnet-4-5"
        )
        print(passport.agent_id)
        print(passport.is_trusted())  # True
    """

    TRUST_LEVELS = {"restricted": 1, "standard": 2, "elevated": 3, "autonomous": 4}

    def __init__(self, data):
        self.agent_id     = data.get("agent_id",    str(uuid.uuid4()))
        self.agent_name   = data.get("agent_name",  "Unknown Agent")
        self.agent_type   = data.get("agent_type",  "general")
        self.owner_org    = data.get("owner_org",   "Unknown")
        self.owner_email  = data.get("owner_email", "")
        self.model        = data.get("model",       "unknown")
        self.status       = data.get("status",      "active")
        self.trust_level  = data.get("trust_level", "restricted")
        self.capabilities = data.get("capabilities", AgentCapabilities().to_dict())
        self.issued_at    = data.get("issued_at",   datetime.utcnow().isoformat())
        self.expires_at   = data.get("expires_at",
                            (datetime.utcnow() + timedelta(days=365)).isoformat())
        self.revoked_at   = data.get("revoked_at")
        self.revoke_reason= data.get("revoke_reason")
        self._audit_log   = data.get("audit_log",   [])
        caps = self.capabilities
        if isinstance(caps, AgentCapabilities):
            caps = caps.to_dict()
        self._fingerprint = hashlib.sha256(
            json.dumps({
                "agent_id":    self.agent_id,
                "agent_name":  self.agent_name,
                "owner_org":   self.owner_org,
                "issued_at":   self.issued_at,
                "trust_level": self.trust_level,
            }, sort_keys=True).encode()
        ).hexdigest()[:16]

    @classmethod
    def issue(cls, agent_name, agent_type="general", owner_org="Unknown",
              owner_email="", capabilities=None, model="unknown",
              api_key=None, api_url=COMPUTEID_API):
        """Issue a new AgentPassport (local object — not server-backed)."""
        if capabilities is None:
            capabilities = AgentCapabilities.standard()
        trust = capabilities.trust_level if hasattr(capabilities, "trust_level") else "standard"
        caps_dict = capabilities.to_dict() if hasattr(capabilities, "to_dict") else capabilities
        now = datetime.utcnow()
        return cls({
            "agent_id":     str(uuid.uuid4()),
            "agent_name":   agent_name,
            "agent_type":   agent_type,
            "owner_org":    owner_org,
            "owner_email":  owner_email,
            "model":        model,
            "status":       "active",
            "trust_level":  trust,
            "capabilities": caps_dict,
            "issued_at":    now.isoformat(),
            "expires_at":   (now + timedelta(days=365)).isoformat(),
        })

    def is_trusted(self):
        """Returns True if the passport is active and not expired."""
        if self.status != "active":
            return False
        if datetime.utcnow().isoformat() > self.expires_at:
            self.status = "expired"
            return False
        return True

    def verify_action(self, action):
        """Check if the agent can perform a given action."""
        if not self.is_trusted():
            return False
        caps = self.capabilities
        if isinstance(caps, dict):
            action_map = {
                "browse_web":      caps.get("can_browse_web"),
                "execute_code":    caps.get("can_execute_code"),
                "access_files":    caps.get("can_access_files"),
                "call_apis":       caps.get("can_call_apis"),
                "spawn_agents":    caps.get("can_spawn_agents"),
                "access_database": caps.get("can_access_database"),
                "send_email":      caps.get("can_send_email"),
            }
            return action_map.get(action, False)
        return getattr(caps, f"can_{action}", False)

    def log_action(self, action, outcome="success", metadata=None):
        """Log an action to the in-memory audit trail."""
        self._audit_log.append({
            "action":     action,
            "outcome":    outcome,
            "timestamp":  datetime.utcnow().isoformat(),
            "metadata":   metadata or {},
        })

    def revoke(self, reason="Revoked"):
        """Revoke the passport immediately."""
        self.status       = "revoked"
        self.revoked_at   = datetime.utcnow().isoformat()
        self.revoke_reason= reason
        self.log_action("revoke", outcome="revoked", metadata={"reason": reason})

    def get_summary(self):
        return {
            "agent_id":    self.agent_id,
            "agent_name":  self.agent_name,
            "owner_org":   self.owner_org,
            "status":      self.status,
            "trust_level": self.trust_level,
            "model":       self.model,
            "issued_at":   self.issued_at,
            "expires_at":  self.expires_at,
            "fingerprint": self._fingerprint,
        }

    def get_audit_log(self):
        return self._audit_log.copy()

    def to_dict(self):
        caps = self.capabilities
        if hasattr(caps, "to_dict"):
            caps = caps.to_dict()
        d = self.get_summary()
        d.update({
            "agent_type":    self.agent_type,
            "owner_email":   self.owner_email,
            "capabilities":  caps,
            "revoked_at":    self.revoked_at,
            "revoke_reason": self.revoke_reason,
            "audit_log":     self._audit_log,
        })
        return d

    def __repr__(self):
        return f"<AgentPassport {self.agent_id[:8]}... | {self.agent_name} | {self.trust_level} | {self.status}>"


class PassportOffice:
    """
    Organisation-wide passport management for AI agents.

    The PassportOffice tracks every AgentPassport in your organisation,
    verifies trust, and generates compliance reports.

    Example:
        office = PassportOffice(org_name="Acme Corp")
        office.register_agent(agent_passport)

        if office.is_trusted(agent_id):
            allow_access()

        report = office.get_audit_report()
    """

    def __init__(self, org_name, api_key=None):
        self.org_name    = org_name
        self.api_key     = api_key
        self._agents     = {}
        self._created_at = datetime.utcnow().isoformat()

    def register_agent(self, passport):
        """Register an agent passport with the office."""
        self._agents[passport.agent_id] = passport

    def is_trusted(self, agent_id):
        """Check if an agent is currently trusted."""
        passport = self._agents.get(agent_id)
        return passport.is_trusted() if passport else False

    def revoke_agent(self, agent_id, reason="Revoked by PassportOffice"):
        """Revoke an agent passport by ID."""
        passport = self._agents.get(agent_id)
        if passport:
            passport.revoke(reason)
            return True
        return False

    def get_active_agents(self):
        """Get all currently trusted and active agents."""
        return [p for p in self._agents.values() if p.is_trusted()]

    def get_audit_report(self):
        """Generate a full compliance audit report."""
        return {
            "org_name":      self.org_name,
            "generated_at":  datetime.utcnow().isoformat(),
            "total_agents":  len(self._agents),
            "active_agents": len(self.get_active_agents()),
            "agents": [
                {**p.get_summary(), "audit_log": p.get_audit_log()}
                for p in self._agents.values()
            ]
        }

    def __repr__(self):
        return f"<PassportOffice {self.org_name} | {len(self._agents)} agents>"


TrustRegistry = PassportOffice


def requires_passport(capability=None):
    """
    Decorator to protect functions that require a trusted AgentPassport.

    Example:
        @requires_passport(capability="browse_web")
        def search_web(query: str, passport: AgentPassport):
            return do_search(query)
    """
    def decorator(func):
        def wrapper(*args, passport=None, **kwargs):
            if passport is None:
                raise AuthenticationError(f"{func.__name__} requires an AgentPassport")
            if not passport.is_trusted():
                raise AuthenticationError(f"Passport for {passport.agent_name} is not trusted")
            if capability and not passport.verify_action(capability):
                raise TrustError(f"Agent lacks {capability} capability")
            passport.log_action(func.__name__, outcome="success")
            return func(*args, passport=passport, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator


def issue_agent_passport(agent_name, owner_org, owner_email,
                          trust_level="standard", model="unknown", api_key=None):
    """
    Quickstart — issue a local AgentPassport in one line.

    For server-backed passports (recommended for production), use the REST API:
      POST https://api.aicomputeid.com/v1/agents/register

    Example:
        from computeid import issue_agent_passport

        passport = issue_agent_passport(
            agent_name="MyAgent",
            owner_org="Acme Corp",
            owner_email="admin@acme.com",
            trust_level="standard",
            model="claude-sonnet-4-5"
        )
    """
    caps_map = {
        "restricted": AgentCapabilities.restricted(),
        "standard":   AgentCapabilities.standard(),
        "elevated":   AgentCapabilities.elevated(),
        "autonomous": AgentCapabilities.autonomous(),
    }
    return AgentPassport.issue(
        agent_name=agent_name, agent_type="general",
        owner_org=owner_org, owner_email=owner_email,
        capabilities=caps_map.get(trust_level, AgentCapabilities.standard()),
        model=model, api_key=api_key
    )
