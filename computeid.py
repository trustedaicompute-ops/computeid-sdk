"""
ComputeID SDK v1.1.0
====================
Cryptographic identity for AI compute infrastructure and agentic AI systems.

Every GPU needs a passport. Every AI agent needs an identity.

Products:
  DevicePassport  — Cryptographic passports for GPUs and servers
  AgentPassport   — Cryptographic passports for AI agents
  PassportOffice  — Organisation-wide identity management

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

    Every agentic AI system should hold a valid AgentPassport that:
    - Identifies who built the agent and who owns it
    - Specifies what the agent is allowed to do
    - Creates an immutable audit trail of every action
    - Can be revoked instantly if the agent misbehaves
    - Establishes a chain of trust between parent and child agents

    Example:
        passport = AgentPassport.issue(
            agent_name="ResearchAgent",
            agent_type="researcher",
            owner_org="Acme Corp",
            owner_email="admin@acme.com",
            capabilities=AgentCapabilities.standard(),
            model="claude-sonnet-4-5"
        )

        if passport.is_trusted():
            run_agent(passport=passport)

        passport.log_action("web_search", {"query": "GPU prices"})
        passport.revoke(reason="Unexpected behaviour")
    """

    def __init__(self, data):
        self.agent_id        = data.get("agent_id", str(uuid.uuid4()))
        self.agent_name      = data.get("agent_name")
        self.agent_type      = data.get("agent_type")
        self.owner_org       = data.get("owner_org")
        self.owner_email     = data.get("owner_email")
        self.model           = data.get("model")
        self.version         = data.get("version", "1.0.0")
        self.status          = data.get("status", "active")
        self.trust_level     = data.get("trust_level", "restricted")
        self.parent_agent_id = data.get("parent_agent_id")
        self.issued_at       = data.get("issued_at", datetime.utcnow().isoformat())
        self.expires_at      = data.get("expires_at")
        self.revoked_at      = data.get("revoked_at")
        self.revoke_reason   = data.get("revoke_reason")
        caps = data.get("capabilities", {})
        self.capabilities    = AgentCapabilities(**caps) if isinstance(caps, dict) else caps
        self._audit_log      = data.get("audit_log", [])
        self._fingerprint    = hashlib.sha256(
            f"{self.agent_id}{self.agent_name}{self.owner_org}{self.issued_at}".encode()
        ).hexdigest()[:16]

    @classmethod
    def issue(cls, agent_name, agent_type, owner_org, owner_email,
              capabilities, model="unknown", version="1.0.0",
              parent_passport=None, expires_in_hours=24,
              api_key=None, api_url=COMPUTEID_API):
        """Issue a new passport for an AI agent."""
        if parent_passport:
            if not parent_passport.capabilities.can_spawn_agents:
                raise TrustError("Parent agent cannot spawn child agents")
            if not parent_passport.is_trusted():
                raise TrustError("Parent agent is not trusted")
        now = datetime.utcnow()
        data = {
            "agent_id":        str(uuid.uuid4()),
            "agent_name":      agent_name,
            "agent_type":      agent_type,
            "owner_org":       owner_org,
            "owner_email":     owner_email,
            "model":           model,
            "version":         version,
            "status":          "active",
            "trust_level":     capabilities.trust_level,
            "parent_agent_id": parent_passport.agent_id if parent_passport else None,
            "issued_at":       now.isoformat(),
            "expires_at":      (now + timedelta(hours=expires_in_hours)).isoformat(),
            "capabilities":    capabilities.to_dict(),
            "audit_log":       [],
        }
        passport = cls(data)
        passport.log_action("passport_issued", {"agent_name": agent_name}, "success")
        return passport

    def log_action(self, action, details=None, outcome="success"):
        """Log an action to the immutable audit trail."""
        entry = {
            "log_id":    str(uuid.uuid4()),
            "agent_id":  self.agent_id,
            "action":    action,
            "details":   details or {},
            "outcome":   outcome,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self._audit_log.append(entry)
        return entry

    def verify_action(self, action):
        """Check if this agent is allowed to perform a specific action."""
        if not self.is_trusted():
            self.log_action(action, outcome="blocked", details={"reason": "passport_invalid"})
            return False
        action_map = {
            "browse_web":      self.capabilities.can_browse_web,
            "execute_code":    self.capabilities.can_execute_code,
            "access_files":    self.capabilities.can_access_files,
            "call_api":        self.capabilities.can_call_apis,
            "spawn_agent":     self.capabilities.can_spawn_agents,
            "access_database": self.capabilities.can_access_database,
            "send_email":      self.capabilities.can_send_email,
        }
        allowed = action_map.get(action, False)
        if not allowed:
            self.log_action(action, outcome="blocked", details={"reason": "capability_not_granted"})
        return allowed

    def revoke(self, reason="Manual revocation"):
        """Immediately revoke this agent passport."""
        self.status        = "revoked"
        self.revoked_at    = datetime.utcnow().isoformat()
        self.revoke_reason = reason
        self.log_action("passport_revoked", {"reason": reason}, "success")

    def is_trusted(self):
        """Returns True if the passport is valid, active and not expired."""
        if self.status != "active":
            return False
        if self.expires_at:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", ""))
            if datetime.utcnow() > expires:
                self.status = "expired"
                return False
        return True

    def get_audit_log(self):
        """Returns the full immutable audit log."""
        return self._audit_log.copy()

    def get_summary(self):
        """Returns a summary of the passport."""
        return {
            "agent_id":       self.agent_id,
            "agent_name":     self.agent_name,
            "owner_org":      self.owner_org,
            "model":          self.model,
            "status":         self.status,
            "trust_level":    self.trust_level,
            "issued_at":      self.issued_at,
            "expires_at":     self.expires_at,
            "actions_logged": len(self._audit_log),
            "fingerprint":    self._fingerprint,
        }

    def export(self):
        """Export passport to JSON string for storage."""
        data = self.get_summary()
        data["capabilities"] = self.capabilities.to_dict()
        data["audit_log"]    = self._audit_log
        return json.dumps(data, indent=2)

    @classmethod
    def load(cls, json_str):
        """Load a passport from a previously exported JSON string."""
        return cls(json.loads(json_str))

    def __repr__(self):
        return f"<AgentPassport {self.agent_id[:8]}... | {self.agent_name} | {self.trust_level} | {self.status}>"


class DevicePassport:
    """
    A cryptographic passport for a GPU, server or compute device.

    Every device that participates in a trusted compute network
    must hold a valid DevicePassport issued by ComputeID.

    Example:
        passport = DevicePassport.register(
            name="NVIDIA A100",
            device_type="GPU",
            ip_address="192.168.1.10",
            api_key="your-api-key"
        )
        print(passport.device_code)  # GPU-001
        print(passport.is_valid())   # True
    """

    def __init__(self, data):
        self.device_id   = data.get("device_id")
        self.device_code = data.get("device_code")
        self.name        = data.get("name")
        self.device_type = data.get("type")
        self.ip_address  = data.get("ip_address")
        self.status      = data.get("status", "pending")
        self.issued_at   = data.get("issued_at", datetime.utcnow().isoformat())

    @classmethod
    def register(cls, name, device_type, ip_address,
                 api_key=None, api_url=COMPUTEID_API):
        """Register a device and receive a cryptographic passport."""
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        try:
            res = requests.post(
                f"{api_url}/api/devices/register",
                json={"name": name, "type": device_type, "ip_address": ip_address},
                headers=headers, timeout=30
            )
            data = res.json()
            if not res.ok:
                raise RegistrationError(data.get("error", "Registration failed"))
            return cls(data)
        except requests.RequestException as e:
            raise RegistrationError(f"Network error: {e}")

    @classmethod
    def authenticate(cls, device_code, api_url=COMPUTEID_API):
        """Authenticate a device and receive a JWT access token."""
        try:
            res = requests.post(
                f"{api_url}/api/devices/authenticate",
                json={"device_code": device_code},
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            data = res.json()
            if not res.ok:
                raise AuthenticationError(data.get("error", "Authentication failed"))
            return data.get("access_token")
        except requests.RequestException as e:
            raise AuthenticationError(f"Network error: {e}")

    def is_valid(self):
        """Returns True if the passport is active."""
        return self.status == "active"

    def is_pending(self):
        """Returns True if awaiting admin approval."""
        return self.status == "pending"

    def __repr__(self):
        return f"<DevicePassport {self.device_code} | {self.name} | {self.status}>"


class PassportOffice:
    """
    Organisation-wide passport management for all devices and agents.

    The PassportOffice tracks every DevicePassport and AgentPassport
    in your organisation, verifies trust, and generates compliance reports.

    Example:
        office = PassportOffice(org_name="Acme Corp")

        office.register_device(gpu_passport)
        office.register_agent(agent_passport)

        if office.is_trusted(agent_id):
            allow_access()

        report = office.get_audit_report()
    """

    def __init__(self, org_name, api_key=None):
        self.org_name  = org_name
        self.api_key   = api_key
        self._agents   = {}
        self._devices  = {}
        self._created_at = datetime.utcnow().isoformat()

    def register_device(self, passport):
        """Register a device passport with the office."""
        if passport.device_id:
            self._devices[passport.device_id] = passport

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

    def get_active_devices(self):
        """Get all active devices."""
        return [p for p in self._devices.values() if p.is_valid()]

    def get_audit_report(self):
        """Generate a full compliance audit report."""
        return {
            "org_name":      self.org_name,
            "generated_at":  datetime.utcnow().isoformat(),
            "total_agents":  len(self._agents),
            "active_agents": len(self.get_active_agents()),
            "total_devices": len(self._devices),
            "active_devices":len(self.get_active_devices()),
            "agents": [
                {**p.get_summary(), "audit_log": p.get_audit_log()}
                for p in self._agents.values()
            ]
        }

    def __repr__(self):
        return f"<PassportOffice {self.org_name} | {len(self._agents)} agents | {len(self._devices)} devices>"


# Keep TrustRegistry as alias for backwards compatibility
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
    Quickstart — issue a passport for an AI agent in one line.

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


def register_gpu(name, ip_address, api_key=None):
    """
    Quickstart — register a GPU and get a passport in one line.

    Example:
        from computeid import register_gpu

        passport = register_gpu(
            name="NVIDIA A100",
            ip_address="192.168.1.10",
            api_key="your-api-key"
        )
        print(passport.device_code)  # GPU-001
    """
    return DevicePassport.register(
        name=name, device_type="GPU",
        ip_address=ip_address, api_key=api_key
    )
