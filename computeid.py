"""
ComputeID SDK v1.0.0
Cryptographic identity for AI compute and agentic AI systems.
https://compute-id.com
"""

import hashlib
import json
import uuid
import requests
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

COMPUTEID_API = "https://api.aicomputeid.com"
SDK_VERSION   = "1.0.0"

class ComputeIDError(Exception): pass
class AuthenticationError(ComputeIDError): pass
class RegistrationError(ComputeIDError): pass
class RevocationError(ComputeIDError): pass
class TrustError(ComputeIDError): pass

class AgentCapabilities:
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
        return cls(trust_level="restricted", human_in_loop=True, max_actions_per_hour=50)

    @classmethod
    def standard(cls):
        return cls(can_browse_web=True, can_call_apis=True, can_access_files=True,
                   trust_level="standard", human_in_loop=True, max_actions_per_hour=200)

    @classmethod
    def elevated(cls):
        return cls(can_browse_web=True, can_execute_code=True, can_call_apis=True,
                   can_access_files=True, can_spawn_agents=True,
                   trust_level="elevated", human_in_loop=False, max_actions_per_hour=1000)

    @classmethod
    def autonomous(cls):
        return cls(can_browse_web=True, can_execute_code=True, can_call_apis=True,
                   can_access_files=True, can_spawn_agents=True,
                   can_access_database=True, can_send_email=True,
                   trust_level="autonomous", human_in_loop=False, max_actions_per_hour=10000)


class AgentPassport:
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
        self.status        = "revoked"
        self.revoked_at    = datetime.utcnow().isoformat()
        self.revoke_reason = reason
        self.log_action("passport_revoked", {"reason": reason}, "success")

    def is_trusted(self):
        if self.status != "active":
            return False
        if self.expires_at:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", ""))
            if datetime.utcnow() > expires:
                self.status = "expired"
                return False
        return True

    def get_audit_log(self):
        return self._audit_log.copy()

    def get_summary(self):
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
        data = self.get_summary()
        data["capabilities"] = self.capabilities.to_dict()
        data["audit_log"]    = self._audit_log
        return json.dumps(data, indent=2)

    @classmethod
    def load(cls, json_str):
        return cls(json.loads(json_str))

    def __repr__(self):
        return f"<AgentPassport {self.agent_id[:8]}... | {self.agent_name} | {self.trust_level} | {self.status}>"


class DevicePassport:
    def __init__(self, data):
        self.device_id   = data.get("device_id")
        self.device_code = data.get("device_code")
        self.name        = data.get("name")
        self.device_type = data.get("type")
        self.ip_address  = data.get("ip_address")
        self.status      = data.get("status", "pending")
        self.issued_at   = data.get("issued_at", datetime.utcnow().isoformat())

    @classmethod
    def register(cls, name, device_type, ip_address, api_key=None, api_url=COMPUTEID_API):
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["X-API-Key"] = api_key
        try:
            res = requests.post(f"{api_url}/api/devices/register",
                                json={"name": name, "type": device_type, "ip_address": ip_address},
                                headers=headers, timeout=30)
            data = res.json()
            if not res.ok:
                raise RegistrationError(data.get("error", "Registration failed"))
            return cls(data)
        except requests.RequestException as e:
            raise RegistrationError(f"Network error: {e}")

    @classmethod
    def authenticate(cls, device_code, api_url=COMPUTEID_API):
        try:
            res = requests.post(f"{api_url}/api/devices/authenticate",
                                json={"device_code": device_code},
                                headers={"Content-Type": "application/json"}, timeout=30)
            data = res.json()
            if not res.ok:
                raise AuthenticationError(data.get("error", "Authentication failed"))
            return data.get("access_token")
        except requests.RequestException as e:
            raise AuthenticationError(f"Network error: {e}")

    def is_valid(self):
        return self.status == "active"

    def __repr__(self):
        return f"<DevicePassport {self.device_code} | {self.name} | {self.status}>"


class TrustRegistry:
    def __init__(self, org_name, api_key=None):
        self.org_name  = org_name
        self.api_key   = api_key
        self._agents   = {}
        self._devices  = {}

    def register_agent(self, passport):
        self._agents[passport.agent_id] = passport

    def register_device(self, passport):
        if passport.device_id:
            self._devices[passport.device_id] = passport

    def is_trusted(self, agent_id):
        passport = self._agents.get(agent_id)
        return passport.is_trusted() if passport else False

    def revoke_agent(self, agent_id, reason="Revoked by registry"):
        passport = self._agents.get(agent_id)
        if passport:
            passport.revoke(reason)
            return True
        return False

    def get_active_agents(self):
        return [p for p in self._agents.values() if p.is_trusted()]

    def get_audit_report(self):
        return {
            "org_name":      self.org_name,
            "generated_at":  datetime.utcnow().isoformat(),
            "total_agents":  len(self._agents),
            "active_agents": len(self.get_active_agents()),
            "total_devices": len(self._devices),
            "agents": [{**p.get_summary(), "audit_log": p.get_audit_log()}
                       for p in self._agents.values()]
        }

    def __repr__(self):
        return f"<TrustRegistry {self.org_name} | {len(self._agents)} agents>"


def requires_passport(capability=None):
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
    return DevicePassport.register(name=name, device_type="GPU",
                                   ip_address=ip_address, api_key=api_key)
