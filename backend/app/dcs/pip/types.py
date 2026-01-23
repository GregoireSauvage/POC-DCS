from dataclasses import dataclass
from typing import Literal, Any

Classification = Literal["PUBLIC","INTERNAL","PII","SENSITIVE"]

@dataclass(frozen=True)
class Subject:
    user_id: str
    tenant_id: str
    role: str
    username: str

@dataclass(frozen=True)
class Context:
    env: str
    channel: str
    purpose: str
    client_ip: str | None
    device_trust: float
    request_id: str

@dataclass(frozen=True)
class Resource:
    type: str
    id: str
    owner_id: str | None
    tenant_id: str
    labels: list[str]
    fields: dict[str, dict[str, Any]]  # field -> {classification, crypto?}

@dataclass(frozen=True)
class PolicyInput:
    subject: Subject
    action: str
    resource: Resource
    context: Context
