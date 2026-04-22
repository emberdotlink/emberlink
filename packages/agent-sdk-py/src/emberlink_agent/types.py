from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AgentConfig:
    db_path: str
    persona_id: str
    binary_path: str = "emberlink-agent"
    label: str | None = None


@dataclass
class WhoAmIResult:
    persona_id: str
    label: str | None = None


@dataclass
class GrantInfo:
    grant_id: str
    issuer_id: str
    capability: str
    status: str
    expires_at: int | None = None


@dataclass
class RequestGrantResult:
    request_id: str
    status: str


@dataclass
class GrantStatusResult:
    grant_id: str
    status: str
    issuer_id: str | None = None
    capability: str | None = None
    expires_at: int | None = None


@dataclass
class CredentialValue:
    value: str
    scope: str
    grant_id: str


@dataclass
class UseCredentialResult:
    status: str
    credential: CredentialValue


@dataclass
class GrantRevokedNotification:
    """Server-initiated notification pushed by the daemon when a grant is revoked."""

    grant_id: str
    persona_id: str
