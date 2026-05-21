from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class AgentConfig:
    db_path: str
    persona_id: str
    binary_path: str = "emberlink-agent"
    label: str | None = None
    daemon_socket: str | None = None


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
    status: str
    grant_id: str | None = None
    request_id: str | None = None
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


# Budget axis values matching the Rust BudgetAxis enum wire form.
BudgetAxis = Literal["tokens", "cents", "requests", "wall_clock_secs"]


@dataclass
class BudgetWarningNotification:
    """Server-initiated notification pushed when a Statement's budget crosses a warning threshold (80%, 95%)."""

    grant_id: str
    statement_sid: str
    axis: str
    used: float
    budget: float
    percent: float
    threshold_band: Literal["warning"]


@dataclass
class BudgetExhaustedNotification:
    """Server-initiated notification pushed when a Statement's budget is fully exhausted (100%)."""

    grant_id: str
    statement_sid: str
    axis: str
    used: float
    budget: float
    percent: float
    threshold_band: Literal["exhausted"]
