from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class AccountTarget:
    account_id: str
    account_name: str
    role_arn: str | None = None
    regions: tuple[str, ...] = field(default_factory=tuple)
    external_id: str | None = None
    role_session_name: str = "CSAGEComplianceAudit"
    duration_seconds: int = 3600


@dataclass
class FindingData:
    module: str
    rule_id: str
    account_id: str
    account_name: str
    region: str
    service: str
    resource_id: str
    resource_type: str
    compliant: bool
    title: str
    details: str = ""
    severity: str = "MEDIUM"
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class InventoryData:
    account_id: str
    account_name: str
    region: str
    service: str
    resource_type: str
    resource_id: str
    resource_arn: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
