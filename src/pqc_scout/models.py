"""Data models for PQC-Scout assessments."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, UTC
from typing import Any, Dict, List

from pydantic import BaseModel, Field


class CryptographicSurface(BaseModel):
    """A single discovered cryptographic surface in the target's stack."""

    surface_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    category: str = ""             # TLS_CERTIFICATES, CODE_SIGNING, ...
    algorithm: str = ""            # RSA-2048, ECDSA-P256, ML-KEM-768, ...
    location: str = ""             # service name, domain, system
    data_retention_yrs: int = 10   # years the data must remain confidential
    exposure_tier: str = "MONITOR" # CRITICAL | HIGH | MONITOR | SAFE
    qday_horizon_yrs: int = 8
    migration_target: str = ""
    priority_score: float = 0.0    # 0-100 remediation priority


class AssessmentReport(BaseModel):
    """Full post-quantum exposure assessment for a single target."""

    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str = ""
    assessed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    stack_description: str = ""
    sector: str = ""
    surfaces: List[CryptographicSurface] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    monitor_count: int = 0
    safe_count: int = 0
    overall_tier: str = "MONITOR"
    executive_summary: str = ""
    roadmap: List[Dict[str, Any]] = Field(default_factory=list)
    report_digest: str = ""

    def compute_digest(self) -> str:
        """SHA3-256 integrity digest over the report's decision-bearing core."""
        core = f"{self.report_id}|{self.target}|{self.overall_tier}|{self.critical_count}"
        return hashlib.sha3_256(core.encode()).hexdigest()[:24]

    def recount(self) -> None:
        """Recompute tier counts and the overall tier from `surfaces`."""
        tiers = [s.exposure_tier for s in self.surfaces]
        self.critical_count = tiers.count("CRITICAL")
        self.high_count = tiers.count("HIGH")
        self.monitor_count = tiers.count("MONITOR")
        self.safe_count = tiers.count("SAFE")
        for tier in ("CRITICAL", "HIGH", "MONITOR"):
            if tiers.count(tier):
                self.overall_tier = tier
                return
        self.overall_tier = "SAFE"


#: Surface categories assessed per target.
SURFACE_CATEGORIES = [
    "TLS_CERTIFICATES",   # public TLS certs (server, client auth)
    "CODE_SIGNING",       # binary/package signing keys
    "STORAGE_ENCRYPTION", # at-rest encryption (databases, backups, file stores)
    "KEY_EXCHANGE",       # key agreement protocols (ECDH, DH)
    "FIRMWARE_INTEGRITY", # firmware signing + verification chains
    "API_AUTHENTICATION", # API key / JWT signing algorithms
    "VPN_TUNNELS",        # IKEv2/IPsec cipher suites
    "EMAIL_SIGNING",      # S/MIME, DKIM
    "PKI_HIERARCHY",      # internal CA chains, signing roots
    "HARDWARE_KEYS",      # HSM key material, TPM bindings
]
