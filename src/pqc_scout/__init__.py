"""PQC-Scout — post-quantum cryptography migration scanner.

Cryptographic inventory -> Q-Day exposure scoring -> NIST-aligned migration
roadmap. See https://github.com/matrixcrstudio/pqc-scout.
"""

__version__ = "0.1.0"

from .horizon import (
    QDAY_HORIZON,
    apply_sector_floor,
    exposure_tier,
    migration_target,
    priority_score,
    qday_nominal,
    qday_optimistic,
    sector_retention_years,
)
from .models import AssessmentReport, CryptographicSurface, SURFACE_CATEGORIES
from .pipeline import run_assessment
from .tls import scan_tls_cert, scan_tls_multi

__all__ = [
    "QDAY_HORIZON",
    "AssessmentReport",
    "CryptographicSurface",
    "SURFACE_CATEGORIES",
    "apply_sector_floor",
    "exposure_tier",
    "migration_target",
    "priority_score",
    "qday_nominal",
    "qday_optimistic",
    "run_assessment",
    "scan_tls_cert",
    "scan_tls_multi",
    "sector_retention_years",
    "__version__",
]
