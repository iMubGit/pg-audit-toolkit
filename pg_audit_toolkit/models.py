from pydantic import BaseModel
from typing import List
from enum import Enum
from datetime import datetime

class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Finding(BaseModel):
    issue: str
    risk: RiskLevel
    control: str
    description: str
    object: str = ""

class AuditReport(BaseModel):
    scan_time: str
    total_findings: int
    summary: dict
    findings: List[Finding]