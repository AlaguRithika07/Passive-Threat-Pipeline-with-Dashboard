from pydantic import BaseModel, Field
from typing import Dict, Any, Optional
from datetime import datetime

class FlowIdentifier(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

class AlertSchema(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    alert_id: str
    flow_id: FlowIdentifier
    threat_class: str
    confidence_score: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: Dict[str, Any]  # Dictionary values