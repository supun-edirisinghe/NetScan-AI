from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey, Text, Float, JSON, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
import enum

from app.core.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    target = Column(String(500), nullable=False)  # IP, CIDR, hostname
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    scan_type = Column(String(50), default="tcp")  # tcp, udp, syn
    port_range = Column(String(100), default="1-1024")
    
    # Results
    total_hosts = Column(Integer, default=0)
    hosts_up = Column(Integer, default=0)
    total_open_ports = Column(Integer, default=0)
    high_risk_hosts = Column(Integer, default=0)
    
    # AI Analysis
    risk_score = Column(Float, default=0.0)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.LOW)
    ai_recommendations = Column(JSON, default=list)
    
    # Raw data
    scan_results = Column(JSON, default=dict)  # Full scan data per host
    port_distribution = Column(JSON, default=dict)  # {port: count}
    
    # Metadata
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    owner = relationship("User", back_populates="scans")
