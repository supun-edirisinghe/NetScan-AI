from sqlalchemy import Column, String, Boolean, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.core.database import Base


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    target = Column(String(500), nullable=False)
    port_range = Column(String(100), default="1-1024")
    scan_type = Column(String(50), default="tcp")

    # Schedule settings
    schedule_type = Column(String(20), default="daily")   # daily, weekly, monthly
    schedule_hour = Column(Integer, default=2)             # 0-23
    schedule_minute = Column(Integer, default=0)           # 0-59
    schedule_day = Column(String(20), default="mon")       # mon,tue,wed,thu,fri,sat,sun

    # Status
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    total_runs = Column(Integer, default=0)

    # Owner
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", backref="scheduled_scans")