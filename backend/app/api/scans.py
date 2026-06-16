from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import uuid
import logging

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus, RiskLevel
from app.services.scanner import run_full_scan
from app.services.ai_analyzer import analyze_scan_with_ml
from app.services.email_service import send_risk_alert
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


class ScanCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    target: str = Field(..., description="IP, CIDR range, or hostname")
    port_range: str = Field(default="1-1024")
    scan_type: str = Field(default="tcp")
    notes: Optional[str] = None


class ScanResponse(BaseModel):
    id: str
    name: str
    target: str
    status: str
    scan_type: str
    port_range: str
    total_hosts: int
    hosts_up: int
    total_open_ports: int
    high_risk_hosts: int
    risk_score: float
    risk_level: str
    ai_recommendations: list
    scan_results: dict
    port_distribution: dict
    created_at: str
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    notes: Optional[str]

    class Config:
        from_attributes = True


async def _execute_scan(scan_id: str, db: AsyncSession):
    """Background task: run scan, analyze with AI, update DB."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        return

    try:
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        await db.commit()

        # Run port scan
        raw_results = await run_full_scan(
            target=scan.target,
            port_range=scan.port_range,
            scan_type=scan.scan_type,
        )

        # AI analysis
        analyzed = analyze_scan_with_ml(raw_results)

        # Update scan record
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.duration_seconds = analyzed.get("scan_duration", 0)
        scan.total_hosts = analyzed.get("total_hosts", 0)
        scan.hosts_up = analyzed.get("hosts_up", 0)
        scan.total_open_ports = analyzed.get("total_open_ports", 0)
        scan.high_risk_hosts = analyzed.get("high_risk_hosts", 0)
        scan.risk_score = analyzed.get("overall_risk_score", 0.0)
        scan.ai_recommendations = analyzed.get("ai_recommendations", [])
        scan.port_distribution = analyzed.get("port_distribution", {})

        # Map risk level
        level_str = analyzed.get("overall_risk_level", "low")
        scan.risk_level = RiskLevel(level_str)

        # Store full results
        scan.scan_results = {
            "hosts": analyzed.get("hosts", []),
            "scanned_at": analyzed.get("scanned_at"),
        }

        # Send email alert for high/critical risk scans
        if (
            settings.ENABLE_EMAIL_ALERTS
            and level_str in ("high", "critical")
            and settings.SMTP_USER
        ):
            try:
                await send_risk_alert(
                    scan_name=scan.name,
                    target=scan.target,
                    risk_level=level_str,
                    risk_score=analyzed.get("overall_risk_score", 0),
                    high_risk_hosts=analyzed.get("high_risk_hosts", 0),
                    recommendations=analyzed.get("ai_recommendations", []),
                    to_emails=[settings.SMTP_USER],
                )
                logger.info(f"Risk alert email sent for scan {scan_id}")
            except Exception as email_error:
                logger.error(f"Email alert failed: {email_error}")
                # Email failure should not affect scan completion

        await db.commit()
        logger.info(f"Scan {scan_id} completed. Risk: {level_str} ({scan.risk_score})")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        await db.commit()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create and start a new port scan."""
    scan = Scan(
        name=request.name,
        target=request.target,
        port_range=request.port_range,
        scan_type=request.scan_type,
        notes=request.notes,
        owner_id=current_user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(_execute_scan, str(scan.id), db)

    return _to_response(scan)


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scans for current user."""
    result = await db.execute(
        select(Scan)
        .where(Scan.owner_id == current_user.id)
        .order_by(desc(Scan.created_at))
        .offset(skip)
        .limit(limit)
    )
    scans = result.scalars().all()
    return [_to_response(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific scan by ID."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _to_response(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()


def _to_response(scan: Scan) -> ScanResponse:
    return ScanResponse(
        id=str(scan.id),
        name=scan.name,
        target=scan.target,
        status=scan.status.value if scan.status else "pending",
        scan_type=scan.scan_type or "tcp",
        port_range=scan.port_range or "1-1024",
        total_hosts=scan.total_hosts or 0,
        hosts_up=scan.hosts_up or 0,
        total_open_ports=scan.total_open_ports or 0,
        high_risk_hosts=scan.high_risk_hosts or 0,
        risk_score=scan.risk_score or 0.0,
        risk_level=scan.risk_level.value if scan.risk_level else "low",
        ai_recommendations=scan.ai_recommendations or [],
        scan_results=scan.scan_results or {},
        port_distribution=scan.port_distribution or {},
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        duration_seconds=scan.duration_seconds,
        notes=scan.notes,
    )