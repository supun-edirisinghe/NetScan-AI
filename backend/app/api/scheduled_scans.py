from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
from typing import Optional, List

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scheduled_scan import ScheduledScan
from app.services.scheduler_service import add_scan_job, remove_scan_job

router = APIRouter()


class ScheduledScanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    target: str
    port_range: str = "1-1024"
    scan_type: str = "tcp"
    schedule_type: str = "daily"
    schedule_hour: int = 2
    schedule_minute: int = 0
    schedule_day: str = "mon"


class ScheduledScanResponse(BaseModel):
    id: str
    name: str
    target: str
    port_range: str
    schedule_type: str
    schedule_hour: int
    schedule_minute: int
    schedule_day: str
    is_active: bool
    last_run: Optional[str]
    total_runs: int
    created_at: str

    class Config:
        from_attributes = True


@router.post("/", response_model=ScheduledScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    request: ScheduledScanCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scheduled = ScheduledScan(
        name=request.name,
        target=request.target,
        port_range=request.port_range,
        scan_type=request.scan_type,
        schedule_type=request.schedule_type,
        schedule_hour=request.schedule_hour,
        schedule_minute=request.schedule_minute,
        schedule_day=request.schedule_day,
        owner_id=current_user.id,
    )
    db.add(scheduled)
    await db.commit()
    await db.refresh(scheduled)
    add_scan_job(scheduled)
    return _to_response(scheduled)


@router.get("/", response_model=List[ScheduledScanResponse])
async def list_scheduled_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.owner_id == current_user.id)
    )
    scans = result.scalars().all()
    return [_to_response(s) for s in scans]


@router.delete("/{scheduled_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    scheduled_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scheduled_id,
            ScheduledScan.owner_id == current_user.id,
        )
    )
    scheduled = result.scalar_one_or_none()
    if not scheduled:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    remove_scan_job(scheduled_id)
    await db.delete(scheduled)
    await db.commit()


@router.patch("/{scheduled_id}/toggle", response_model=ScheduledScanResponse)
async def toggle_scheduled_scan(
    scheduled_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.id == scheduled_id,
            ScheduledScan.owner_id == current_user.id,
        )
    )
    scheduled = result.scalar_one_or_none()
    if not scheduled:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    scheduled.is_active = not scheduled.is_active
    if scheduled.is_active:
        add_scan_job(scheduled)
    else:
        remove_scan_job(scheduled_id)
    await db.commit()
    return _to_response(scheduled)


def _to_response(s: ScheduledScan) -> ScheduledScanResponse:
    return ScheduledScanResponse(
        id=str(s.id),
        name=s.name,
        target=s.target,
        port_range=s.port_range,
        schedule_type=s.schedule_type,
        schedule_hour=s.schedule_hour,
        schedule_minute=s.schedule_minute,
        schedule_day=s.schedule_day,
        is_active=s.is_active,
        last_run=s.last_run.isoformat() if s.last_run else None,
        total_runs=s.total_runs,
        created_at=s.created_at.isoformat() if s.created_at else "",
    )