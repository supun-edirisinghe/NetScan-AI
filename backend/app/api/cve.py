from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus
from app.services.cve_service import get_cves_for_port, enrich_scan_with_cves

router = APIRouter()


@router.get("/port/{port}")
async def get_port_cves(
    port: int,
    service: str = "unknown",
    current_user: User = Depends(get_current_user),
):
    """Get CVEs for a specific port and service."""
    cves = await get_cves_for_port(port, service)
    return {
        "port": port,
        "service": service,
        "cve_count": len(cves),
        "cves": cves,
    }


@router.get("/scan/{scan_id}")
async def get_scan_cves(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get enriched CVE data for all ports in a completed scan."""
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.owner_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    scan_data = {
        "hosts": scan.scan_results.get("hosts", []) if scan.scan_results else []
    }

    enriched = await enrich_scan_with_cves(scan_data)

    return {
        "scan_id": scan_id,
        "scan_name": scan.name,
        "hosts": enriched.get("hosts", []),
    }