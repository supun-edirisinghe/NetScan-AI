from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus

router = APIRouter()


@router.get("/{scan_id}/pdf")
async def download_pdf_report(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate and download PDF report for a scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.owner_id == current_user.id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan not completed yet")

    from app.services.report_generator import generate_scan_report

    scan_data = {
        "name": scan.name,
        "target": scan.target,
        "status": scan.status.value,
        "total_hosts": scan.total_hosts,
        "hosts_up": scan.hosts_up,
        "total_open_ports": scan.total_open_ports,
        "high_risk_hosts": scan.high_risk_hosts,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level.value if scan.risk_level else "low",
        "ai_recommendations": scan.ai_recommendations or [],
        "port_distribution": scan.port_distribution or {},
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "duration_seconds": scan.duration_seconds or 0,
    }

    try:
        pdf_bytes = generate_scan_report(scan_data)
        filename = f"netscan_report_{scan.name.replace(' ', '_')}_{scan_id[:8]}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
