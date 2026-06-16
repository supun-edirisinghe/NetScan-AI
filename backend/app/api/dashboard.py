from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.scan import Scan, ScanStatus, RiskLevel

router = APIRouter()


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get aggregated dashboard statistics."""
    base = select(Scan).where(Scan.owner_id == current_user.id)

    # Total scans
    total_result = await db.execute(
        select(func.count()).select_from(
            select(Scan).where(Scan.owner_id == current_user.id).subquery()
        )
    )
    total_scans = total_result.scalar() or 0

    # Completed scans
    completed_result = await db.execute(
        select(func.count()).select_from(
            select(Scan).where(
                Scan.owner_id == current_user.id,
                Scan.status == ScanStatus.COMPLETED
            ).subquery()
        )
    )
    completed_scans = completed_result.scalar() or 0

    # Aggregate totals from completed scans
    agg_result = await db.execute(
        select(
            func.sum(Scan.total_hosts),
            func.sum(Scan.hosts_up),
            func.sum(Scan.total_open_ports),
            func.sum(Scan.high_risk_hosts),
            func.avg(Scan.risk_score),
        ).where(
            Scan.owner_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        )
    )
    agg = agg_result.first()

    # Risk level distribution
    risk_result = await db.execute(
        select(Scan.risk_level, func.count(Scan.id)).where(
            Scan.owner_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        ).group_by(Scan.risk_level)
    )
    risk_dist = {row[0].value if row[0] else "unknown": row[1] for row in risk_result}

    # Recent scans
    recent_result = await db.execute(
        select(Scan).where(
            Scan.owner_id == current_user.id
        ).order_by(desc(Scan.created_at)).limit(5)
    )
    recent_scans = recent_result.scalars().all()

    # Scan activity last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    activity_result = await db.execute(
        select(
            func.date_trunc('day', Scan.created_at).label("day"),
            func.count(Scan.id).label("count")
        ).where(
            Scan.owner_id == current_user.id,
            Scan.created_at >= thirty_days_ago,
        ).group_by("day").order_by("day")
    )
    activity = [
        {"date": row.day.strftime("%Y-%m-%d"), "count": row.count}
        for row in activity_result
    ]

    # Top open ports across all scans
    top_ports_data = {}
    port_result = await db.execute(
        select(Scan.port_distribution).where(
            Scan.owner_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        )
    )
    for row in port_result:
        if row[0]:
            for port, count in row[0].items():
                top_ports_data[port] = top_ports_data.get(port, 0) + count

    top_ports = sorted(top_ports_data.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "total_hosts_scanned": int(agg[0] or 0),
        "total_hosts_up": int(agg[1] or 0),
        "total_open_ports": int(agg[2] or 0),
        "total_high_risk_hosts": int(agg[3] or 0),
        "avg_risk_score": round(float(agg[4] or 0), 1),
        "risk_distribution": risk_dist,
        "recent_scans": [
            {
                "id": str(s.id),
                "name": s.name,
                "target": s.target,
                "status": s.status.value if s.status else "pending",
                "risk_level": s.risk_level.value if s.risk_level else "low",
                "risk_score": s.risk_score or 0,
                "created_at": s.created_at.isoformat() if s.created_at else "",
            }
            for s in recent_scans
        ],
        "scan_activity": activity,
        "top_open_ports": [
            {"port": p, "count": c} for p, c in top_ports
        ],
    }
