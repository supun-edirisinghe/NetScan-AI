"""
Scheduler Service
Handles automatic scheduled port scans using APScheduler.
"""
import logging
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.core.database import AsyncSessionLocal
from app.models.scheduled_scan import ScheduledScan
from app.models.scan import Scan, ScanStatus, RiskLevel
from app.models.user import User
from app.services.scanner import run_full_scan
from app.services.ai_analyzer import analyze_scan_with_ml

logger = logging.getLogger(__name__)

# Global scheduler instance
scheduler = AsyncIOScheduler()


async def run_scheduled_scan(scheduled_scan_id: str):
    """Execute a scheduled scan automatically."""
    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(
                select(ScheduledScan).where(
                    ScheduledScan.id == scheduled_scan_id
                )
            )
            scheduled = result.scalar_one_or_none()
            if not scheduled or not scheduled.is_active:
                return

            logger.info(f"Running scheduled scan: {scheduled.name}")

            # Create new scan record
            scan_name = f"{scheduled.name} (Auto {datetime.now().strftime('%Y-%m-%d')})"
            scan = Scan(
                name=scan_name,
                target=scheduled.target,
                port_range=scheduled.port_range,
                scan_type=scheduled.scan_type,
                status=ScanStatus.RUNNING,
                started_at=datetime.utcnow(),
                owner_id=scheduled.owner_id,
                notes=f"Auto scan: {scheduled.schedule_type}",
            )
            db.add(scan)
            await db.flush()

            # Run port scan
            raw_results = await run_full_scan(
                target=scheduled.target,
                port_range=scheduled.port_range,
                scan_type=scheduled.scan_type,
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
            level_str = analyzed.get("overall_risk_level", "low")
            scan.risk_level = RiskLevel(level_str)
            scan.scan_results = {
                "hosts": analyzed.get("hosts", []),
                "scanned_at": analyzed.get("scanned_at"),
            }

            # Update scheduled scan metadata
            scheduled.last_run = datetime.utcnow()
            scheduled.total_runs += 1
            await db.commit()

            logger.info(f"Scheduled scan '{scan_name}' completed. Risk: {level_str}")

            # Send email alert if high/critical
            from app.core.config import settings
            from app.services.email_service import send_risk_alert

            if (
                settings.ENABLE_EMAIL_ALERTS
                and level_str in ("high", "critical")
                and settings.SMTP_USER
            ):
                owner_result = await db.execute(
                    select(User).where(User.id == scheduled.owner_id)
                )
                owner = owner_result.scalar_one_or_none()
                alert_emails = []
                if owner and owner.email:
                    alert_emails.append(owner.email)
                if settings.SMTP_USER not in alert_emails:
                    alert_emails.append(settings.SMTP_USER)

                await send_risk_alert(
                    scan_name=scan_name,
                    target=scheduled.target,
                    risk_level=level_str,
                    risk_score=analyzed.get("overall_risk_score", 0),
                    high_risk_hosts=analyzed.get("high_risk_hosts", 0),
                    recommendations=analyzed.get("ai_recommendations", []),
                    to_emails=alert_emails,
                )

        except Exception as e:
            logger.error(f"Scheduled scan failed: {e}")


def add_scan_job(scheduled_scan):
    """Add a scan job to the scheduler."""
    job_id = f"scan_{scheduled_scan.id}"

    if scheduled_scan.schedule_type == "daily":
        trigger = CronTrigger(
            hour=scheduled_scan.schedule_hour,
            minute=scheduled_scan.schedule_minute,
        )
    elif scheduled_scan.schedule_type == "weekly":
        trigger = CronTrigger(
            day_of_week=scheduled_scan.schedule_day,
            hour=scheduled_scan.schedule_hour,
            minute=scheduled_scan.schedule_minute,
        )
    elif scheduled_scan.schedule_type == "monthly":
        trigger = CronTrigger(
            day=1,
            hour=scheduled_scan.schedule_hour,
            minute=scheduled_scan.schedule_minute,
        )
    else:
        return

    scheduler.add_job(
        run_scheduled_scan,
        trigger=trigger,
        args=[str(scheduled_scan.id)],
        id=job_id,
        replace_existing=True,
    )
    logger.info(f"Scheduled job added: {job_id} ({scheduled_scan.schedule_type})")


def remove_scan_job(scheduled_scan_id: str):
    """Remove a scheduled scan job."""
    job_id = f"scan_{scheduled_scan_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        logger.info(f"Scheduled job removed: {job_id}")


async def load_all_scheduled_scans():
    """Load all active scheduled scans from DB on startup."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(ScheduledScan.is_active == True)
        )
        scheduled_scans = result.scalars().all()
        for s in scheduled_scans:
            add_scan_job(s)
        logger.info(f"Loaded {len(scheduled_scans)} scheduled scans from database")


def start_scheduler():
    """Start the APScheduler."""
    if not scheduler.running:
        scheduler.start()
        logger.info("Scheduler started successfully")


def stop_scheduler():
    """Stop the APScheduler."""
    if scheduler.running:
        scheduler.shutdown()
        logger.info("Scheduler stopped")