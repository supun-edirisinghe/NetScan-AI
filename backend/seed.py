"""
seed.py
───────
Creates a default admin user and optional demo scan data.
Run once after first launch:
    cd backend && python seed.py
"""
import asyncio
import logging
from datetime import datetime, timedelta
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed")


async def seed():
    from app.core.database import init_db, AsyncSessionLocal
    from app.models.user import User
    from app.models.scan import Scan, ScanStatus, RiskLevel
    from app.core.security import get_password_hash
    from sqlalchemy import select

    await init_db()

    async with AsyncSessionLocal() as db:
        # ── Create admin user ─────────────────────────────────────
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                email="admin@netscan.local",
                hashed_password=get_password_hash("admin123"),
                full_name="Administrator",
                is_admin=True,
            )
            db.add(admin)
            await db.flush()
            logger.info("Created admin user (password: admin123)")
        else:
            result = await db.execute(select(User).where(User.username == "admin"))
            admin = result.scalar_one()
            logger.info("Admin user already exists")

        # ── Create demo scans ─────────────────────────────────────
        result = await db.execute(select(Scan).where(Scan.owner_id == admin.id))
        existing = result.scalars().all()

        if len(existing) == 0:
            demo_scans = [
                {
                    "name": "Production Network Audit",
                    "target": "192.168.1.0/24",
                    "port_range": "1-1024",
                    "total_hosts": 20,
                    "hosts_up": 12,
                    "total_open_ports": 47,
                    "high_risk_hosts": 3,
                    "risk_score": 72.5,
                    "risk_level": RiskLevel.CRITICAL,
                    "port_distribution": {"22": 8, "80": 10, "443": 9, "3306": 3, "445": 2, "23": 1},
                    "ai_recommendations": [
                        {"id": "R001", "severity": "critical", "title": "Telnet Detected",
                         "description": "Telnet found on 1 host.", "recommendation": "Disable Telnet, use SSH.",
                         "affected_port": 23, "service": "Telnet", "cve_refs": []},
                        {"id": "R003", "severity": "critical", "title": "SMB Exposed",
                         "description": "SMB port open on 2 hosts.", "recommendation": "Block from internet, apply patches.",
                         "affected_port": 445, "service": "SMB", "cve_refs": ["CVE-2017-0144"]},
                    ],
                },
                {
                    "name": "Dev Server Scan",
                    "target": "10.0.0.5",
                    "port_range": "1-65535",
                    "total_hosts": 1,
                    "hosts_up": 1,
                    "total_open_ports": 8,
                    "high_risk_hosts": 0,
                    "risk_score": 22.0,
                    "risk_level": RiskLevel.LOW,
                    "port_distribution": {"22": 1, "80": 1, "443": 1, "3000": 1, "5432": 1},
                    "ai_recommendations": [
                        {"id": "R010", "severity": "low", "title": "SSH Hardening",
                         "description": "SSH is open.", "recommendation": "Use key-based auth, disable root login.",
                         "affected_port": 22, "service": "SSH", "cve_refs": []},
                    ],
                },
                {
                    "name": "DMZ Security Check",
                    "target": "172.16.0.0/28",
                    "port_range": "1-10000",
                    "total_hosts": 14,
                    "hosts_up": 9,
                    "total_open_ports": 31,
                    "high_risk_hosts": 2,
                    "risk_score": 55.0,
                    "risk_level": RiskLevel.HIGH,
                    "port_distribution": {"80": 7, "443": 6, "22": 5, "3389": 2, "8080": 3},
                    "ai_recommendations": [
                        {"id": "R004", "severity": "high", "title": "RDP Exposed",
                         "description": "RDP on 2 hosts.", "recommendation": "Restrict via VPN only.",
                         "affected_port": 3389, "service": "RDP", "cve_refs": ["CVE-2019-0708"]},
                    ],
                },
            ]

            for i, s in enumerate(demo_scans):
                created = datetime.utcnow() - timedelta(days=random.randint(1, 30))
                scan = Scan(
                    name=s["name"],
                    target=s["target"],
                    port_range=s["port_range"],
                    scan_type="tcp",
                    status=ScanStatus.COMPLETED,
                    total_hosts=s["total_hosts"],
                    hosts_up=s["hosts_up"],
                    total_open_ports=s["total_open_ports"],
                    high_risk_hosts=s["high_risk_hosts"],
                    risk_score=s["risk_score"],
                    risk_level=s["risk_level"],
                    ai_recommendations=s["ai_recommendations"],
                    port_distribution=s["port_distribution"],
                    scan_results={"hosts": []},
                    owner_id=admin.id,
                    created_at=created,
                    started_at=created,
                    completed_at=created + timedelta(seconds=random.randint(30, 300)),
                    duration_seconds=random.uniform(30, 300),
                )
                db.add(scan)

            logger.info(f"Created {len(demo_scans)} demo scans")

        await db.commit()
        logger.info("Seeding complete! Login: admin / admin123")


if __name__ == "__main__":
    asyncio.run(seed())
