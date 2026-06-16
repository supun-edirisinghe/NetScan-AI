"""
WebSocket endpoint for real-time scan progress updates.
"""
import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set

logger = logging.getLogger(__name__)
router = APIRouter()

# Store active WebSocket connections per scan
active_connections: Dict[str, Set[WebSocket]] = {}


async def broadcast_progress(scan_id: str, data: dict):
    """Send progress update to all connected clients for a scan."""
    if scan_id not in active_connections:
        return
    dead = set()
    for ws in active_connections[scan_id]:
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    active_connections[scan_id] -= dead


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for real-time scan progress."""
    await websocket.accept()

    if scan_id not in active_connections:
        active_connections[scan_id] = set()
    active_connections[scan_id].add(websocket)

    logger.info(f"WebSocket connected for scan {scan_id}")

    try:
        while True:
            await asyncio.sleep(1)
            try:
                await websocket.receive_text()
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if scan_id in active_connections:
            active_connections[scan_id].discard(websocket)
            if not active_connections[scan_id]:
                del active_connections[scan_id]
        logger.info(f"WebSocket disconnected for scan {scan_id}")