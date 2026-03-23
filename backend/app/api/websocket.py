import json
import uuid

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.events.bus import event_bus

router = APIRouter()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: uuid.UUID):
    """Stream scan events to the frontend via WebSocket."""
    await websocket.accept()
    try:
        async for event in event_bus.subscribe(scan_id):
            await websocket.send_text(json.dumps(event, default=str))
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()
