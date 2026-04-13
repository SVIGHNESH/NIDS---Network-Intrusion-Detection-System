"""
nids/api/server.py
FastAPI REST API server
"""

import logging
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from nids.core.config import ApiConfig, get_settings
from nids.storage.database import Database, get_database


logger = logging.getLogger("nids.api")


class WebSocketManager:
    """WebSocket connection manager for real-time alerts"""

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"WebSocket send error: {e}")
                disconnected.append(connection)

        for ws in disconnected:
            self.disconnect(ws)


# Global WebSocket manager
ws_manager = WebSocketManager()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    settings = get_settings()
    db_path = settings.database.path
    retention_days = settings.database.retention_days

    # Initialize database
    database = get_database(db_path, retention_days)
    app.state.database = database
    app.state.ws_manager = ws_manager

    logger.info(f"API server started with database: {db_path}")

    yield

    logger.info("API server shutting down")


def create_app() -> FastAPI:
    """Create and configure FastAPI application"""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    from nids.api import alerts, health

    app.include_router(alerts.router, prefix="/api/v1", tags=["alerts"])
    app.include_router(health.router, prefix="/api/v1", tags=["health"])

    # WebSocket endpoint
    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive, wait for broadcasts
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception as e:
            logger.error(f"WebSocket error: {e}")
            ws_manager.disconnect(websocket)

    return app


def get_ws_manager() -> WebSocketManager:
    """Get global WebSocket manager"""
    return ws_manager
