"""
main.py
NIDS Entry point - starts both API server and detection pipeline
"""

import os
import sys
import signal
import logging
import threading
import time
from pathlib import Path

# Setup path
sys.path.insert(0, str(Path(__file__).parent))

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("nids.log"),
    ],
)

logger = logging.getLogger("nids.main")


# Global references for cleanup
_pipeline = None
_api_app = None


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Received shutdown signal, stopping NIDS...")
    if _pipeline:
        _pipeline.stop()
    sys.exit(0)


def run_api_server():
    """Run FastAPI server in separate thread"""
    import uvicorn
    from nids.core.config import get_settings
    from nids.api.server import create_app

    settings = get_settings()
    app = create_app()

    config = uvicorn.Config(
        app=app,
        host=settings.api.host,
        port=settings.api.port,
        reload=False,
        log_level="info",
    )
    server = uvicorn.Server(config)
    server.run()


def main():
    """Main entry point"""
    global _pipeline

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    from nids.core.config import get_settings

    settings = get_settings()

    logger.info(f"Starting NIDS v{settings.version}")
    logger.info(f"Runtime profile: {settings.runtime.profile}")
    logger.info(f"API will listen on {settings.api.host}:{settings.api.port}")

    # Initialize and start pipeline
    from nids.pipeline import get_pipeline

    _pipeline = get_pipeline()
    _pipeline.start()

    # Start API server in background thread
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()

    # Wait a moment for API to start
    time.sleep(2)

    logger.info("NIDS is running. Press Ctrl+C to stop.")

    # Keep main thread alive with simple sleep
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        if _pipeline:
            _pipeline.stop()


if __name__ == "__main__":
    main()
