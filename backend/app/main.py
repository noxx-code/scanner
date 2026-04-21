"""FastAPI application factory."""
import logging
from pathlib import Path

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None

from backend.app.core.config import get_config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config=None) -> FastAPI:
    """Create and configure FastAPI application.
    
    Args:
        config: Configuration object (optional, will use default if not provided)
        
    Returns:
        Configured FastAPI application
    """
    if not HAS_FASTAPI:
        logger.error("FastAPI is not installed")
        return None
    
    if config is None:
        config = get_config()
    
    app = FastAPI(
        title=config.API_TITLE,
        version=config.API_VERSION,
        debug=getattr(config, 'DEBUG', False)
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Register routes
    try:
        from backend.app.routes.scanning import router as scanning_router
        if scanning_router:
            app.include_router(scanning_router)
            logger.info("✓ Scanning routes registered")
    except Exception as e:
        logger.warning(f"Failed to register scanning routes: {e}")
    
    # Try to include other existing routes
    try:
        # Adjust these imports based on your actual route structure
        from backend.app.routes import auth
        if hasattr(auth, 'router'):
            app.include_router(auth.router)
            logger.info("✓ Auth routes registered")
    except Exception as e:
        logger.debug(f"Auth routes not available: {e}")
    
    try:
        from backend.app.routes import report
        if hasattr(report, 'router'):
            app.include_router(report.router)
            logger.info("✓ Report routes registered")
    except Exception as e:
        logger.debug(f"Report routes not available: {e}")
    
    # Health check endpoints
    @app.get("/")
    async def root():
        """Root endpoint."""
        return {
            "message": config.API_TITLE,
            "version": config.API_VERSION,
            "status": "operational"
        }
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "version": config.API_VERSION
        }
    
    logger.info(f"✓ FastAPI application initialized ({config.API_TITLE})")
    return app


# Create app instance for ASGI servers
if HAS_FASTAPI:
    app = create_app()
else:
    logger.error("Cannot create app - FastAPI not installed")
    app = None


if __name__ == "__main__":
    if HAS_FASTAPI and app:
        import uvicorn
        config = get_config()
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            reload=getattr(config, 'DEBUG', False)
        )
    else:
        print("FastAPI not available")
