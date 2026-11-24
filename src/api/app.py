"""FastAPI Application factory and configuration for SENTINEL AI."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router


def create_app() -> FastAPI:
    """Create and configure the SENTINEL AI FastAPI application."""
    app = FastAPI(
        title="SENTINEL AI Threat Detection & Hybrid Risk Aggregation API",
        description=(
            "Production API integrating multi-domain detection: HTTP payloads, "
            "temporal sessions, Sequence LSTM, transport flows, and Autoencoders."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Enable CORS for frontend dashboard
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom exception handler for request validation errors
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors = exc.errors()
        error_messages = [
            f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}"
            for err in errors
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Request validation failed",
                "errors": error_messages,
            },
        )

    # Include API routes
    app.include_router(router)

    return app


# Default application instance for ASGI servers (uvicorn src.api.app:app)
app = create_app()
