"""FastAPI router endpoints for SENTINEL AI threat detection and aggregation."""

from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, status
import pandas as pd

from src.api.schemas import (
    AggregatedRiskResponse,
    EvaluateRequest,
    HealthResponse,
)
from src.detection.aggregator import (
    aggregate_event,
    AggregatorConfig,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

router = APIRouter()


def _get_detector_health() -> Dict[str, bool]:
    """Check availability of detector model artifacts on disk."""
    return {
        "http": (PROJECT_ROOT / "models" / "http" / "http_classifier.joblib").is_file(),
        "session": (PROJECT_ROOT / "models" / "session" / "session_classifier.joblib").is_file(),
        "sequence": (PROJECT_ROOT / "models" / "sequence" / "sequence_lstm_v2.keras").is_file(),
        "network": (PROJECT_ROOT / "models" / "network" / "network_classifier.joblib").is_file(),
        "autoencoder": (PROJECT_ROOT / "models" / "autoencoder.keras").is_file(),
    }


def _build_config_override(config_req: Any) -> Optional[AggregatorConfig]:
    """Build AggregatorConfig instance from optional request parameters."""
    if config_req is None:
        return None
    config_dict = {
        k: v for k, v in config_req.model_dump().items() if v is not None
    }
    if not config_dict:
        return None
    try:
        return AggregatorConfig(**config_dict)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid aggregator configuration: {str(exc)}",
        ) from exc


@router.get("/", tags=["Info"])
def root_info() -> Dict[str, str]:
    """Root metadata endpoint providing service details and documentation links."""
    return {
        "service": "SENTINEL AI Threat Detection & Hybrid Risk Aggregation API",
        "version": "1.0.0",
        "status": "running",
        "docs_url": "/docs",
        "health_url": "/health",
        "evaluate_url": "/evaluate",
    }


@router.get("/health", response_model=HealthResponse, tags=["Health"])
def health_check() -> HealthResponse:
    """System health check endpoint verifying component and artifact availability."""
    detector_status = _get_detector_health()
    all_healthy = all(detector_status.values())
    return HealthResponse(
        status="healthy" if all_healthy else "degraded",
        service="sentinel-ai-backend",
        version="1.0.0",
        detectors=detector_status,
    )


@router.post(
    "/evaluate",
    response_model=AggregatedRiskResponse,
    status_code=status.HTTP_200_OK,
    tags=["Evaluation"],
    summary="Evaluate Telemetry Event with Hybrid Risk Aggregation",
)
def evaluate_event_endpoint(request: EvaluateRequest) -> Dict[str, Any]:
    """Evaluate a telemetry observation (HTTP, Network, or Payload).

    Supports:
    - Single telemetry observation evaluation.
    - Chronological session context passed to Sequence LSTM when available.
    - Missing/unavailable detector handling without crashing.
    - Correlation dampening and cross-domain fusion.
    """
    config_override = _build_config_override(request.config)

    try:
        result = aggregate_event(
            event=request.event,
            session_history=request.session_history,
            config=config_override,
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event evaluation request: {str(exc)}",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error evaluating event: {str(exc)}",
        ) from exc


@router.post(
    "/evaluate/http",
    response_model=AggregatedRiskResponse,
    status_code=status.HTTP_200_OK,
    tags=["Evaluation"],
    summary="Evaluate HTTP Event",
)
def evaluate_http_endpoint(request: EvaluateRequest) -> Dict[str, Any]:
    """Convenience endpoint dedicated to HTTP and session evaluation."""
    return evaluate_event_endpoint(request)
