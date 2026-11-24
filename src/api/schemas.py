"""Pydantic schemas for the SENTINEL AI API.

Defines request and response data contracts for event evaluation,
session history, individual detector outputs, and overall risk aggregation.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator


class AggregatorConfigOverride(BaseModel):
    """Optional overrides for hybrid aggregator weights and thresholds."""

    weight_http: Optional[float] = Field(None, ge=0.0, description="Weight for HTTP detector")
    weight_session: Optional[float] = Field(None, ge=0.0, description="Weight for Session detector")
    weight_sequence: Optional[float] = Field(None, ge=0.0, description="Weight for Sequence detector")
    weight_autoencoder: Optional[float] = Field(None, ge=0.0, description="Weight for Autoencoder detector")

    channel_weight_web: Optional[float] = Field(None, ge=0.0, description="Weight for Web channel")
    channel_weight_net: Optional[float] = Field(None, ge=0.0, description="Weight for Network channel")

    web_correlation_dampening: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Web signal correlation dampening factor"
    )
    cross_domain_boost: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Cross-domain corroboration boost factor"
    )

    threat_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Operational threat threshold")
    critical_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Critical severity threshold")
    high_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="High severity threshold")
    medium_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Medium severity threshold")
    low_threshold: Optional[float] = Field(None, ge=0.0, le=1.0, description="Low severity threshold")


class EvaluateRequest(BaseModel):
    """Request schema for evaluating a telemetry observation with optional session context."""

    event: Dict[str, Any] = Field(
        ...,
        description="Telemetry event feature dictionary (e.g., HTTP payload/time features or network features).",
    )
    session_history: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Optional list of chronological session request records for Sequence LSTM evaluation.",
    )
    config: Optional[AggregatorConfigOverride] = Field(
        default=None,
        description="Optional aggregator configuration parameter overrides.",
    )

    @model_validator(mode="before")
    @classmethod
    def handle_direct_or_nested(cls, data: Any) -> Any:
        """Allow both wrapped {'event': {...}} and direct flat event dictionaries."""
        if isinstance(data, dict):
            if "event" not in data:
                # If neither 'event' nor 'session_history' is present, treat entire body as event
                # Preserves 'session_history' if sent at top level with flat features
                session_history = data.pop("session_history", None)
                config = data.pop("config", None)
                return {
                    "event": data,
                    "session_history": session_history,
                    "config": config,
                }
        return data

    @field_validator("event")
    @classmethod
    def validate_event_not_empty(cls, v: Any) -> Dict[str, Any]:
        """Validate that the event dictionary is non-empty."""
        if not isinstance(v, dict):
            raise ValueError("Event must be a dictionary of feature key-value pairs.")
        if not v:
            raise ValueError("Event dictionary cannot be empty.")
        return v

    @field_validator("session_history")
    @classmethod
    def validate_session_history(cls, v: Any) -> Optional[List[Dict[str, Any]]]:
        """Validate session history structure if supplied."""
        if v is not None:
            if not isinstance(v, list):
                raise ValueError("session_history must be a list of request records.")
            if len(v) == 0:
                return None
            for idx, item in enumerate(v):
                if not isinstance(item, dict) or not item:
                    raise ValueError(
                        f"session_history record at index {idx} must be a non-empty dictionary."
                    )
        return v


class DetectorResultSchema(BaseModel):
    """Standardized output for an individual detector evaluation."""

    detector_name: str = Field(..., description="Name of the detector (http, session, sequence, network, autoencoder)")
    available: bool = Field(..., description="Whether the detector was available and successfully evaluated")
    threat_score: Optional[float] = Field(None, description="Normalized threat score in [0.0, 1.0], or None if unavailable")
    threat_type: str = Field("UNAVAILABLE", description="Predicted threat classification or status")
    prediction: Optional[str] = Field(None, description="Raw categorical prediction string")
    confidence: Optional[float] = Field(None, description="Prediction confidence or probability")
    details: Dict[str, Any] = Field(default_factory=dict, description="Component-specific diagnostics or probabilities")


class AggregatedRiskResponse(BaseModel):
    """Unified threat evaluation response across all operational channels."""

    overall_risk_score: float = Field(..., description="Aggregated risk score in [0.0, 1.0]")
    risk_level: str = Field(..., description="Categorical severity level (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNKNOWN)")
    is_threat: bool = Field(..., description="Whether the event warrants operational threat alert")
    primary_threat_type: str = Field(..., description="Primary threat classification type (e.g., SQLI_ATTEMPT, NORMAL, UNKNOWN)")
    contributing_detectors: List[str] = Field(..., description="Detectors that actively contributed to threat assessment")
    evaluated_detectors: List[str] = Field(..., description="Detectors evaluated with valid threat scores")
    unavailable_detectors: List[str] = Field(..., description="Detectors that were omitted due to missing data or schema")
    detector_results: Dict[str, DetectorResultSchema] = Field(..., description="Per-detector standardized outputs")
    aggregation_metadata: Dict[str, Any] = Field(..., description="Operational metadata and channel score breakdown")


class HealthResponse(BaseModel):
    """System health check and component availability status."""

    status: str = Field("healthy", description="Overall service status")
    service: str = Field("sentinel-ai-backend", description="Service identifier")
    version: str = Field("1.0.0", description="API version")
    detectors: Dict[str, bool] = Field(..., description="Model artifact availability for each detector")
