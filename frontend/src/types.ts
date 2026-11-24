/**
 * TypeScript data contracts matching the SENTINEL AI backend schemas.
 */

export interface DetectorResult {
  detector_name: string;
  available: boolean;
  threat_score: number | null;
  threat_type: string;
  prediction: string | null;
  confidence: number | null;
  details: Record<string, any>;
}

export interface AggregatedRiskResponse {
  overall_risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'UNKNOWN';
  is_threat: boolean;
  primary_threat_type: string;
  contributing_detectors: string[];
  evaluated_detectors: string[];
  unavailable_detectors: string[];
  detector_results: Record<string, DetectorResult>;
  aggregation_metadata: {
    evaluated_channels?: string[];
    web_channel_score?: number | null;
    network_channel_score?: number | null;
    cross_domain_boost_applied?: boolean;
    channel_weights_applied?: Record<string, number>;
    web_detectors_evaluated?: string[];
    [key: string]: any;
  };
}

export interface EvaluateRequest {
  event: Record<string, any>;
  session_history?: Record<string, any>[] | null;
  config?: Record<string, any> | null;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'offline';
  service: string;
  version: string;
  detectors: {
    http: boolean;
    session: boolean;
    sequence: boolean;
    network: boolean;
    autoencoder: boolean;
    [key: string]: boolean;
  };
}

export interface HistoryItem {
  id: string;
  timestamp: string;
  request: EvaluateRequest;
  response: AggregatedRiskResponse;
  label?: string;
  source?: string;
  latencyMs?: number;
}

export interface TelemetrySample {
  id: string;
  name: string;
  category: 'NORMAL' | 'ATTACK' | 'SESSION_ATTACK' | 'PAYLOAD_ANOMALY' | 'NETWORK_ATTACK';
  source: 'nginx' | 'suricata' | 'payload';
  description: string;
  groundTruth: string;
  payload: EvaluateRequest;
}
