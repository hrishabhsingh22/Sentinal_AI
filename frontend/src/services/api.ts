import { AggregatedRiskResponse, EvaluateRequest, HealthResponse } from '../types';

export const DEFAULT_API_BASE_URL = 'http://127.0.0.1:8000';

export class ApiService {
  private baseUrl: string;

  constructor(baseUrl: string = DEFAULT_API_BASE_URL) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  setBaseUrl(url: string) {
    this.baseUrl = url.replace(/\/+$/, '');
  }

  getBaseUrl(): string {
    return this.baseUrl;
  }

  async checkHealth(): Promise<HealthResponse> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        throw new Error(`Health check failed with status: ${response.status}`);
      }

      return await response.json();
    } catch (err: any) {
      return {
        status: 'offline',
        service: 'sentinel-ai-backend',
        version: 'unknown',
        detectors: {
          http: false,
          session: false,
          sequence: false,
          network: false,
          autoencoder: false,
        },
      };
    }
  }

  async evaluate(request: EvaluateRequest): Promise<{ result: AggregatedRiskResponse; latencyMs: number }> {
    const startTime = performance.now();
    const response = await fetch(`${this.baseUrl}/evaluate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(request),
    });

    const latencyMs = Math.round(performance.now() - startTime);

    if (!response.ok) {
      let errorMessage = `Server error ${response.status}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          if (typeof errorJson.detail === 'string') {
            errorMessage = errorJson.detail;
          } else if (Array.isArray(errorJson.detail)) {
            errorMessage = errorJson.detail.map((d: any) => d.msg || JSON.stringify(d)).join('; ');
          } else {
            errorMessage = JSON.stringify(errorJson.detail);
          }
        } else if (errorJson.errors) {
          errorMessage = errorJson.errors.join('; ');
        }
      } catch {
        // Fallback to text if not json
        const text = await response.text();
        if (text) errorMessage = text;
      }
      throw new Error(errorMessage);
    }

    const result = await response.json();
    return { result, latencyMs };
  }
}

export const apiService = new ApiService();
