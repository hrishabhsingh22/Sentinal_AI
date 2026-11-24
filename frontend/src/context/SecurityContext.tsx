import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import {
  AggregatedRiskResponse,
  EvaluateRequest,
  HealthResponse,
  HistoryItem,
} from '../types';
import { apiService, DEFAULT_API_BASE_URL } from '../services/api';

export type TabType =
  | 'overview'
  | 'threat-detection'
  | 'traffic-analysis'
  | 'detector-health'
  | 'event-history'
  | 'settings';

interface SecurityStats {
  totalRequests: number;
  threatsDetected: number;
  normalRequests: number;
  criticalAlerts: number;
  threatDistribution: Record<string, number>;
}

interface SecurityContextType {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  history: HistoryItem[];
  stats: SecurityStats;
  health: HealthResponse | null;
  lastResult: AggregatedRiskResponse | null;
  isEvaluating: boolean;
  apiError: string | null;
  apiBaseUrl: string;
  setApiBaseUrl: (url: string) => void;
  evaluateEvent: (request: EvaluateRequest, label?: string, source?: string) => Promise<AggregatedRiskResponse | null>;
  refreshHealth: () => Promise<void>;
  clearHistory: () => void;
}

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export const SecurityProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [lastResult, setLastResult] = useState<AggregatedRiskResponse | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [apiBaseUrl, setApiBaseUrlState] = useState<string>(DEFAULT_API_BASE_URL);

  const [stats, setStats] = useState<SecurityStats>({
    totalRequests: 0,
    threatsDetected: 0,
    normalRequests: 0,
    criticalAlerts: 0,
    threatDistribution: {},
  });

  const setApiBaseUrl = (url: string) => {
    setApiBaseUrlState(url);
    apiService.setBaseUrl(url);
    refreshHealth();
  };

  const refreshHealth = async () => {
    try {
      const data = await apiService.checkHealth();
      setHealth(data);
    } catch {
      setHealth({
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
      });
    }
  };

  useEffect(() => {
    refreshHealth();
    const interval = setInterval(refreshHealth, 15000);
    return () => clearInterval(interval);
  }, []);

  const evaluateEvent = async (
    request: EvaluateRequest,
    label?: string,
    source?: string
  ): Promise<AggregatedRiskResponse | null> => {
    setIsEvaluating(true);
    setApiError(null);

    try {
      const { result, latencyMs } = await apiService.evaluate(request);
      setLastResult(result);

      const rawType = result.primary_threat_type;
      const threatType = (rawType && typeof rawType === 'string' && rawType.trim() && rawType.trim().toUpperCase() !== 'UNAVAILABLE' && rawType.trim().toUpperCase() !== 'NONE')
        ? rawType.trim()
        : 'UNKNOWN';

      const historyItem: HistoryItem = {
        id: `evt-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
        timestamp: new Date().toLocaleTimeString(),
        request,
        response: result,
        label: label || threatType,
        source: source || 'api',
        latencyMs,
      };

      setHistory((prev) => [historyItem, ...prev]);

      // Update aggregate statistics from actual API response
      setStats((prev) => {
        const isThreat = Boolean(result.is_threat);
        const isCritical = result.risk_level === 'CRITICAL';

        // Count ONLY explicitly NORMAL or confirmed benign events
        // Do NOT count UNKNOWN events or unclassified events as benign
        const BENIGN_LABELS = ['NORMAL', 'BENIGN', 'CLEAN', 'LEGITIMATE', 'SAFE'];
        const isBenign = !isThreat && BENIGN_LABELS.includes(threatType.toUpperCase());

        const updatedDistribution = { ...prev.threatDistribution };
        updatedDistribution[threatType] = (updatedDistribution[threatType] || 0) + 1;

        return {
          totalRequests: prev.totalRequests + 1,
          threatsDetected: prev.threatsDetected + (isThreat ? 1 : 0),
          normalRequests: prev.normalRequests + (isBenign ? 1 : 0),
          criticalAlerts: prev.criticalAlerts + (isCritical ? 1 : 0),
          threatDistribution: updatedDistribution,
        };
      });

      return result;
    } catch (err: any) {
      const msg = err.message || 'Failed to communicate with backend API.';
      setApiError(msg);
      return null;
    } finally {
      setIsEvaluating(false);
    }
  };

  const clearHistory = () => {
    setHistory([]);
    setStats({
      totalRequests: 0,
      threatsDetected: 0,
      normalRequests: 0,
      criticalAlerts: 0,
      threatDistribution: {},
    });
    setLastResult(null);
  };

  return (
    <SecurityContext.Provider
      value={{
        activeTab,
        setActiveTab,
        history,
        stats,
        health,
        lastResult,
        isEvaluating,
        apiError,
        apiBaseUrl,
        setApiBaseUrl,
        evaluateEvent,
        refreshHealth,
        clearHistory,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export const useSecurity = () => {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
};
