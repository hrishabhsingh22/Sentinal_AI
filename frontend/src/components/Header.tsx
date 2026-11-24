import React from 'react';
import { ExternalLink, RefreshCw, Terminal } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';

export const Header: React.FC = () => {
  const { activeTab, health, refreshHealth, apiBaseUrl } = useSecurity();

  const getTitle = () => {
    switch (activeTab) {
      case 'overview':
        return 'Security Operations Overview';
      case 'threat-detection':
        return 'Hybrid Threat Detection Engine';
      case 'traffic-analysis':
        return 'Traffic Analysis & Replay';
      case 'detector-health':
        return 'Multi-Detector Diagnostic Health';
      case 'event-history':
        return 'Session Event Audit Log';
      case 'settings':
        return 'System & API Configuration';
      default:
        return 'Dashboard';
    }
  };

  return (
    <header className="h-16 bg-[#0a0f1d] border-b border-[#1a2333] px-6 flex items-center justify-between shrink-0">
      <div className="flex items-center gap-3">
        <h1 className="text-base font-semibold text-slate-100 font-sans tracking-wide">
          {getTitle()}
        </h1>
        <span className="text-slate-600 font-mono text-xs">/</span>
        <span className="text-xs font-mono text-slate-400">
          SOC-MLD TELEMETRY
        </span>
      </div>

      <div className="flex items-center gap-4">
        {/* API connection indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#0f172a] border border-[#1e293b] text-xs font-mono">
          <Terminal className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-slate-400">API:</span>
          <span className="text-slate-200">{apiBaseUrl}</span>
        </div>

        {/* Quick Health Status Indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-[#0f172a] border border-[#1e293b] text-xs">
          <span
            className={`w-2 h-2 rounded-full ${
              health?.status === 'healthy'
                ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                : health?.status === 'degraded'
                ? 'bg-amber-400'
                : 'bg-red-400 shadow-[0_0_8px_#f87171]'
            }`}
          />
          <span className="text-slate-300 font-mono capitalize">
            {health?.status || 'Connecting...'}
          </span>
          <button
            onClick={() => refreshHealth()}
            title="Refresh component health"
            className="text-slate-400 hover:text-cyan-400 transition-colors ml-1 p-0.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Swagger docs link */}
        <a
          href={`${apiBaseUrl}/docs`}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-mono text-slate-300 hover:text-cyan-300 px-3 py-1.5 rounded-md bg-[#0f172a] hover:bg-[#152238] border border-[#1e293b] transition-all"
        >
          <span>Swagger UI</span>
          <ExternalLink className="w-3 h-3 text-slate-400" />
        </a>
      </div>
    </header>
  );
};
