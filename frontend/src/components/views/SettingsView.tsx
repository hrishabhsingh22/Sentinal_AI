import React, { useState } from 'react';
import {
  Settings,
  Server,
  CheckCircle2,
  RefreshCw,
  ExternalLink,
  Sliders,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

export const SettingsView: React.FC = () => {
  const { apiBaseUrl, setApiBaseUrl, health, refreshHealth } = useSecurity();
  const [urlInput, setUrlInput] = useState<string>(apiBaseUrl);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  const handleSaveUrl = () => {
    setApiBaseUrl(urlInput);
    setSaveMessage('Backend URL updated successfully.');
    setTimeout(() => setSaveMessage(null), 3000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      {/* Header */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5">
        <div className="flex items-center gap-2">
          <Settings className="w-4 h-4 text-cyan-400" />
          <h2 className="text-base font-semibold text-slate-100 font-sans">
            System Configuration & Backend Settings
          </h2>
        </div>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Manage FastAPI connection endpoints and inspect hybrid aggregator operational parameters
        </p>
      </div>

      {/* Backend API Connection Setting */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 font-sans">
          <Server className="w-4 h-4 text-cyan-400" />
          <span>FastAPI Engine Endpoint</span>
        </div>

        <div className="space-y-2">
          <label className="text-xs font-mono text-slate-400 block">
            Base Endpoint URL (Default: http://127.0.0.1:8000)
          </label>
          <div className="flex items-center gap-3">
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="flex-1 bg-[#080d18] border border-[#1e293b] rounded-lg px-3.5 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
              placeholder="http://127.0.0.1:8000"
            />
            <button
              onClick={handleSaveUrl}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 text-xs font-mono transition-all font-medium"
            >
              Update URL
            </button>
            <button
              onClick={() => refreshHealth()}
              className="px-3.5 py-2 rounded-lg bg-[#0f172a] hover:bg-[#1a263d] text-slate-300 text-xs font-mono transition-all flex items-center gap-1.5 border border-[#1e293b]"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Test Ping</span>
            </button>
          </div>
          {saveMessage && (
            <div className="text-xs font-mono text-emerald-400 flex items-center gap-1 mt-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{saveMessage}</span>
            </div>
          )}
        </div>

        {/* Status card */}
        <div className="p-3.5 rounded-lg bg-[#080d18] border border-[#162035] flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                health?.status === 'healthy'
                  ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                  : health?.status === 'degraded'
                  ? 'bg-amber-400'
                  : 'bg-red-400 shadow-[0_0_8px_#f87171]'
              }`}
            />
            <span className="text-slate-300">Connection State:</span>
            <span className="font-semibold text-slate-100 uppercase">
              {health?.status || 'OFFLINE'}
            </span>
          </div>

          <a
            href={`${apiBaseUrl}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <span>Interactive OpenAPI Docs</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>
      </div>

      {/* Aggregator Architecture Specifications */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100 font-sans">
          <Sliders className="w-4 h-4 text-cyan-400" />
          <span>Configured Aggregator Calibration Weights</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-[#080d18] border border-[#162035]">
            <div className="text-slate-400 text-[11px]">Web Channel Weight</div>
            <div className="text-base font-bold text-slate-100 mt-1">0.60 (60%)</div>
            <div className="text-[10px] text-slate-500 mt-0.5">HTTP: 0.35, Session: 0.20, Sequence: 0.30, AE: 0.15</div>
          </div>

          <div className="p-3 rounded-lg bg-[#080d18] border border-[#162035]">
            <div className="text-slate-400 text-[11px]">Network Channel Weight</div>
            <div className="text-base font-bold text-slate-100 mt-1">0.40 (40%)</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Suricata Alerts, Flow Rates & Port Telemetry</div>
          </div>

          <div className="p-3 rounded-lg bg-[#080d18] border border-[#162035]">
            <div className="text-slate-400 text-[11px]">Correlation Dampening (γ)</div>
            <div className="text-base font-bold text-slate-100 mt-1">0.35</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Prevents additive inflation across collinear web signals</div>
          </div>

          <div className="p-3 rounded-lg bg-[#080d18] border border-[#162035]">
            <div className="text-slate-400 text-[11px]">Cross-Domain Boost</div>
            <div className="text-base font-bold text-slate-100 mt-1">+0.05</div>
            <div className="text-[10px] text-slate-500 mt-0.5">When both App and Transport layers flag independent threats</div>
          </div>
        </div>
      </div>
    </div>
  );
};
