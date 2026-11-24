import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  RotateCcw,
  CheckCircle,
  AlertCircle,
  FileCode,
  Layers,
  Cpu,
  Info,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { RiskBadge } from '../RiskBadge';
import { TELEMETRY_SAMPLES } from '../../data/samples';

export const ThreatDetectionView: React.FC = () => {
  const { evaluateEvent, isEvaluating, apiError, lastResult } = useSecurity();

  // Initial default JSON from sample 1 (Normal HTTP)
  const [jsonInput, setJsonInput] = useState<string>(
    JSON.stringify(TELEMETRY_SAMPLES[1].payload, null, 2)
  );
  const [parseError, setParseError] = useState<string | null>(null);

  const handleFormatJson = () => {
    try {
      const parsed = JSON.parse(jsonInput);
      setJsonInput(JSON.stringify(parsed, null, 2));
      setParseError(null);
    } catch (err: any) {
      setParseError(`JSON Syntax Error: ${err.message}`);
    }
  };

  const handleSelectTemplate = (sampleId: string) => {
    const sample = TELEMETRY_SAMPLES.find((s) => s.id === sampleId);
    if (sample) {
      setJsonInput(JSON.stringify(sample.payload, null, 2));
      setParseError(null);
    }
  };

  const handleSubmit = async () => {
    setParseError(null);
    try {
      const parsed = JSON.parse(jsonInput);
      await evaluateEvent(parsed, 'Manual Evaluation', 'manual-input');
    } catch (err: any) {
      setParseError(`Invalid JSON format: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-slate-100 font-sans">
            Manual Telemetry Evaluation
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Submit JSON telemetry directly to POST /evaluate for multi-detector hybrid risk analysis
          </p>
        </div>

        {/* Quick Sample Selector */}
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Load Template:</span>
          <select
            onChange={(e) => handleSelectTemplate(e.target.value)}
            defaultValue="sqli-attempt-274"
            className="bg-[#0f172a] border border-[#1e293b] rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            {TELEMETRY_SAMPLES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.category})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: JSON Editor */}
        <div className="lg:col-span-6 bg-[#0c1322] border border-[#1a263d] rounded-xl flex flex-col h-[650px] overflow-hidden">
          <div className="p-4 border-b border-[#1a263d] flex items-center justify-between bg-[#080d18]">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-medium text-slate-200">
                REQUEST BODY JSON
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleFormatJson}
                className="px-2.5 py-1 text-[11px] font-mono text-slate-400 hover:text-slate-200 bg-[#0f172a] border border-[#1e293b] rounded hover:border-slate-600 transition-all"
              >
                Format JSON
              </button>
              <button
                onClick={() => setJsonInput('{\n  "event": {}\n}')}
                className="px-2.5 py-1 text-[11px] font-mono text-slate-400 hover:text-slate-200 bg-[#0f172a] border border-[#1e293b] rounded hover:border-slate-600 transition-all flex items-center gap-1"
              >
                <RotateCcw className="w-3 h-3" />
                Clear
              </button>
            </div>
          </div>

          <div className="flex-1 p-3 bg-[#060a12] font-mono text-xs overflow-hidden">
            <textarea
              value={jsonInput}
              onChange={(e) => {
                setJsonInput(e.target.value);
                if (parseError) setParseError(null);
              }}
              spellCheck={false}
              className="w-full h-full bg-transparent text-slate-200 focus:outline-none resize-none font-mono text-xs leading-relaxed selection:bg-cyan-500/30"
              placeholder='{\n  "event": {\n    "f_has_sqli": 1,\n    ...\n  }\n}'
            />
          </div>

          {/* Validation or API error alert */}
          {(parseError || apiError) && (
            <div className="p-3 bg-red-950/60 border-t border-red-800/60 text-xs font-mono text-red-300 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
              <div className="break-all">{parseError || apiError}</div>
            </div>
          )}

          {/* Action Footer */}
          <div className="p-4 border-t border-[#1a263d] bg-[#0a0f1d] flex items-center justify-between">
            <div className="text-[11px] font-mono text-slate-500">
              Target: <span className="text-slate-400">POST /evaluate</span>
            </div>
            <button
              onClick={handleSubmit}
              disabled={isEvaluating}
              className={`px-5 py-2 rounded-lg font-mono text-xs font-medium flex items-center gap-2 transition-all shadow-lg ${
                isEvaluating
                  ? 'bg-cyan-950 text-cyan-400/50 cursor-not-allowed border border-cyan-800/40'
                  : 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 hover:border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
              }`}
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{isEvaluating ? 'EVALUATING...' : 'SUBMIT EVENT'}</span>
            </button>
          </div>
        </div>

        {/* Right Column: Live Detection Results */}
        <div className="lg:col-span-6 bg-[#0c1322] border border-[#1a263d] rounded-xl flex flex-col h-[650px] overflow-hidden">
          <div className="p-4 border-b border-[#1a263d] flex items-center justify-between bg-[#080d18]">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-medium text-slate-200">
                EVALUATION RESULT
              </span>
            </div>
            {lastResult && (
              <RiskBadge level={lastResult.risk_level} size="sm" />
            )}
          </div>

          <div className="flex-1 p-5 overflow-y-auto space-y-5 bg-[#080d18]/50">
            {lastResult ? (
              <>
                {/* Risk Score & Threat Banner */}
                <div className="p-4 rounded-xl bg-[#0e1627] border border-[#1d2a45]">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-[11px] font-mono text-slate-400 uppercase">
                        Unified Threat Assessment
                      </div>
                      <div className="text-2xl font-bold font-mono text-slate-100 mt-1 flex items-center gap-2">
                        <span>{lastResult.primary_threat_type}</span>
                        {lastResult.is_threat ? (
                          <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800/60">
                            THREAT
                          </span>
                        ) : (
                          <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60">
                            BENIGN
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-[11px] font-mono text-slate-400 uppercase">
                        Risk Score
                      </div>
                      <div
                        className={`text-3xl font-bold font-mono ${
                          lastResult.overall_risk_score >= 0.50
                            ? 'text-red-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {lastResult.overall_risk_score.toFixed(4)}
                      </div>
                    </div>
                  </div>

                  {/* Visual Risk Gauge Bar */}
                  <div className="mt-4">
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 mb-1">
                      <span>0.0 (SAFE)</span>
                      <span>0.50 (THRESHOLD)</span>
                      <span>1.0 (CRITICAL)</span>
                    </div>
                    <div className="w-full h-2 bg-[#162138] rounded-full overflow-hidden relative">
                      {/* Threshold marker */}
                      <div className="absolute left-1/2 top-0 bottom-0 w-0.5 bg-slate-600 z-10" />
                      <div
                        className={`h-full transition-all duration-500 rounded-full ${
                          lastResult.overall_risk_score >= 0.8
                            ? 'bg-red-500 shadow-[0_0_8px_#ef4444]'
                            : lastResult.overall_risk_score >= 0.5
                            ? 'bg-amber-500 shadow-[0_0_8px_#f59e0b]'
                            : 'bg-emerald-500 shadow-[0_0_8px_#10b981]'
                        }`}
                        style={{ width: `${Math.min(lastResult.overall_risk_score * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Contributing Detectors */}
                <div className="p-4 rounded-xl bg-[#0e1627] border border-[#1d2a45]">
                  <div className="text-xs font-mono text-slate-400 mb-2 uppercase">
                    Contributing Attack Detectors
                  </div>
                  {lastResult.contributing_detectors.length > 0 ? (
                    <div className="flex flex-wrap gap-2">
                      {lastResult.contributing_detectors.map((det) => (
                        <span
                          key={det}
                          className="px-2.5 py-1 rounded-md bg-red-950/60 text-red-300 border border-red-800/50 text-xs font-mono flex items-center gap-1.5"
                        >
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                          {det.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs font-mono text-slate-500">
                      None (Zero detectors flagged threat above threshold)
                    </div>
                  )}
                </div>

                {/* Individual 5-Detector Breakdown */}
                <div className="space-y-2">
                  <div className="text-xs font-mono text-slate-400 uppercase">
                    Component Level Diagnostic Outputs
                  </div>
                  <div className="space-y-2">
                    {['http', 'session', 'sequence', 'network', 'autoencoder'].map((name) => {
                      const res = lastResult.detector_results[name];
                      if (!res) return null;

                      return (
                        <div
                          key={name}
                          className="p-3 rounded-lg bg-[#0e1627] border border-[#1d2a45] flex items-center justify-between font-mono text-xs"
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span
                                className={`w-2 h-2 rounded-full ${
                                  res.available
                                    ? res.threat_score !== null && res.threat_score >= 0.50
                                      ? 'bg-red-400'
                                      : 'bg-emerald-400'
                                    : 'bg-slate-600'
                                }`}
                              />
                              <span className="font-semibold text-slate-200 uppercase">
                                {name}
                              </span>
                              <span
                                className={`text-[10px] px-1.5 py-0.2 rounded border ${
                                  res.available
                                    ? 'bg-blue-950/60 text-blue-300 border-blue-800/40'
                                    : 'bg-slate-900 text-slate-400 border-slate-700/50'
                                }`}
                              >
                                {res.available ? 'AVAILABLE' : 'UNAVAILABLE'}
                              </span>
                            </div>
                            <div className="text-[11px] text-slate-400 mt-1">
                              Pred: <span className="text-slate-200">{res.prediction || '—'}</span>{' '}
                              • Type: <span className="text-slate-300">{res.threat_type}</span>
                            </div>
                          </div>

                          <div className="text-right">
                            <div className="text-sm font-bold text-slate-200">
                              {res.threat_score !== null ? res.threat_score.toFixed(4) : 'N/A'}
                            </div>
                            <div className="text-[10px] text-slate-500">
                              Conf: {res.confidence !== null ? `${Math.round(res.confidence * 100)}%` : '—'}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Aggregation Metadata Details */}
                <div className="p-3.5 rounded-lg bg-[#070c16] border border-[#19243a] text-xs font-mono space-y-1.5 text-slate-400">
                  <div className="text-[10px] text-slate-500 uppercase font-semibold">
                    Channel Aggregation Metadata
                  </div>
                  <div className="flex justify-between">
                    <span>Evaluated Channels:</span>
                    <span className="text-slate-200">
                      {lastResult.aggregation_metadata?.evaluated_channels?.join(', ') || 'None'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Web Channel Score:</span>
                    <span className="text-slate-200">
                      {lastResult.aggregation_metadata?.web_channel_score !== null
                        ? lastResult.aggregation_metadata.web_channel_score
                        : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Cross-Domain Boost:</span>
                    <span className="text-slate-200">
                      {lastResult.aggregation_metadata?.cross_domain_boost_applied ? 'APPLIED (+0.05)' : 'NO'}
                    </span>
                  </div>
                </div>
              </>
            ) : (
              <div className="h-full flex flex-col items-center justify-center text-center p-8">
                <Cpu className="w-10 h-10 text-slate-600 mb-3" />
                <div className="text-sm font-medium text-slate-300 font-sans">
                  Awaiting Telemetry Input
                </div>
                <div className="text-xs text-slate-500 font-mono mt-1 max-w-xs">
                  Click 'SUBMIT EVENT' to execute live inference across all models and view aggregated risk.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
