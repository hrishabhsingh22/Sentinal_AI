import React, { useState } from 'react';
import {
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  Radio,
  Layers,
  Activity,
  ArrowRight,
  Shield,
  Zap,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { TELEMETRY_SAMPLES } from '../../data/samples';
import { TelemetrySample } from '../../types';
import { RiskBadge } from '../RiskBadge';

export const TrafficAnalysisView: React.FC = () => {
  const { evaluateEvent, isEvaluating } = useSecurity();
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null);
  const [isBatchRunning, setIsBatchRunning] = useState<boolean>(false);
  const [batchProgress, setBatchProgress] = useState<{ current: number; total: number } | null>(null);

  const filteredSamples = TELEMETRY_SAMPLES.filter((s) => {
    if (selectedCategory === 'ALL') return true;
    if (selectedCategory === 'NORMAL') return s.category === 'NORMAL';
    if (selectedCategory === 'ATTACK') return s.category !== 'NORMAL';
    return s.category === selectedCategory;
  });

  const handleReplaySample = async (sample: TelemetrySample) => {
    setActiveSampleId(sample.id);
    await evaluateEvent(sample.payload, sample.name, sample.source);
    setActiveSampleId(null);
  };

  const handleReplayAll = async () => {
    setIsBatchRunning(true);
    setBatchProgress({ current: 0, total: filteredSamples.length });

    for (let i = 0; i < filteredSamples.length; i++) {
      const sample = filteredSamples[i];
      setActiveSampleId(sample.id);
      setBatchProgress({ current: i + 1, total: filteredSamples.length });
      await evaluateEvent(sample.payload, sample.name, sample.source);
      // Small natural delay between telemetry packets
      await new Promise((resolve) => setTimeout(resolve, 400));
    }

    setActiveSampleId(null);
    setIsBatchRunning(false);
    setBatchProgress(null);
  };

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h2 className="text-base font-semibold text-slate-100 font-sans">
              Telemetry Traffic Replay
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Inject authentic SOC-MLD benchmark telemetry records into the live hybrid aggregator
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Category Filter */}
          <div className="flex items-center rounded-lg bg-[#0f172a] border border-[#1e293b] p-0.5 text-xs font-mono">
            {['ALL', 'NORMAL', 'ATTACK'].map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-md transition-all ${
                  selectedCategory === cat
                    ? 'bg-cyan-500/20 text-cyan-300 font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>

          {/* Replay Batch Button */}
          <button
            onClick={handleReplayAll}
            disabled={isBatchRunning || isEvaluating}
            className={`px-4 py-2 rounded-lg font-mono text-xs font-medium flex items-center gap-2 transition-all ${
              isBatchRunning || isEvaluating
                ? 'bg-cyan-950 text-cyan-400/50 cursor-not-allowed border border-cyan-800/40'
                : 'bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)]'
            }`}
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span>
              {isBatchRunning
                ? `REPLAYING (${batchProgress?.current}/${batchProgress?.total})...`
                : `REPLAY ALL (${filteredSamples.length})`}
            </span>
          </button>
        </div>
      </div>

      {/* Samples Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filteredSamples.map((sample) => {
          const isCurrent = activeSampleId === sample.id;
          const isAttack = sample.category !== 'NORMAL';

          return (
            <div
              key={sample.id}
              className={`bg-[#0c1322] border rounded-xl p-5 flex flex-col justify-between transition-all ${
                isCurrent
                  ? 'border-cyan-500 shadow-[0_0_15px_rgba(6,182,212,0.25)] bg-[#0f192d]'
                  : 'border-[#1a263d] hover:border-[#2a3a5a]'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded-full border ${
                      isAttack
                        ? 'bg-red-950/70 text-red-400 border-red-800/60'
                        : 'bg-emerald-950/70 text-emerald-400 border-emerald-800/60'
                    }`}
                  >
                    {sample.category}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">
                    SRC: {sample.source}
                  </span>
                </div>

                <h3 className="text-sm font-semibold text-slate-100 font-sans mt-2">
                  {sample.name}
                </h3>
                <p className="text-xs text-slate-400 mt-1 line-clamp-2 leading-relaxed">
                  {sample.description}
                </p>

                <div className="mt-3 pt-3 border-t border-[#162138] flex items-center justify-between text-[11px] font-mono text-slate-400">
                  <span>Ground Truth:</span>
                  <span className="text-slate-200 font-medium">{sample.groundTruth}</span>
                </div>
              </div>

              <div className="mt-4 pt-3 flex items-center justify-between border-t border-[#162138]">
                <span className="text-[10px] font-mono text-slate-500">
                  {sample.payload.session_history
                    ? `${sample.payload.session_history.length} Requests`
                    : '1 Request'}
                </span>
                <button
                  onClick={() => handleReplaySample(sample)}
                  disabled={isBatchRunning || isEvaluating}
                  className="px-3 py-1.5 rounded-lg bg-[#142036] hover:bg-cyan-500/20 text-slate-200 hover:text-cyan-300 border border-[#223352] hover:border-cyan-500/50 text-xs font-mono transition-all flex items-center gap-1.5"
                >
                  <Play className="w-3 h-3 fill-current" />
                  <span>Replay</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
