import React from 'react';
import {
  HeartPulse,
  RefreshCw,
  Info,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

export const DetectorHealthView: React.FC = () => {
  const { health, refreshHealth, lastResult } = useSecurity();

  const detectors = [
    {
      id: 'http',
      name: 'HTTP Classifier',
      modelType: 'Multi-Class Random Forest (27 Classes)',
      artifactPath: 'models/http/http_classifier.joblib',
      artifactStatus: health?.detectors?.http,
      featureRequirement: '26 Features (11 Payload + 10 Window + 5 Session)',
      evaluationCapability:
        'Evaluates Nginx web observations. Computes threat score as 1 - P(NORMAL). Requires benign class in probabilities.',
      operationalNotes:
        'Trained on 26 attack classes + 1 NORMAL class. Calibrated threat threshold 0.50.',
    },
    {
      id: 'session',
      name: 'Session Detector',
      modelType: 'Temporal Random Forest (27 Classes)',
      artifactPath: 'models/session/session_classifier.joblib',
      artifactStatus: health?.detectors?.session,
      featureRequirement: '15 Session-Level Temporal & Frequency Metrics',
      evaluationCapability:
        'Evaluates session request rates, duration, and error frequencies. Corroborates web channel signals.',
      operationalNotes:
        'Trained on multi-class session behavior. Dampened via correlation factor (γ = 0.35) against HTTP classifier.',
    },
    {
      id: 'sequence',
      name: 'Sequence LSTM',
      modelType: 'Stacked Sequence LSTM (11-Feature Timesteps)',
      artifactPath: 'models/sequence/sequence_lstm_v2.keras',
      artifactStatus: health?.detectors?.sequence,
      featureRequirement: '11 Features per request in chronological session history',
      evaluationCapability:
        'Strictly requires chronological session history. Validates all 11 features on every record with post-padding (-999.0, max 99).',
      operationalNotes:
        'Evaluates stateful attack progression across consecutive requests. Decision threshold: 0.50 (loaded from the saved sequence evaluation metrics).',
    },
    {
      id: 'network',
      name: 'Network Detector',
      modelType: 'Flow-Level Random Forest (5 Classes)',
      artifactPath: 'models/network/network_classifier.joblib',
      artifactStatus: health?.detectors?.network,
      featureRequirement: '23 Features (15 Base CSV + 8 Flow Engineered)',
      evaluationCapability:
        'Evaluates Suricata alert and flow telemetry. Marks threat scoring UNAVAILABLE when benign probability cannot be established reliably.',
      operationalNotes:
        'Closed-world classifier trained on 5 attack classes (ICMP_FLOOD, SYN_SCAN, TCP_SCAN, WEB_BRUTEFORCE, WEB_SCAN).',
    },
    {
      id: 'autoencoder',
      name: 'Autoencoder Payload Anomaly',
      modelType: 'Deep Autoencoder Unsupervised MSE',
      artifactPath: 'models/autoencoder.keras',
      artifactStatus: health?.detectors?.autoencoder,
      featureRequirement: '12 Payload Features or raw path/query/body',
      evaluationCapability:
        'Calculates continuous reconstruction loss. Smoothly calibrated into [0.0, 1.0] normalized score around decision threshold.',
      operationalNotes:
        'Trained exclusively on benign payload structures. Decision threshold: 0.0003149.',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <HeartPulse className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-semibold text-slate-100 font-sans">
              Detector Architecture Diagnostics
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time status of 5 specialized detection models across operational channels
          </p>
        </div>

        <button
          onClick={() => refreshHealth()}
          className="px-3.5 py-1.5 rounded-lg bg-[#0f172a] hover:bg-[#152238] border border-[#1e293b] text-xs font-mono text-slate-300 hover:text-cyan-300 transition-all flex items-center gap-2"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Artifacts</span>
        </button>
      </div>

      {/* Explanatory Distinction Banner */}
      <div className="bg-[#0c1629] border border-cyan-900/40 rounded-xl p-4 flex items-start gap-3 text-xs font-mono">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1 text-slate-300 leading-relaxed">
          <span className="font-semibold text-cyan-300">Architecture Availability Note:</span>{' '}
          <strong className="text-slate-100">Artifact Availability</strong> confirms the trained neural network or ensemble weights are present on disk. In contrast,{' '}
          <strong className="text-slate-100">Event Evaluation Capability</strong> indicates whether a specific telemetry event supplies the necessary schema (e.g. valid session history for Sequence LSTM, or calibrated benign probabilities for Network Flow).
        </div>
      </div>

      {/* 5 Detectors Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {detectors.map((det) => {
          const evalResult = lastResult?.detector_results?.[det.id];
          const isArtifactOk = det.artifactStatus === true;

          return (
            <div
              key={det.id}
              className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col justify-between"
            >
              <div>
                {/* Header */}
                <div className="flex items-center justify-between pb-3 border-b border-[#162138]">
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`w-2.5 h-2.5 rounded-full ${
                        isArtifactOk ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-red-400 shadow-[0_0_8px_#f87171]'
                      }`}
                    />
                    <h3 className="text-sm font-semibold text-slate-100 font-sans">
                      {det.name}
                    </h3>
                  </div>

                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${
                      isArtifactOk
                        ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50'
                        : 'bg-red-950/60 text-red-300 border-red-800/50'
                    }`}
                  >
                    {isArtifactOk ? 'ARTIFACT LOADED' : 'ARTIFACT MISSING'}
                  </span>
                </div>

                {/* Details */}
                <div className="mt-4 space-y-3 font-mono text-xs">
                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">Architecture</div>
                    <div className="text-slate-300 mt-0.5 font-medium">{det.modelType}</div>
                  </div>

                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">Artifact Path</div>
                    <div className="text-slate-400 mt-0.5 text-[11px] bg-[#070b14] px-2 py-1 rounded border border-[#162035] break-all">
                      {det.artifactPath}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">Schema & Preconditions</div>
                    <div className="text-slate-300 mt-0.5 text-[11px] leading-relaxed">
                      {det.featureRequirement}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-slate-500 uppercase">Evaluation Capability</div>
                    <div className="text-slate-400 mt-0.5 text-[11px] leading-relaxed">
                      {det.evaluationCapability}
                    </div>
                  </div>
                </div>
              </div>

              {/* Latest Event Evaluation Pill */}
              <div className="mt-4 pt-3 border-t border-[#162138] flex items-center justify-between text-xs font-mono">
                <span className="text-[11px] text-slate-500">Last Telemetry Run:</span>
                {evalResult ? (
                  <span
                    className={`text-[11px] px-2 py-0.5 rounded border ${
                      evalResult.available
                        ? 'bg-blue-950/60 text-blue-300 border-blue-800/40'
                        : 'bg-slate-900 text-slate-400 border-slate-700/50'
                    }`}
                  >
                    {evalResult.available ? `EVALUATED (${evalResult.threat_score?.toFixed(4)})` : 'SKIPPED / UNAVAILABLE'}
                  </span>
                ) : (
                  <span className="text-[11px] text-slate-500">Awaiting evaluation</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
