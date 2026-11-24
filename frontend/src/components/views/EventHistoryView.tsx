import React, { useState } from 'react';
import {
  History,
  Trash2,
  Search,
  Filter,
  Eye,
  FileCode,
  X,
  ExternalLink,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';
import { RiskBadge } from '../RiskBadge';
import { HistoryItem } from '../../types';

export const EventHistoryView: React.FC = () => {
  const { history, clearHistory } = useSecurity();
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<HistoryItem | null>(null);

  const filteredHistory = history.filter((item) => {
    const matchesSearch =
      searchTerm === '' ||
      item.response.primary_threat_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (item.label && item.label.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (item.source && item.source.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesSeverity =
      severityFilter === 'ALL' || item.response.risk_level === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Header & Controls */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <History className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-semibold text-slate-100 font-sans">
              Session Event Audit Log
            </h2>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time audit history of all telemetry events evaluated in this active session
          </p>
        </div>

        <div className="flex items-center gap-3">
          {history.length > 0 && (
            <button
              onClick={clearHistory}
              className="px-3 py-1.5 rounded-lg bg-red-950/40 hover:bg-red-900/50 text-red-300 border border-red-800/40 text-xs font-mono transition-all flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear Log</span>
            </button>
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Search */}
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter by threat type or label..."
            className="w-full bg-[#080d18] border border-[#1e293b] rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2 w-full sm:w-auto">
          <span className="text-xs font-mono text-slate-500 flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" />
            Severity:
          </span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#080d18] border border-[#1e293b] rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">ALL LEVELS</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="INFORMATIONAL">INFORMATIONAL</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5">
        {filteredHistory.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-[#1a263d] text-slate-400">
                  <th className="pb-3 pl-2">TIMESTAMP</th>
                  <th className="pb-3">EVENT LABEL</th>
                  <th className="pb-3">SOURCE</th>
                  <th className="pb-3">PRIMARY THREAT</th>
                  <th className="pb-3">SCORE</th>
                  <th className="pb-3">SEVERITY</th>
                  <th className="pb-3">CONTRIBUTING</th>
                  <th className="pb-3">LATENCY</th>
                  <th className="pb-3 text-right pr-2">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#162035]">
                {filteredHistory.map((item) => (
                  <tr key={item.id} className="hover:bg-[#0f172a]/60 transition-colors">
                    <td className="py-3 pl-2 text-slate-300">{item.timestamp}</td>
                    <td className="py-3 text-slate-200 font-medium">
                      {item.label || '—'}
                    </td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded bg-[#162035] text-slate-300 text-[11px]">
                        {item.source}
                      </span>
                    </td>
                    <td className="py-3 font-semibold text-slate-100">
                      {item.response.primary_threat_type}
                    </td>
                    <td className="py-3 font-semibold text-slate-200">
                      {item.response.overall_risk_score.toFixed(4)}
                    </td>
                    <td className="py-3">
                      <RiskBadge level={item.response.risk_level} size="sm" />
                    </td>
                    <td className="py-3 text-slate-400">
                      {item.response.contributing_detectors.length > 0
                        ? item.response.contributing_detectors.join(', ')
                        : '—'}
                    </td>
                    <td className="py-3 text-slate-400">
                      {item.latencyMs ? `${item.latencyMs}ms` : '—'}
                    </td>
                    <td className="py-3 text-right pr-2">
                      <button
                        onClick={() => setSelectedEvent(item)}
                        className="px-2.5 py-1 rounded bg-[#152033] hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-[#223048] hover:border-cyan-500/40 text-[11px] transition-all flex items-center gap-1 ml-auto"
                      >
                        <Eye className="w-3 h-3" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-xs font-mono text-slate-500">
            {history.length === 0
              ? 'No events in current session. Submit an event or run traffic replay to generate audit entries.'
              : 'No events match the selected filters.'}
          </div>
        )}
      </div>

      {/* Inspect Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0c1322] border border-[#1e2a44] rounded-2xl w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-5 border-b border-[#1a263d] flex items-center justify-between bg-[#080d18]">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-slate-100 font-sans">
                    Event Diagnostics ({selectedEvent.id})
                  </h3>
                  <RiskBadge level={selectedEvent.response.risk_level} size="sm" />
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Logged at {selectedEvent.timestamp} • Latency: {selectedEvent.latencyMs || '—'}ms
                </p>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg bg-[#0f172a] hover:bg-[#1a263d] transition-all"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-4 font-mono text-xs">
              <div>
                <div className="text-[11px] text-slate-400 uppercase mb-1">
                  API Response Payload
                </div>
                <pre className="bg-[#070b14] p-3.5 rounded-xl border border-[#162035] text-cyan-300 overflow-x-auto text-[11px] leading-relaxed">
                  {JSON.stringify(selectedEvent.response, null, 2)}
                </pre>
              </div>

              <div>
                <div className="text-[11px] text-slate-400 uppercase mb-1">
                  Submitted Request Telemetry
                </div>
                <pre className="bg-[#070b14] p-3.5 rounded-xl border border-[#162035] text-slate-300 overflow-x-auto text-[11px] leading-relaxed">
                  {JSON.stringify(selectedEvent.request, null, 2)}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-[#1a263d] bg-[#080d18] flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-[#152033] hover:bg-[#1f2f4a] text-slate-200 text-xs font-mono transition-all"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
