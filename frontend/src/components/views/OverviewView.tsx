import React from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Activity,
  ArrowRight,
  Layers,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import { useSecurity } from '../../context/SecurityContext';
import { RiskBadge } from '../RiskBadge';
import type { HistoryItem } from '../../types';

/**
 * Resolves a raw threat string to a valid, non-empty display category label.
 * Maps missing, empty, unavailable, or non-string values to 'UNKNOWN'.
 */
export const resolveCategoryLabel = (rawCategory?: string | null): string => {
  if (!rawCategory || typeof rawCategory !== 'string') {
    return 'UNKNOWN';
  }
  const trimmed = rawCategory.trim();
  if (!trimmed || trimmed.toUpperCase() === 'UNAVAILABLE' || trimmed.toUpperCase() === 'NONE') {
    return 'UNKNOWN';
  }
  return trimmed;
};

/**
 * Resolves category color strictly based on actual classification and severity.
 * - NORMAL and other recognized benign labels: green (#10b981)
 * - CRITICAL attack categories: red (#ef4444)
 * - HIGH attack categories: orange (#f97316)
 * - MEDIUM attack categories: yellow (#eab308)
 * - LOW attack categories: blue (#3b82f6)
 * - UNKNOWN fallback: slate gray (#64748b)
 */
export const getCategoryColor = (categoryName: string, history?: HistoryItem[]): string => {
  const norm = resolveCategoryLabel(categoryName).toUpperCase();

  // 0. UNKNOWN category fallback -> Slate gray
  if (norm === 'UNKNOWN') {
    return '#64748b';
  }

  // 1. NORMAL and other recognized benign labels -> GREEN
  const benignLabels = ['NORMAL', 'BENIGN', 'CLEAN', 'LEGITIMATE', 'SAFE'];
  if (benignLabels.includes(norm)) {
    return '#10b981'; // Green
  }

  // 2. Check actual severity from evaluated session history if available
  if (history && history.length > 0) {
    const matching = history.filter(
      (h) => resolveCategoryLabel(h.response.primary_threat_type).toUpperCase() === norm
    );
    if (matching.length > 0) {
      const levels = matching.map((m) => m.response.risk_level.toUpperCase());
      if (levels.includes('CRITICAL')) return '#ef4444'; // Red
      if (levels.includes('HIGH')) return '#f97316';     // Orange
      if (levels.includes('MEDIUM')) return '#eab308';   // Yellow
      if (levels.includes('LOW')) return '#3b82f6';      // Blue
      if (levels.includes('INFORMATIONAL')) return '#10b981'; // Green
    }
  }

  // 3. Intrinsic threat category taxonomy mapping
  // CRITICAL attack categories -> RED
  const criticalCategories = [
    'CMD_INJECTION',
    'SQLI_ATTEMPT',
    'SQLI_EVASION',
    'SQLMAP',
    'SQLMAP_EVASION',
    'SSRF_ATTEMPT',
    'HTTP_SMUGGLING',
    'LFI_ATTEMPT',
    'LFI_EVASION',
    'ICMP_FLOOD',
    'CRITICAL',
  ];
  if (criticalCategories.some((c) => norm === c || norm.startsWith(c) || c.startsWith(norm))) {
    return '#ef4444'; // Red
  }

  // HIGH attack categories -> ORANGE
  const highCategories = [
    'PATH_TRAVERSAL',
    'CREDENTIAL_STUFFING',
    'WEB_BRUTEFORCE',
    'SLOW_BRUTEFORCE',
    'REFLECTED_XSS',
    'XSS_ATTEMPT',
    'XSS_EVASION',
    'HEADER_INJECTION',
    'HPP_ATTACK',
    'PAYLOAD_ANOMALY',
    'SEQUENTIAL_ATTACK',
    'SYN_SCAN',
    'TCP_SCAN',
    'SLOWLORIS',
    'HIGH',
  ];
  if (highCategories.some((c) => norm === c || norm.startsWith(c) || c.startsWith(norm))) {
    return '#f97316'; // Orange
  }

  // MEDIUM attack categories -> YELLOW
  const mediumCategories = [
    'DIR_ENUM',
    'DIR_FUZZ',
    'WEB_SCAN',
    'UA_ROTATION',
    'UA_SPOOF',
    'MEDIUM',
  ];
  if (mediumCategories.some((c) => norm === c || norm.startsWith(c) || c.startsWith(norm))) {
    return '#eab308'; // Yellow
  }

  // LOW attack categories -> BLUE
  const lowCategories = [
    'WEB_CRAWL',
    'WEB_FINGERPRINT',
    'LOW',
    'INFORMATIONAL',
  ];
  if (lowCategories.some((c) => norm === c || norm.startsWith(c) || c.startsWith(norm))) {
    return '#3b82f6'; // Blue
  }

  // Default fallback for any unspecified attack category -> Orange
  return '#f97316';
};

export const OverviewView: React.FC = () => {
  const { stats, history, setActiveTab, health } = useSecurity();

  // Aggregate categories ensuring every bar has a valid category label derived from primary threat
  const categoryCounts: Record<string, number> = {};
  Object.entries(stats.threatDistribution).forEach(([rawKey, count]) => {
    const label = resolveCategoryLabel(rawKey);
    categoryCounts[label] = (categoryCounts[label] || 0) + count;
  });

  const chartData = Object.entries(categoryCounts).map(([name, value]) => ({
    name,
    value,
  }));

  const recentEvents = history.slice(0, 7);

  return (
    <div className="space-y-6">
      {/* KPI Cards Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Requests */}
        <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Total Analyzed
            </span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-slate-100">
              {stats.totalRequests}
            </span>
            <span className="text-xs text-slate-400 font-mono">requests</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-sans">
            Real-time inference events evaluated
          </div>
        </div>

        {/* Threats Detected */}
        <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Threats Detected
            </span>
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-amber-400">
              {stats.threatsDetected}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              ({stats.totalRequests > 0 ? Math.round((stats.threatsDetected / stats.totalRequests) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-sans">
            Confirmed attack patterns & anomalies
          </div>
        </div>

        {/* Normal Requests */}
        <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Benign / Normal
            </span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <CheckCircle2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-emerald-400">
              {stats.normalRequests}
            </span>
            <span className="text-xs text-slate-400 font-mono">
              ({stats.totalRequests > 0 ? Math.round((stats.normalRequests / stats.totalRequests) * 100) : 0}%)
            </span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-sans">
            Verified safe traffic observations
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Critical Alerts
            </span>
            <div className="w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center justify-center text-red-400">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold font-mono text-red-400">
              {stats.criticalAlerts}
            </span>
            <span className="text-xs text-slate-400 font-mono">high severity</span>
          </div>
          <div className="mt-2 text-xs text-slate-400 font-sans">
            Risk score ≥ 0.80 requiring immediate triage
          </div>
        </div>
      </div>

      {/* Middle Row: Charts and Active Engine Info */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Chart */}
        <div className="lg:col-span-2 bg-[#0c1322] border border-[#1a263d] rounded-xl p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100 font-sans">
                Threat Classification Distribution
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Distribution colored by severity (Green: Normal, Red: Critical, Orange: High, Yellow: Medium, Blue: Low)
              </p>
            </div>
            {/* Color Legend */}
            <div className="flex flex-wrap items-center gap-2.5 text-[10px] font-mono text-slate-400">
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#10b981]" />
                NORMAL
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#ef4444]" />
                CRITICAL
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#f97316]" />
                HIGH
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#eab308]" />
                MEDIUM
              </span>
              <span className="flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-[#3b82f6]" />
                LOW
              </span>
            </div>
          </div>

          {chartData.length > 0 ? (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 10, right: 15, left: -20, bottom: 35 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="name"
                    stroke="#64748b"
                    interval={0}
                    angle={-20}
                    textAnchor="end"
                    height={50}
                    tick={{ fill: '#94a3b8', fontSize: 10 }}
                    tickFormatter={(val: string) => resolveCategoryLabel(val)}
                  />
                  <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 11 }} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                      fontFamily: 'monospace',
                    }}
                    formatter={(value: any, name: any, props: any) => {
                      const catName = resolveCategoryLabel(props?.payload?.name || name);
                      const color = getCategoryColor(catName, history);
                      return [
                        <span style={{ color, fontWeight: 'bold' }}>
                          {value} requests
                        </span>,
                        'Count',
                      ];
                    }}
                  />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {chartData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={getCategoryColor(entry.name, history)}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center border border-dashed border-[#1e293b] rounded-lg text-center p-6">
              <Layers className="w-8 h-8 text-slate-600 mb-2" />
              <div className="text-sm text-slate-300 font-medium">No telemetry data recorded yet</div>
              <div className="text-xs text-slate-500 mt-1 max-w-sm">
                Run a detection test or replay traffic samples to populate threat distribution charts.
              </div>
              <button
                onClick={() => setActiveTab('traffic-analysis')}
                className="mt-4 px-3.5 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs font-mono hover:bg-cyan-500/20 transition-all flex items-center gap-1.5"
              >
                <span>Replay Telemetry Samples</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
        </div>

        {/* Multi-Layer Pipeline Summary */}
        <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 font-sans mb-1">
              Architecture Status
            </h2>
            <p className="text-xs text-slate-400 font-mono mb-4">
              5-Component Multi-Tier Detection
            </p>

            <div className="space-y-3 font-mono text-xs">
              {[
                { name: 'HTTP Classifier', tier: 'App Layer', ok: health?.detectors?.http },
                { name: 'Session Detector', tier: 'Temporal', ok: health?.detectors?.session },
                { name: 'Sequence LSTM', tier: 'Stateful', ok: health?.detectors?.sequence },
                { name: 'Network Flow', tier: 'Transport', ok: health?.detectors?.network },
                { name: 'Autoencoder MSE', tier: 'Payload', ok: health?.detectors?.autoencoder },
              ].map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#0f172a] border border-[#1a2436]"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        item.ok ? 'bg-emerald-400' : 'bg-red-400'
                      }`}
                    />
                    <span className="text-slate-200 font-medium">{item.name}</span>
                  </div>
                  <span className="text-[11px] text-slate-400">{item.tier}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-4 pt-4 border-t border-[#1a263d] flex items-center justify-between">
            <button
              onClick={() => setActiveTab('detector-health')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              <span>View Full Health Diagnostics</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent Detection Events Table */}
      <div className="bg-[#0c1322] border border-[#1a263d] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100 font-sans">
              Recent Detection Events
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Chronological log of evaluated security telemetry
            </p>
          </div>
          {history.length > 0 && (
            <button
              onClick={() => setActiveTab('event-history')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1"
            >
              <span>View All ({history.length})</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {recentEvents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-[#1a263d] text-slate-400">
                  <th className="pb-3 pl-2">TIMESTAMP</th>
                  <th className="pb-3">SOURCE</th>
                  <th className="pb-3">PRIMARY THREAT</th>
                  <th className="pb-3">RISK SCORE</th>
                  <th className="pb-3">SEVERITY</th>
                  <th className="pb-3">CONTRIBUTING</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#162035]">
                {recentEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-[#0f172a]/60 transition-colors">
                    <td className="py-3 pl-2 text-slate-300">{evt.timestamp}</td>
                    <td className="py-3">
                      <span className="px-2 py-0.5 rounded bg-[#162035] text-slate-300 text-[11px]">
                        {evt.source || 'api'}
                      </span>
                    </td>
                    <td className="py-3 font-medium text-slate-100">
                      {resolveCategoryLabel(evt.response.primary_threat_type)}
                    </td>
                    <td className="py-3 font-semibold text-slate-200">
                      {evt.response.overall_risk_score.toFixed(4)}
                    </td>
                    <td className="py-3">
                      <RiskBadge level={evt.response.risk_level} size="sm" />
                    </td>
                    <td className="py-3 text-slate-400">
                      {evt.response.contributing_detectors.length > 0
                        ? evt.response.contributing_detectors.join(', ')
                        : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs font-mono text-slate-500">
            No events recorded in this session. Send an event or replay sample traffic to begin monitoring.
          </div>
        )}
      </div>
    </div>
  );
};
