import React from 'react';
import {
  ShieldAlert,
  Layers,
  HeartPulse,
  History,
  Settings,
  Radio,
  Lock,
} from 'lucide-react';
import { useSecurity, type TabType } from '../context/SecurityContext';

export const Sidebar: React.FC = () => {
  const { activeTab, setActiveTab, stats, health } = useSecurity();

  const navItems: { id: TabType; label: string; icon: React.ElementType; badge?: number | string }[] = [
    { id: 'overview', label: 'Overview', icon: Layers },
    { id: 'threat-detection', label: 'Threat Detection', icon: ShieldAlert, badge: stats.threatsDetected > 0 ? stats.threatsDetected : undefined },
    { id: 'traffic-analysis', label: 'Traffic Analysis', icon: Radio },
    { id: 'detector-health', label: 'Detector Health', icon: HeartPulse, badge: health?.status === 'healthy' ? 'OK' : 'CHECK' },
    { id: 'event-history', label: 'Event History', icon: History, badge: stats.totalRequests > 0 ? stats.totalRequests : undefined },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-[#1a2333] flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#1a2333] flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-indigo-500/20 to-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
          <Lock className="w-5 h-5 text-cyan-400" />
        </div>
        <div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-base tracking-wider text-slate-100 font-mono">
              SENTINEL<span className="text-cyan-400">.AI</span>
            </span>
          </div>
          <div className="text-[11px] text-slate-400 tracking-wider uppercase font-medium">
            SOC Threat Defense
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <div className="px-3 py-2 text-[10px] font-mono tracking-widest text-slate-400 uppercase">
          Core Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all duration-150 ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(6,182,212,0.1)]'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#111928] border border-transparent'
              }`}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-cyan-400' : 'text-slate-400'
                  }`}
                />
                <span className="font-sans text-[13px]">{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                    isActive
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : item.badge === 'CHECK'
                      ? 'bg-amber-950/70 text-amber-400 border border-amber-800/60'
                      : 'bg-[#152033] text-slate-400 border border-[#223048]'
                  }`}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer System Telemetry Status */}
      <div className="p-4 border-t border-[#1a2333] bg-[#070b14]/70">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                health?.status === 'healthy'
                  ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]'
                  : health?.status === 'degraded'
                  ? 'bg-amber-400 shadow-[0_0_8px_#fbbf24]'
                  : 'bg-red-400 shadow-[0_0_8px_#f87171]'
              }`}
            />
            <span className="text-xs text-slate-300 font-mono">Backend Engine</span>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            {health?.status ? health.status.toUpperCase() : 'CONNECTING'}
          </span>
        </div>
        <div className="text-[11px] text-slate-400 font-mono truncate">
          v{health?.version || '1.0.0'} • Hybrid Risk Fusion
        </div>
      </div>
    </aside>
  );
};
