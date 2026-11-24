import React from 'react';

interface RiskBadgeProps {
  level: string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level, size = 'md' }) => {
  const norm = (level || 'UNKNOWN').toUpperCase();

  const getStyle = () => {
    switch (norm) {
      case 'CRITICAL':
        return 'bg-red-950/70 text-red-400 border-red-800/60 shadow-[0_0_12px_rgba(239,68,68,0.2)]';
      case 'HIGH':
        return 'bg-amber-950/70 text-amber-400 border-amber-800/60 shadow-[0_0_12px_rgba(245,158,11,0.2)]';
      case 'MEDIUM':
        return 'bg-yellow-950/60 text-yellow-400 border-yellow-800/50';
      case 'LOW':
        return 'bg-blue-950/60 text-blue-400 border-blue-800/50';
      case 'INFORMATIONAL':
      case 'NORMAL':
      case 'CLEAN':
      case 'BENIGN':
        return 'bg-emerald-950/60 text-emerald-400 border-emerald-800/50 shadow-[0_0_10px_rgba(16,185,129,0.15)]';
      default:
        return 'bg-slate-900/60 text-slate-400 border-slate-800';
    }
  };

  const getSize = () => {
    switch (size) {
      case 'sm':
        return 'px-2 py-0.5 text-xs';
      case 'lg':
        return 'px-3.5 py-1 text-sm font-semibold';
      case 'md':
      default:
        return 'px-2.5 py-0.5 text-xs font-medium';
    }
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border tracking-wide uppercase font-mono ${getStyle()} ${getSize()}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current opacity-80 animate-pulse" />
      {norm}
    </span>
  );
};
