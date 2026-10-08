import React from 'react';
import { ScanModel } from '../types';
import { AlertTriangle, CheckCircle2, ShieldAlert, Activity, Clock } from 'lucide-react';

interface ScoreCardProps {
  scan: ScanModel | null;
  isScanning: boolean;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({ scan, isScanning }) => {
  const hasCompletedScore = scan?.status === 'completed';
  const score = hasCompletedScore ? scan.summary.security_score : null;
  const sev = scan?.summary.severity_breakdown ?? { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const total = scan?.summary.total_findings ?? 0;

  // Determine score color
  const getScoreColor = (s: number) => {
    if (s >= 80) return { text: 'text-emerald-400', ring: 'border-emerald-500/40', bg: 'bg-emerald-500/10' };
    if (s >= 65) return { text: 'text-yellow-400', ring: 'border-yellow-500/40', bg: 'bg-yellow-500/10' };
    return { text: 'text-rose-400', ring: 'border-rose-500/40', bg: 'bg-rose-500/10' };
  };

  const colors = getScoreColor(score ?? 0);

  return (
    <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
      {/* Active Scan Progress Overlay */}
      {isScanning && (
        <div className="mb-4 bg-indigo-950/40 border border-indigo-500/30 rounded-lg p-3">
          <div className="flex items-center justify-between text-xs mb-1.5">
            <span className="flex items-center gap-2 text-indigo-300 font-semibold">
              <span className="w-2 h-2 rounded-full bg-indigo-400 animate-ping" />
              {scan?.current_phase || 'Active Probing...'}
            </span>
            <span className="font-mono text-indigo-400 font-bold">{scan?.progress || 0}%</span>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div
              className="bg-indigo-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${scan?.progress || 5}%` }}
            />
          </div>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <span className="text-[11px] font-bold tracking-wider text-slate-400 uppercase">SECURITY POSTURE SCORE</span>
          <div className="flex items-baseline gap-2 mt-1">
            <span className={`text-4xl font-black tracking-tight ${score === null ? 'text-slate-400' : colors.text}`}>{score === null ? '--' : score}</span>
            {score !== null && <span className="text-slate-500 text-sm font-semibold">/ 100</span>}
          </div>
          <div className="mt-1">
            <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${colors.bg} ${colors.text} border ${colors.ring}`}>
              {score === null ? (isScanning ? 'ANALYSIS IN PROGRESS' : 'NOT ASSESSED') : score >= 80 ? 'SECURE POSTURE' : score >= 65 ? 'MODERATE RISK' : 'CRITICAL RISK'}
            </span>
          </div>
        </div>

        {/* Circular Gauge Representation */}
        <div className={`w-20 h-20 rounded-full border-4 ${colors.ring} flex items-center justify-center bg-slate-900/60 shadow-inner`}>
          <ShieldAlert className={`w-9 h-9 ${colors.text}`} />
        </div>
      </div>

      {/* Severity Badges Grid */}
      <div className="grid grid-cols-4 gap-2 mt-5 pt-4 border-t border-slate-800/80 text-center">
        <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg py-1.5 px-1">
          <span className="block text-xs font-bold text-rose-400">{sev.critical}</span>
          <span className="text-[10px] text-rose-300/80 uppercase font-medium">Critical</span>
        </div>
        <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg py-1.5 px-1">
          <span className="block text-xs font-bold text-orange-400">{sev.high}</span>
          <span className="text-[10px] text-orange-300/80 uppercase font-medium">High</span>
        </div>
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg py-1.5 px-1">
          <span className="block text-xs font-bold text-yellow-400">{sev.medium}</span>
          <span className="text-[10px] text-yellow-300/80 uppercase font-medium">Medium</span>
        </div>
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg py-1.5 px-1">
          <span className="block text-xs font-bold text-blue-400">{sev.low}</span>
          <span className="text-[10px] text-blue-300/80 uppercase font-medium">Low</span>
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500">
        <span className="flex items-center gap-1">
          <Activity className="w-3 h-3 text-slate-400" /> Total Findings: <strong className="text-slate-300">{total}</strong>
        </span>
        <span className="flex items-center gap-1 font-mono">
          <Clock className="w-3 h-3 text-slate-400" /> {scan ? `${scan.duration_seconds}s` : '0s'}
        </span>
      </div>
    </div>
  );
};
