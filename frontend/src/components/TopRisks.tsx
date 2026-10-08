import React from 'react';
import { FindingModel } from '../types';
import { AlertCircle, ChevronRight, Zap } from 'lucide-react';

interface TopRisksProps {
  findings: FindingModel[];
  onSelectFinding: (finding: FindingModel) => void;
}

export const TopRisks: React.FC<TopRisksProps> = ({ findings, onSelectFinding }) => {
  const sortedRisks = [...findings].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

  return (
    <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-3.5">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h3 className="text-xs font-bold tracking-wider text-slate-300 uppercase">PRIORITIZED TOP RISKS</h3>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">DETERMINISTIC RANKING</span>
        </div>

        {sortedRisks.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs">
            No active high-risk vulnerabilities identified in current scan.
          </div>
        ) : (
          <div className="space-y-2">
            {sortedRisks.map((finding) => {
              const sevBadge = {
                CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
                HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
                MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
                LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
                INFORMATIONAL: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
              }[finding.severity] || 'bg-slate-500/10 text-slate-400';

              return (
                <div
                  key={finding.finding_id}
                  onClick={() => onSelectFinding(finding)}
                  className="group flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-all"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${sevBadge}`}>
                      {finding.severity}
                    </span>
                    <div className="truncate">
                      <div className="text-xs font-semibold text-slate-200 group-hover:text-indigo-300 truncate">
                        {finding.title}
                      </div>
                      <div className="text-[11px] text-slate-500 font-mono truncate">
                        {finding.parameter ? `param: ${finding.parameter}` : finding.target}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 ml-2">
                    <div className="text-right">
                      <div className="text-xs font-black text-rose-400">
                        {finding.risk_score} <span className="text-[10px] text-slate-500 font-normal">/ 10</span>
                      </div>
                      <div className="text-[10px] text-slate-400 font-mono">
                        {finding.confidence}% conf
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-indigo-400 transition-colors" />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="mt-3 pt-2 text-[11px] text-slate-500 border-t border-slate-800/60 flex items-center justify-between">
        <span>Click any risk item to inspect evidence</span>
        <span>CVSS 3.1 Grounded</span>
      </div>
    </div>
  );
};
