import React from 'react';
import { VulnerabilityCorrelation } from '../types';
import { Network, AlertTriangle } from 'lucide-react';

interface CorrelationViewProps {
  correlations: VulnerabilityCorrelation[];
}

export const CorrelationView: React.FC<CorrelationViewProps> = ({ correlations }) => {
  if (correlations.length === 0) return null;

  return (
    <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex items-center gap-2 mb-3">
        <Network className="w-4 h-4 text-purple-400" />
        <h3 className="text-xs font-bold tracking-wider text-slate-300 uppercase">
          VULNERABILITY CORRELATIONS & COMPOUND ATTACK SURFACE
        </h3>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {correlations.map((corr) => (
          <div
            key={corr.correlation_id}
            className="bg-purple-950/20 border border-purple-500/30 rounded-xl p-4 flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[11px] font-mono font-bold text-purple-400 px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20">
                  {corr.relationship_type}
                </span>
                <span className="text-xs font-bold text-rose-400 font-mono">
                  Compounded Risk: {corr.compounded_risk_score}/10
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed mt-2">{corr.reason}</p>
            </div>

            <div className="mt-3 pt-2.5 border-t border-purple-500/20 flex items-center justify-between text-[11px] text-slate-400 font-mono">
              <span>Findings Involved: <strong>{corr.findings_involved.length}</strong></span>
              <span>Correlation Confidence: <strong className="text-purple-300">{corr.confidence}%</strong></span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
