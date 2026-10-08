import React, { useState } from 'react';
import { FindingModel } from '../types';
import { Search, Filter, ShieldCheck, AlertCircle, ChevronRight, Layers } from 'lucide-react';

interface FindingsTableProps {
  findings: FindingModel[];
  onSelectFinding: (finding: FindingModel) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({ findings, onSelectFinding }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [minConfidence, setMinConfidence] = useState<number>(0);

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      f.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (f.parameter && f.parameter.toLowerCase().includes(searchTerm.toLowerCase())) ||
      f.type.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    const matchesConfidence = f.confidence >= minConfidence;

    return matchesSearch && matchesSeverity && matchesConfidence;
  });

  return (
    <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-5 shadow-lg">
      {/* Header and Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          <h3 className="text-xs font-bold tracking-wider text-slate-300 uppercase">
            DETAILED VULNERABILITY FINDINGS ({filtered.length})
          </h3>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search bar */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings, params, endpoints..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900 border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-56"
            />
          </div>

          {/* Severity Filters */}
          <div className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-lg border border-slate-800">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`text-[10px] font-bold px-2 py-1 rounded transition-colors ${
                  selectedSeverity === sev
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-slate-800/80">
        <table className="w-full text-left text-xs">
          <thead className="bg-[#0b0f19] text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Vulnerability Finding</th>
              <th className="py-3 px-4">Target Endpoint</th>
              <th className="py-3 px-4">Param</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Risk</th>
              <th className="py-3 px-4">Standard</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-8 text-slate-500">
                  No vulnerability findings match the current criteria.
                </td>
              </tr>
            ) : (
              filtered.map((f) => {
                const sevBadge = {
                  CRITICAL: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
                  HIGH: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
                  MEDIUM: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
                  LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
                  INFORMATIONAL: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
                }[f.severity] || 'bg-slate-500/10 text-slate-400';

                return (
                  <tr
                    key={f.finding_id}
                    onClick={() => onSelectFinding(f)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 px-4">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${sevBadge}`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-200 group-hover:text-indigo-300">
                      {f.title}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 truncate max-w-[200px]">
                      {f.target}
                    </td>
                    <td className="py-3 px-4 font-mono text-indigo-400">
                      {f.parameter || '-'}
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-slate-300">
                      {f.confidence}%
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                        {f.validation_status}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono font-bold text-rose-400">
                      {f.risk_score}/10
                    </td>
                    <td className="py-3 px-4 text-slate-400 font-mono text-[11px]">
                      {f.cwe.id || f.owasp.id}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <span className="text-slate-500 group-hover:text-indigo-400 font-mono text-[11px] flex items-center justify-end gap-1">
                        Inspect <ChevronRight className="w-3.5 h-3.5" />
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
