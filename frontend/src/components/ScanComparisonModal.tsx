import React, { useState, useEffect } from 'react';
import { X, GitCompare, ArrowRight, CheckCircle, AlertTriangle, TrendingUp, TrendingDown } from 'lucide-react';
import { listScans, compareScans } from '../api';
import { ScanModel, ScanComparisonResult } from '../types';

interface ScanComparisonModalProps {
  onClose: () => void;
  onSelectScan: (scan: ScanModel) => void;
}

export const ScanComparisonModal: React.FC<ScanComparisonModalProps> = ({ onClose, onSelectScan }) => {
  const [scans, setScans] = useState<ScanModel[]>([]);
  const [scanA, setScanA] = useState<string>('');
  const [scanB, setScanB] = useState<string>('');
  const [result, setResult] = useState<ScanComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    listScans().then((data) => {
      setScans(data);
      if (data.length >= 2) {
        setScanA(data[1].id);
        setScanB(data[0].id);
      } else if (data.length === 1) {
        setScanA(data[0].id);
        setScanB(data[0].id);
      }
    });
  }, []);

  const handleCompare = async () => {
    if (!scanA || !scanB) return;
    setLoading(true);
    try {
      const cmp = await compareScans(scanA, scanB);
      setResult(cmp);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#0f172a] border border-slate-800 rounded-2xl shadow-2xl p-6 flex flex-col max-h-[85vh] overflow-hidden">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-indigo-400" />
            <h3 className="text-sm font-bold text-white uppercase font-mono">Scan History & Diff Comparison</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Selection Bar */}
        <div className="my-4 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Baseline Scan A</label>
            <select
              value={scanA}
              onChange={(e) => setScanA(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.target_url}) - {s.summary.security_score}/100
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Target Scan B</label>
            <select
              value={scanB}
              onChange={(e) => setScanB(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.id} ({s.target_url}) - {s.summary.security_score}/100
                </option>
              ))}
            </select>
          </div>
        </div>

        <button
          onClick={handleCompare}
          disabled={loading || !scanA || !scanB}
          className="w-full bg-indigo-600 hover:bg-indigo-500 py-2 rounded-lg text-xs font-bold text-white mb-4 transition-colors"
        >
          {loading ? 'Evaluating Diff...' : 'Run Differential Analysis'}
        </button>

        {/* Comparison Result */}
        {result && (
          <div className="overflow-y-auto space-y-4 text-xs">
            {/* Score delta */}
            <div className="bg-slate-900 p-4 rounded-xl border border-slate-800 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-slate-500 uppercase block">Security Posture Delta</span>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xl font-bold text-slate-300">{result.score_before}</span>
                  <ArrowRight className="w-4 h-4 text-slate-500" />
                  <span className="text-2xl font-black text-white">{result.score_after}</span>
                </div>
              </div>

              <div className="text-right">
                <span
                  className={`text-sm font-bold flex items-center gap-1 ${
                    result.score_improvement >= 0 ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {result.score_improvement >= 0 ? <TrendingUp className="w-4 h-4" /> : <TrendingDown className="w-4 h-4" />}
                  {result.score_improvement >= 0 ? `+${result.score_improvement}` : result.score_improvement} Posture Improvement
                </span>
              </div>
            </div>

            {/* Findings Diff Breakdown */}
            <div className="grid grid-cols-4 gap-2 text-center">
              <div className="bg-rose-500/10 border border-rose-500/20 p-2 rounded-lg">
                <span className="text-lg font-bold text-rose-400 block">{result.summary.new}</span>
                <span className="text-[10px] text-rose-300/80 uppercase">New</span>
              </div>
              <div className="bg-emerald-500/10 border border-emerald-500/20 p-2 rounded-lg">
                <span className="text-lg font-bold text-emerald-400 block">{result.summary.fixed}</span>
                <span className="text-[10px] text-emerald-300/80 uppercase">Fixed</span>
              </div>
              <div className="bg-slate-800 border border-slate-700 p-2 rounded-lg">
                <span className="text-lg font-bold text-slate-300 block">{result.summary.unchanged}</span>
                <span className="text-[10px] text-slate-400 uppercase">Unchanged</span>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/20 p-2 rounded-lg">
                <span className="text-lg font-bold text-amber-400 block">{result.summary.regressed}</span>
                <span className="text-[10px] text-amber-300/80 uppercase">Regressed</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
