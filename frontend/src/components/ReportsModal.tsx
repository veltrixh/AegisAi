import React from 'react';
import { X, Download, FileText, Code2, Globe, Shield } from 'lucide-react';
import { getReportDownloadUrl } from '../api';
import { ScanModel } from '../types';

interface ReportsModalProps {
  scan: ScanModel | null;
  onClose: () => void;
}

export const ReportsModal: React.FC<ReportsModalProps> = ({ scan, onClose }) => {
  if (!scan) return null;

  const formats = [
    {
      id: 'sarif',
      name: 'SARIF 2.1.0 (OASIS)',
      desc: 'Standardized format for GitHub Advanced Security, GitLab CI/CD, and DevSecOps pipelines.',
      icon: Code2,
      color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20'
    },
    {
      id: 'html',
      name: 'Interactive HTML Report',
      desc: 'Standalone, self-contained executive report with dark console design, charts, and evidence cards.',
      icon: Globe,
      color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
    },
    {
      id: 'pdf',
      name: 'Executive PDF Report',
      desc: 'Print-ready security assessment document with executive tables, risk rankings, and remediation.',
      icon: FileText,
      color: 'text-sky-400 bg-sky-500/10 border-sky-500/20'
    },
    {
      id: 'json',
      name: 'Raw JSON Assessment Model',
      desc: 'Complete structured JSON dump containing findings, attack paths, correlations, and evidence.',
      icon: Shield,
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/20'
    }
  ];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-xl bg-[#0f172a] border border-slate-800 rounded-2xl shadow-2xl p-6">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Download className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold text-white uppercase font-mono">Export Assessment Reports</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-xs text-slate-400 my-3">
          Download security assessment results for scan <code className="text-indigo-300">{scan.id}</code> ({scan.target_url}):
        </p>

        <div className="space-y-3 my-4">
          {formats.map((fmt) => {
            const Icon = fmt.icon;
            const downloadUrl = getReportDownloadUrl(scan.id, fmt.id);

            return (
              <a
                key={fmt.id}
                href={downloadUrl}
                download
                target="_blank"
                rel="noreferrer"
                className="group flex items-center justify-between p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-850 transition-all cursor-pointer block"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-9 h-9 rounded-lg border flex items-center justify-center ${fmt.color}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div>
                    <strong className="text-xs text-slate-200 group-hover:text-indigo-300 block">{fmt.name}</strong>
                    <span className="text-[11px] text-slate-400">{fmt.desc}</span>
                  </div>
                </div>

                <Download className="w-4 h-4 text-slate-500 group-hover:text-indigo-400 shrink-0 ml-2" />
              </a>
            );
          })}
        </div>
      </div>
    </div>
  );
};
