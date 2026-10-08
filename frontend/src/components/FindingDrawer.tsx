import React, { useState } from 'react';
import { FindingModel } from '../types';
import {
  X,
  Shield,
  FileSearch,
  Sparkles,
  GitBranch,
  Wrench,
  BookOpen,
  CheckCircle2,
  Copy,
  Check,
  AlertTriangle
} from 'lucide-react';

interface FindingDrawerProps {
  finding: FindingModel | null;
  onClose: () => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({ finding, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'evidence' | 'xai' | 'attack_path' | 'remediation' | 'references'>('overview');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [activeLang, setActiveLang] = useState<'python' | 'javascript' | 'java' | 'php'>('python');

  if (!finding) return null;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(label);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const ev = finding.evidence;
  const xai = finding.ai_explanation;
  const rem = finding.remediation;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end animate-in fade-in duration-200">
      <div className="w-full max-w-3xl bg-[#0f172a] border-l border-slate-800 h-full flex flex-col shadow-2xl">
        {/* Drawer Header */}
        <div className="p-5 border-b border-slate-800 bg-[#131b2e] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span
              className={`text-xs font-bold px-2 py-0.5 rounded border ${
                finding.severity === 'CRITICAL'
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  : finding.severity === 'HIGH'
                  ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                  : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
              }`}
            >
              {finding.severity}
            </span>
            <div>
              <h2 className="text-base font-bold text-white">{finding.title}</h2>
              <div className="text-xs text-slate-400 font-mono">
                {finding.method} {finding.target} {finding.parameter && `| param: ${finding.parameter}`}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 px-5 py-2.5 border-b border-slate-800 bg-[#0d1424] overflow-x-auto text-xs">
          {[
            { id: 'overview', label: 'Overview', icon: Shield },
            { id: 'evidence', label: 'Evidence', icon: FileSearch },
            { id: 'xai', label: 'Explainable AI', icon: Sparkles },
            { id: 'attack_path', label: 'Attack Path', icon: GitBranch },
            { id: 'remediation', label: 'Remediation', icon: Wrench },
            { id: 'references', label: 'References', icon: BookOpen }
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-semibold transition-colors shrink-0 ${
                  isActive
                    ? 'bg-indigo-600 text-white shadow'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6 text-sm text-slate-300">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500 block">Risk Score</span>
                  <span className="text-xl font-bold text-rose-400">{finding.risk_score} / 10</span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500 block">Confidence</span>
                  <span className="text-xl font-bold text-indigo-400">{finding.confidence}%</span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500 block">Validation Status</span>
                  <span className="text-sm font-bold text-emerald-400">{finding.validation_status}</span>
                </div>
                <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                  <span className="text-[10px] uppercase font-mono text-slate-500 block">CVSS v3.1</span>
                  <span className="text-xl font-bold text-amber-400">{finding.cvss}</span>
                </div>
              </div>

              <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4">
                <h4 className="text-xs font-bold uppercase text-slate-400 mb-2 font-mono">STANDARDS MAPPING</h4>
                <div className="space-y-1.5 text-xs font-mono">
                  <div>OWASP: <strong className="text-white">{finding.owasp.id} - {finding.owasp.name}</strong></div>
                  <div>CWE: <strong className="text-white">{finding.cwe.id} - {finding.cwe.name}</strong></div>
                  <div>CVSS Vector: <code className="text-indigo-300 bg-slate-950 px-2 py-0.5 rounded">{finding.cvss_vector}</code></div>
                </div>
              </div>

              {xai && (
                <div className="bg-slate-900/80 border border-indigo-500/20 rounded-lg p-4">
                  <h4 className="text-xs font-bold text-indigo-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5" /> IMPACT ASSESSMENT
                  </h4>
                  <p className="text-xs leading-relaxed text-slate-200">{xai.impact_assessment}</p>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              <div className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-xs">
                <h4 className="font-bold text-slate-300 uppercase tracking-wider mb-3 font-mono">DETERMINISTIC EVIDENCE SUMMARY</h4>
                <div className="grid grid-cols-2 gap-3 text-slate-300 font-mono">
                  <div>Baseline Length: <strong>{ev.baseline_response_length} bytes</strong></div>
                  <div>Test Length: <strong>{ev.test_response_length} bytes (delta {ev.length_diff > 0 ? `+${ev.length_diff}` : ev.length_diff}B)</strong></div>
                  <div>Status Changed: <strong className={ev.status_code_changed ? 'text-amber-400' : 'text-slate-400'}>{String(ev.status_code_changed)} ({ev.baseline_status_code} {'->'} {ev.test_status_code})</strong></div>
                  <div>Timing Changed: <strong>{String(ev.response_time_changed)} ({ev.test_time_ms}ms)</strong></div>
                  <div>Payloads Tested: <strong>{ev.payloads_tested}</strong></div>
                  <div>Reproducible: <strong className="text-emerald-400">{String(ev.reproducible)} ({ev.reproduction_count}x verified)</strong></div>
                  {ev.error_signature && (
                    <div className="col-span-2 text-rose-400">
                      Signature Detected: <strong>{ev.error_signature}</strong>
                    </div>
                  )}
                </div>
              </div>

              {ev.response?.snippet && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-mono">SANITIZED RESPONSE SNIPPET</h4>
                  <pre className="bg-[#090d16] border border-slate-800 p-3 rounded-lg text-xs font-mono text-sky-400 overflow-x-auto whitespace-pre-wrap max-h-56">
                    {ev.response.snippet}
                  </pre>
                </div>
              )}

              {ev.request && (
                <div>
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-mono">SANITIZED REQUEST DATA</h4>
                  <pre className="bg-[#090d16] border border-slate-800 p-3 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto max-h-48">
                    {JSON.stringify(ev.request, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: EXPLAINABLE AI */}
          {activeTab === 'xai' && xai && (
            <div className="space-y-4">
              <div className="bg-indigo-950/20 border border-indigo-500/30 rounded-lg p-4">
                <h4 className="text-xs font-bold text-indigo-300 uppercase tracking-wider mb-2 flex items-center gap-1.5 font-mono">
                  <Sparkles className="w-3.5 h-3.5" /> WHY WAS THIS DETECTED?
                </h4>
                <p className="text-xs leading-relaxed text-slate-200 whitespace-pre-line">{xai.why_detected}</p>
              </div>

              <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 font-mono">CONFIDENCE FACTORS BREAKDOWN</h4>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
                  {Object.entries(xai.evidence_factors).map(([k, v]) => (
                    <div key={k} className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <span className="text-[10px] text-slate-500 uppercase font-mono block">{k.replace('_', ' ')}</span>
                      <span className="text-base font-bold text-indigo-400">{Number(v) * 100}%</span>
                    </div>
                  ))}
                </div>
                <div className="mt-3 text-xs text-indigo-300/80 font-mono">{xai.confidence_narrative}</div>
              </div>

              <div className="bg-slate-900/60 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 font-mono">DETECTION LOGIC</h4>
                <p className="text-xs text-slate-300">{xai.detection_logic}</p>
              </div>
            </div>
          )}

          {/* TAB 4: ATTACK PATH */}
          {activeTab === 'attack_path' && (
            <div className="space-y-4">
              <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 font-mono">ATTACK TRAJECTORY</h4>
                <div className="space-y-3">
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded-full bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold text-xs">1</span>
                    <div>
                      <strong className="text-white text-xs">Internet Attacker</strong>
                      <p className="text-[11px] text-slate-400">Transmits probe payloads targeting parameter <code>{finding.parameter || 'input'}</code></p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center font-bold text-xs">2</span>
                    <div>
                      <strong className="text-white text-xs">Application Endpoint: {finding.target}</strong>
                      <p className="text-[11px] text-slate-400">Executes request without sufficient parameter neutralization or validation</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="w-6 h-6 rounded-full bg-purple-500/20 text-purple-400 flex items-center justify-center font-bold text-xs">3</span>
                    <div>
                      <strong className="text-white text-xs">Exploited Flaw: {finding.type}</strong>
                      <p className="text-[11px] text-slate-400">Severity {finding.severity} (Risk: {finding.risk_score}/10)</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: REMEDIATION */}
          {activeTab === 'remediation' && rem && (
            <div className="space-y-4">
              <div className="bg-emerald-950/20 border border-emerald-500/30 rounded-lg p-4">
                <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-1 font-mono">RECOMMENDED FIX</h4>
                <p className="text-xs text-slate-200 mb-3">{rem.recommendation}</p>
                <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-1 font-mono">VERIFICATION</h4>
                <p className="text-xs text-slate-300">{rem.verification}</p>
              </div>

              {rem.code_examples && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-1">
                      {(['python', 'javascript', 'java', 'php'] as const).map((lang) => (
                        <button
                          key={lang}
                          onClick={() => setActiveLang(lang)}
                          className={`text-xs px-2.5 py-1 rounded font-mono uppercase font-bold transition-colors ${
                            activeLang === lang
                              ? 'bg-slate-700 text-white'
                              : 'text-slate-500 hover:text-white'
                          }`}
                        >
                          {lang}
                        </button>
                      ))}
                    </div>
                    <button
                      onClick={() => copyToClipboard(rem.code_examples[activeLang] || '', activeLang)}
                      className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-mono"
                    >
                      {copiedCode === activeLang ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>Copy</span>
                    </button>
                  </div>

                  <pre className="bg-[#090d16] border border-slate-800 p-4 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                    {rem.code_examples[activeLang] || '# No code snippet available for this language'}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 6: REFERENCES */}
          {activeTab === 'references' && (
            <div className="space-y-3">
              <div className="bg-slate-900 p-4 rounded-lg border border-slate-800">
                <h4 className="text-xs font-bold uppercase text-slate-400 mb-2 font-mono">SECURITY INTELLIGENCE REFERENCES</h4>
                <ul className="space-y-2 text-xs">
                  <li>
                    <span className="text-slate-400">OWASP:</span>{' '}
                    <strong className="text-white">{finding.owasp.id} - {finding.owasp.name}</strong>
                  </li>
                  <li>
                    <span className="text-slate-400">CWE Weakness:</span>{' '}
                    <strong className="text-white">{finding.cwe.id} - {finding.cwe.name}</strong>
                  </li>
                  <li>
                    <span className="text-slate-400">CVSS v3.1 Vector:</span>{' '}
                    <code className="text-indigo-400">{finding.cvss_vector}</code>
                  </li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
