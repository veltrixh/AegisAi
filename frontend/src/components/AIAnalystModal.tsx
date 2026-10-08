import React, { useState } from 'react';
import { X, Sparkles, Send, Loader2, ShieldCheck, AlertCircle } from 'lucide-react';
import { askAnalyst } from '../api';
import { ScanModel } from '../types';

interface AIAnalystModalProps {
  scan: ScanModel | null;
  onClose: () => void;
}

export const AIAnalystModal: React.FC<AIAnalystModalProps> = ({ scan, onClose }) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Array<{ q: string; a: any }>>([]);

  const promptSuggestions = [
    'What are the top 3 risks?',
    'Could this be a false positive?',
    'Which vulnerability should I fix first?',
    'Are these vulnerabilities connected?',
    'Explain the attack path and impact'
  ];

  const handleSend = async (userPrompt: string) => {
    if (!scan || !userPrompt.trim()) return;
    setLoading(true);
    try {
      const res = await askAnalyst(userPrompt, scan.id);
      setMessages((prev) => [...prev, { q: userPrompt, a: res }]);
      setQuery('');
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        { q: userPrompt, a: { summary: `Error querying security analyst: ${err.message}` } }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#0f172a] border border-slate-800 rounded-2xl shadow-2xl flex flex-col max-h-[85vh] overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 bg-[#131b2e] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-indigo-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white">AI Security Analyst</h3>
              <p className="text-[11px] text-slate-400">Evidence-grounded | Auditable reasoning | No fabricated facts</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Chat History */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
          {messages.length === 0 ? (
            <div className="py-8 text-center text-slate-400 space-y-3">
              <ShieldCheck className="w-8 h-8 text-indigo-400 mx-auto opacity-70" />
              <p>Ask the security analyst questions regarding findings, correlations, false positive checks, or remediations.</p>
              <div className="flex flex-wrap justify-center gap-1.5 max-w-lg mx-auto">
                {promptSuggestions.map((sug) => (
                  <button
                    key={sug}
                    onClick={() => handleSend(sug)}
                    className="px-2.5 py-1 rounded-full bg-slate-800/80 hover:bg-indigo-600/30 border border-slate-700/60 text-slate-300 hover:text-indigo-300 text-[11px] transition-colors"
                  >
                    {sug}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((item, idx) => (
              <div key={idx} className="space-y-2">
                <div className="flex justify-end">
                  <div className="bg-indigo-600 text-white px-3 py-2 rounded-xl rounded-tr-none max-w-[80%] text-xs font-medium">
                    {item.q}
                  </div>
                </div>

                <div className="flex justify-start">
                  <div className="bg-slate-900 border border-slate-800 px-4 py-3 rounded-xl rounded-tl-none max-w-[90%] text-xs text-slate-200 space-y-3">
                    {item.a.observed && (
                      <div>
                        <strong className="text-indigo-400 font-mono text-[11px] uppercase block mb-1">[OBSERVED EVIDENCE]</strong>
                        <ul className="list-disc ml-4 space-y-1 text-slate-300">
                          {item.a.observed.map((o: string, i: number) => (
                            <li key={i}>{o}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {item.a.inferred && (
                      <div>
                        <strong className="text-amber-400 font-mono text-[11px] uppercase block mb-1">[INFERRED THREAT ANALYSIS]</strong>
                        <ul className="list-disc ml-4 space-y-1 text-slate-300">
                          {item.a.inferred.map((inf: string, i: number) => (
                            <li key={i}>{inf}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {item.a.recommended && (
                      <div>
                        <strong className="text-emerald-400 font-mono text-[11px] uppercase block mb-1">[RECOMMENDED ACTION]</strong>
                        <ul className="list-disc ml-4 space-y-1 text-slate-300">
                          {item.a.recommended.map((r: string, i: number) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {!item.a.observed && item.a.summary && (
                      <p className="whitespace-pre-line">{item.a.summary}</p>
                    )}
                  </div>
                </div>
              </div>
            ))
          )}

          {loading && (
            <div className="flex items-center gap-2 text-indigo-400 py-2 text-xs">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Security Analyst analyzing deterministic evidence...</span>
            </div>
          )}
        </div>

        {/* Input bar */}
        <div className="p-3 border-t border-slate-800 bg-[#0b0f19] flex items-center gap-2">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSend(query)}
            placeholder="Ask question about this scan or specific vulnerabilities..."
            className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500"
          />
          <button
            onClick={() => handleSend(query)}
            disabled={loading || !query.trim()}
            className="p-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
