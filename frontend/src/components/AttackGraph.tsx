import React, { useState } from 'react';
import { AttackGraphModel, GraphNode, FindingModel } from '../types';
import { ArrowRight, GitBranch, Shield, Globe, Terminal, Database, Server } from 'lucide-react';

interface AttackGraphProps {
  graph: AttackGraphModel | null;
  findings: FindingModel[];
  onSelectFinding: (finding: FindingModel) => void;
}

export const AttackGraph: React.FC<AttackGraphProps> = ({ graph, findings, onSelectFinding }) => {
  const [activeNode, setActiveNode] = useState<GraphNode | null>(null);

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-6 shadow-lg text-center text-slate-500 py-12">
        <GitBranch className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <p className="text-sm">No active attack graph generated for this scan profile.</p>
      </div>
    );
  }

  // Node Type styling
  const getNodeColor = (type: string, sev?: string) => {
    switch (type) {
      case 'entrypoint':
        return { bg: 'bg-rose-950/40', border: 'border-rose-500/50', text: 'text-rose-400', icon: Globe };
      case 'perimeter':
        return { bg: 'bg-indigo-950/40', border: 'border-indigo-500/50', text: 'text-indigo-400', icon: Server };
      case 'endpoint':
      case 'vector':
        return { bg: 'bg-slate-900', border: 'border-slate-700', text: 'text-slate-300', icon: Terminal };
      case 'vulnerability':
        return sev === 'CRITICAL'
          ? { bg: 'bg-red-950/60', border: 'border-red-500', text: 'text-red-400', icon: Shield }
          : { bg: 'bg-amber-950/60', border: 'border-amber-500', text: 'text-amber-400', icon: Shield };
      case 'asset':
        return { bg: 'bg-purple-950/40', border: 'border-purple-500/50', text: 'text-purple-400', icon: Database };
      default:
        return { bg: 'bg-slate-900', border: 'border-slate-700', text: 'text-slate-400', icon: GitBranch };
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    setActiveNode(node);
    if (node.finding_id) {
      const match = findings.find((f) => f.finding_id === node.finding_id);
      if (match) {
        onSelectFinding(match);
      }
    }
  };

  return (
    <div className="bg-[#131b2e] border border-slate-800 rounded-xl p-5 shadow-lg">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-indigo-400" />
          <h3 className="text-xs font-bold tracking-wider text-slate-300 uppercase">INTERACTIVE ATTACK GRAPH</h3>
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
          <span>Max Attack Risk: <strong className="text-rose-400">{graph.risk}/10</strong></span>
          <span>|</span>
          <span>Chains: <strong className="text-indigo-400">{graph.chains.length}</strong></span>
        </div>
      </div>

      {/* Graph Visual Canvas */}
      <div className="bg-[#090d16] border border-slate-800/80 rounded-lg p-5 overflow-x-auto min-h-[260px] flex items-center justify-around gap-6">
        {graph.nodes.slice(0, 8).map((node, idx) => {
          const style = getNodeColor(node.type, node.severity);
          const IconComp = style.icon;
          const isSelected = activeNode?.id === node.id;

          return (
            <div key={node.id} className="flex items-center gap-4 shrink-0">
              <div
                onClick={() => handleNodeClick(node)}
                className={`relative cursor-pointer transition-all duration-200 p-3 rounded-xl border text-center w-40 select-none hover:scale-105 ${style.bg} ${style.border} ${isSelected ? 'ring-2 ring-indigo-400' : ''}`}
              >
                <div className="w-8 h-8 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-center mx-auto mb-2">
                  <IconComp className={`w-4 h-4 ${style.text}`} />
                </div>
                <div className={`text-xs font-bold truncate ${style.text}`}>
                  {node.label}
                </div>
                <div className="text-[10px] text-slate-400 uppercase font-mono mt-0.5">
                  {node.type}
                </div>

                {node.risk_score !== undefined && (
                  <div className="mt-2 text-[10px] font-bold text-rose-400 bg-rose-950/80 rounded py-0.5 border border-rose-900/60">
                    Risk: {node.risk_score}/10
                  </div>
                )}
              </div>

              {idx < graph.nodes.slice(0, 8).length - 1 && (
                <ArrowRight className="text-slate-400 shrink-0" size={16} aria-hidden="true" />
              )}
            </div>
          );
        })}
      </div>

      {/* Attack Chains List */}
      {graph.chains.length > 0 && (
        <div className="mt-4 pt-3 border-t border-slate-800/80">
          <h4 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2">IDENTIFIED ATTACK PATH CHAINS</h4>
          <div className="space-y-2">
            {graph.chains.map((chain) => (
              <div
                key={chain.chain_id}
                className="bg-slate-900/60 border border-slate-800 p-2.5 rounded-lg flex flex-wrap items-center justify-between text-xs gap-2"
              >
                <div>
                  <strong className="text-slate-200">{chain.name}</strong>
                  <p className="text-[11px] text-slate-400 mt-0.5">{chain.description}</p>
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 font-bold">
                    Risk {chain.cumulative_risk}/10
                  </span>
                  <span className="text-slate-400">Likelihood: {Math.round(chain.likelihood * 100)}%</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
