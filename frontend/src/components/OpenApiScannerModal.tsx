import React, { useState } from 'react';
import { X, FileCode, Play, Loader2 } from 'lucide-react';
import { scanOpenApi } from '../api';
import { ScanModel } from '../types';

interface OpenApiScannerModalProps {
  onClose: () => void;
  onScanLaunched: (scan: ScanModel) => void;
}

export const OpenApiScannerModal: React.FC<OpenApiScannerModalProps> = ({ onClose, onScanLaunched }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [specContent, setSpecContent] = useState(`{
  "openapi": "3.0.0",
  "info": { "title": "Target API", "version": "1.0.0" },
  "paths": {
    "/api/users": {
      "get": {
        "summary": "Fetch all users",
        "responses": {
          "200": {
            "description": "OK",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "id": { "type": "integer" },
                    "username": { "type": "string" },
                    "password": { "type": "string" },
                    "api_key": { "type": "string" }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}`);
  const [loading, setLoading] = useState(false);

  const handleLaunch = async () => {
    if (!targetUrl || !specContent) return;
    setLoading(true);
    try {
      const scan = await scanOpenApi(targetUrl, specContent);
      onScanLaunched(scan);
      onClose();
    } catch (err: any) {
      alert(`API scan launch failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#0f172a] border border-slate-800 rounded-2xl shadow-2xl p-6 flex flex-col max-h-[85vh]">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-white uppercase font-mono">OpenAPI / Swagger Security Audit</h3>
          </div>
          <button onClick={onClose} className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-4 my-4 flex-1 flex flex-col">
          <div>
            <label className="text-[11px] font-mono text-slate-400 uppercase block mb-1">Target Base URL</label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white font-mono"
            />
          </div>

          <div className="flex-1 flex flex-col">
            <label className="text-[11px] font-mono text-slate-400 uppercase block mb-1">OpenAPI 2.0 / 3.0 JSON / YAML Definition</label>
            <textarea
              value={specContent}
              onChange={(e) => setSpecContent(e.target.value)}
              className="flex-1 w-full bg-[#090d16] border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-300 resize-none min-h-[220px]"
            />
          </div>
        </div>

        <button
          onClick={handleLaunch}
          disabled={loading || !targetUrl.trim() || !specContent.trim()}
          className="w-full bg-emerald-600 hover:bg-emerald-500 py-2.5 rounded-lg text-xs font-bold text-white transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Analyzing Specification...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Audit API Specification</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
