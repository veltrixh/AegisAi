import React, { useState } from 'react';
import { Play, Loader2, Sparkles, History, FileCode, Download } from 'lucide-react';
import { TargetUrlCheck } from '../urlValidation';

interface NavbarProps {
  targetUrl: string;
  setTargetUrl: (url: string) => void;
  targetCheck: TargetUrlCheck;
  profile: string;
  setProfile: (p: string) => void;
  onLaunchScan: () => void;
  isScanning: boolean;
  hasScan: boolean;
  onOpenAnalyst: () => void;
  onOpenHistory: () => void;
  onOpenOpenApi: () => void;
  onOpenReports: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  targetUrl,
  setTargetUrl,
  targetCheck,
  profile,
  setProfile,
  onLaunchScan,
  isScanning,
  hasScan,
  onOpenAnalyst,
  onOpenHistory,
  onOpenOpenApi,
  onOpenReports
}) => {
  return (
    <header className="app-header">
      <div className="flex items-center gap-3">
        <div className="brand-mark"><img src="/aegis-mark.svg" alt="AEGIS" /></div>
        <div>
          <div className="flex items-center gap-2">
            <span className="brand-name">AEGIS</span>
            <span className="brand-tag">SECURITY CONSOLE</span>
          </div>
          <span className="brand-subtitle">EVIDENCE-GROUNDED / EXPLAINABLE AI</span>
        </div>
      </div>

      <div className="scan-controls">
        <div className="target-field">
          <span className="target-label">TARGET</span>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="Enter a target URL to begin"
            className="target-input"
            aria-invalid={Boolean(targetUrl.trim() && !targetCheck.valid)}
            aria-describedby="target-url-status"
          />
          {targetUrl.trim() && (
            <span id="target-url-status" className={`target-status ${targetCheck.valid ? 'is-valid' : 'is-invalid'}`}>
              <span className="target-status-dot" /> {targetCheck.message}
            </span>
          )}
        </div>

        <select
          value={profile}
          onChange={(e) => setProfile(e.target.value)}
          className="profile-select"
        >
          <option value="quick">Quick (Headers + TLS)</option>
          <option value="standard">Standard (SQLi + XSS + CSRF + SSRF)</option>
          <option value="deep">Deep (Full Probes + Behavioral)</option>
          <option value="passive">Passive (Headers + Config)</option>
          <option value="api">API / OpenAPI Security</option>
          <option value="full">Full Assessment Suite</option>
        </select>

        <button
          onClick={onLaunchScan}
          disabled={isScanning || !targetCheck.valid}
          className="launch-button"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-white" />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Launch Scan</span>
            </>
          )}
        </button>
      </div>

      <div className="toolbar-actions">
        <button
          onClick={onOpenAnalyst}
          disabled={!hasScan}
          title="Open AI Analyst"
          className="toolbar-button"
        >
          <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
          <span className="hidden xl:inline">AI Analyst</span>
        </button>

        <button
          onClick={onOpenHistory}
          title="History and Compare"
          className="toolbar-button"
        >
          <History className="w-3.5 h-3.5 text-slate-400" />
          <span className="hidden xl:inline">History & Compare</span>
        </button>

        <button
          onClick={onOpenOpenApi}
          title="Open API and Swagger scanner"
          className="toolbar-button"
        >
          <FileCode className="w-3.5 h-3.5 text-emerald-400" />
          <span className="hidden xl:inline">API / Swagger</span>
        </button>

        <button
          onClick={onOpenReports}
          disabled={!hasScan}
          title="Export security reports"
          className="toolbar-button"
        >
          <Download className="w-3.5 h-3.5 text-sky-400" />
          <span className="hidden xl:inline">Export Reports</span>
        </button>
      </div>
    </header>
  );
};
