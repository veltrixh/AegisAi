import React, { useState, useEffect } from 'react';
import { Activity, ArrowUpRight, CheckCircle2, Clock3, Crosshair, ShieldCheck } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { ScoreCard } from './components/ScoreCard';
import { TopRisks } from './components/TopRisks';
import { AttackGraph } from './components/AttackGraph';
import { CorrelationView } from './components/CorrelationView';
import { FindingsTable } from './components/FindingsTable';
import { FindingDrawer } from './components/FindingDrawer';
import { AIAnalystModal } from './components/AIAnalystModal';
import { ScanComparisonModal } from './components/ScanComparisonModal';
import { OpenApiScannerModal } from './components/OpenApiScannerModal';
import { ReportsModal } from './components/ReportsModal';
import { launchScan, getScan } from './api';
import { ScanModel, FindingModel } from './types';
import { checkTargetUrl } from './urlValidation';

export const App: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [profile, setProfile] = useState('standard');
  const [activeScan, setActiveScan] = useState<ScanModel | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<FindingModel | null>(null);

  // Modals
  const [isAnalystOpen, setIsAnalystOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isOpenApiOpen, setIsOpenApiOpen] = useState(false);
  const [isReportsOpen, setIsReportsOpen] = useState(false);

  // Polling for active scan progress
  useEffect(() => {
    if (!activeScan || !isScanning) return;
    const interval = setInterval(async () => {
      try {
        const updated = await getScan(activeScan.id);
        setActiveScan(updated);
        if (updated.status === 'completed' || updated.status === 'failed' || updated.status === 'cancelled') {
          setIsScanning(false);
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 1200);

    return () => clearInterval(interval);
  }, [activeScan?.id, isScanning]);

  const handleLaunchScan = async () => {
    if (!targetCheck.valid) return;
    setIsScanning(true);
    try {
      setTargetUrl(targetCheck.normalized);
      const scan = await launchScan(targetCheck.normalized, profile);
      setActiveScan(scan);
    } catch (err: any) {
      alert(`Scan failed to launch: ${err.message}`);
      setIsScanning(false);
    }
  };

  const findingCount = activeScan?.summary.total_findings ?? 0;
  const criticalCount = activeScan?.summary.severity_breakdown.critical ?? 0;
  const hasCompletedScore = activeScan?.status === 'completed';
  const scanState = isScanning ? 'Scan in progress' : activeScan?.status === 'completed' ? 'Last scan completed' : 'No target selected';
  const targetCheck = checkTargetUrl(targetUrl);

  return (
    <div className="console-shell min-h-screen text-slate-900 flex flex-col font-sans">
      <Navbar
        targetUrl={targetUrl}
        setTargetUrl={setTargetUrl}
        targetCheck={targetCheck}
        profile={profile}
        setProfile={setProfile}
        onLaunchScan={handleLaunchScan}
        isScanning={isScanning}
        hasScan={Boolean(activeScan)}
        onOpenAnalyst={() => setIsAnalystOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        onOpenOpenApi={() => setIsOpenApiOpen(true)}
        onOpenReports={() => setIsReportsOpen(true)}
      />

      <main className="flex-1 max-w-[1480px] w-full mx-auto px-5 py-7 lg:px-9 space-y-6">
        <section className="page-intro">
          <div>
            <div className="eyebrow"><span className="eyebrow-dot" /> Security workspace</div>
            <h1>Application security, made legible.</h1>
            <p>Review verified exposure, understand the path to impact, and move remediation forward from one evidence-backed workspace.</p>
          </div>
          <div className="intro-status">
            <div className="status-icon"><Activity size={17} /></div>
            <div><span>Workspace status</span><strong>{scanState}</strong></div>
            <ArrowUpRight size={16} className="status-arrow" />
          </div>
        </section>

        {activeScan ? <section className="metric-strip" aria-label="Scan overview">
          <div className="metric-item"><span className="metric-icon blue"><ShieldCheck size={17} /></span><div><small>Posture score</small><strong>{hasCompletedScore ? activeScan.summary.security_score : '--'}{hasCompletedScore && <em>/100</em>}</strong></div></div>
          <div className="metric-item"><span className="metric-icon amber"><Activity size={17} /></span><div><small>Verified findings</small><strong>{findingCount}</strong></div></div>
          <div className="metric-item"><span className="metric-icon red"><span className="metric-dot" /></span><div><small>Critical exposure</small><strong>{criticalCount}</strong></div></div>
          <div className="metric-item"><span className="metric-icon green"><CheckCircle2 size={17} /></span><div><small>Scan duration</small><strong>{activeScan ? `${activeScan.duration_seconds}s` : '-'}</strong></div></div>
          <div className="metric-item metric-last"><span className="metric-icon slate"><Clock3 size={17} /></span><div><small>Target</small><strong className="metric-target">{activeScan?.target_url || targetUrl}</strong></div></div>
        </section> : (
          <section className="empty-workspace">
            <div className="empty-graphic"><Crosshair size={29} /></div>
            <div>
              <span className="empty-kicker">New assessment</span>
              <h2>Choose a target to begin.</h2>
              <p>Enter a URL above, select a scan profile, and launch a verified assessment. Existing scans remain available through History.</p>
            </div>
            <div className="empty-note"><span>01</span><span>Target</span><span>02</span><span>Profile</span><span>03</span><span>Evidence</span></div>
          </section>
        )}

        {activeScan && <>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ScoreCard scan={activeScan} isScanning={isScanning} />
          <TopRisks
            findings={activeScan?.findings || []}
            onSelectFinding={(f) => setSelectedFinding(f)}
          />
        </div>

        <AttackGraph
          graph={activeScan?.attack_graph || null}
          findings={activeScan?.findings || []}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />

        <CorrelationView correlations={activeScan?.correlations || []} />

        <FindingsTable
          findings={activeScan?.findings || []}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />
        </>}
      </main>

      <footer className="app-footer">
        <span>AEGIS <b>v2.0</b></span><span>Evidence-grounded verification</span><span>Offline capable</span>
      </footer>

      {/* Modals & Drawers */}
      <FindingDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />

      {isAnalystOpen && (
        <AIAnalystModal
          scan={activeScan}
          onClose={() => setIsAnalystOpen(false)}
        />
      )}

      {isHistoryOpen && (
        <ScanComparisonModal
          onClose={() => setIsHistoryOpen(false)}
          onSelectScan={(s) => {
            setActiveScan(s);
            setTargetUrl(s.target_url);
            setIsScanning(false);
          }}
        />
      )}

      {isOpenApiOpen && (
        <OpenApiScannerModal
          onClose={() => setIsOpenApiOpen(false)}
          onScanLaunched={(s) => {
            setActiveScan(s);
            setTargetUrl(s.target_url);
            setIsScanning(true);
          }}
        />
      )}

      {isReportsOpen && (
        <ReportsModal
          scan={activeScan}
          onClose={() => setIsReportsOpen(false)}
        />
      )}
    </div>
  );
};
